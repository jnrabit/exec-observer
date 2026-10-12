//! Exec-Beobachter-Daemon (Schritt 3).
//!
//! Lädt das eBPF-Programm, extrahiert die task_struct-Offsets aus der BTF,
//! pollt den Ringpuffer, löst `/proc/<pid>/exe` auf (SHA-256), und schreibt
//! eine Zeile pro Ereignis (JSON) in eine nur anhängende Senke (O_APPEND).
//!
//! Sicherheitshinweise: Die Senke wird über einen angehefteten Eltern-FD mit
//! `O_NOFOLLOW` geöffnet, muss eine genau einmal verlinkte reguläre Datei sein
//! und erhält Modus 0600. Nach abgeschlossenem Setup werden die Capabilities auf eine
//! vorläufige Mindestmenge reduziert: Effektiv/Permitted behalten nur
//! `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH` und `CAP_BPF`; `inheritable` = 0,
//! Ambient geleert, Bounding auf diese Menge gekürzt (Details in
//! [`restrict_capabilities`]).

mod btf;

use std::collections::{BTreeSet, HashMap};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "cap-matrix")]
use std::sync::OnceLock;

use aya::maps::{Array, PerCpuArray, RingBuf};
use aya::programs::TracePoint;
use aya::{include_bytes_aligned, Ebpf};
use exec_observer_common::{format_line, Event, Flag, HashState};
use exec_observer_uapi::{ExecEvent, MAX_FILENAME, MAX_TASK_OFFSET};
use sha2::{Digest, Sha256};

/// Globales Stopp-Flag (vom Signal-Handler gesetzt).
static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_signal(_sig: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// Installiert `SIGINT`/`SIGTERM` sofort nach der Root-Prüfung, damit auch ein
/// Abbruch während BTF/eBPF-Load geordnet über das Stopp-Flag erkannt wird.
/// `SA_RESTART` verhindert, dass `poll` durch das Signal mit `EINTR` abbricht.
fn install_signal_handlers() -> Result<(), String> {
    // SAFETY: Der Handler schreibt nur ein AtomicBool und ruft nichts anderes
    // auf. Die Maske wird explizit initialisiert; keine weiteren Felder gelesen.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handle_signal as *const () as libc::sighandler_t;
        action.sa_flags = libc::SA_RESTART;
        if libc::sigemptyset(&mut action.sa_mask) != 0 {
            return Err("Signalmaske nicht initialisierbar".to_string());
        }
        for sig in [libc::SIGINT, libc::SIGTERM] {
            if libc::sigaction(sig, &action, std::ptr::null_mut()) != 0 {
                return Err(format!(
                    "Signal-Handler für {sig} nicht installierbar: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
    }
    Ok(())
}

/// Ergebnis der Ringpuffer-Dekodierung. Eine falsche Länge bedeutet fast immer
/// eine ABI-Abweichung zwischen Sensor und Daemon und wird deshalb als eigene
/// Fehlerklasse gezählt, statt Ereignisse kommentarlos zu verwerfen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventParseError {
    WrongLength(usize),
}

/// Liest ein ExecEvent aus den Ringpuffer-Bytes. Layout ist ein bytemuck-Pod
/// (`#[repr(C)]` im uapi-Crate); exakte Größe statt handgepaddeter Offsets.
fn parse_exec_event(data: &[u8]) -> Result<ExecEvent, EventParseError> {
    let expected = std::mem::size_of::<ExecEvent>();
    if data.len() != expected {
        return Err(EventParseError::WrongLength(data.len()));
    }
    bytemuck::try_from_bytes::<ExecEvent>(data)
        .copied()
        .map_err(|_| EventParseError::WrongLength(data.len()))
}

fn boottime_ns() -> u64 {
    clock_ns(libc::CLOCK_BOOTTIME).unwrap_or(0)
}

fn realtime_ns() -> u64 {
    clock_ns(libc::CLOCK_REALTIME).unwrap_or(0)
}

/// Liest die Boot-ID genau einmal. Eine fehlende oder leere ID bricht den Start
/// ab: sonst könnten `start` und `stop` unterschiedliche oder leere `mid`
/// tragen und die SIEM-Korrelation wäre wertlos.
fn read_boot_id() -> Result<String, Box<dyn std::error::Error>> {
    normalize_boot_id(&fs::read_to_string("/proc/sys/kernel/random/boot_id")?)
        .ok_or_else(|| "leere Boot-ID".into())
}

fn normalize_boot_id(raw: &str) -> Option<String> {
    let mid = raw.trim().to_string();
    if mid.is_empty() {
        None
    } else {
        Some(mid)
    }
}

/// Liest eine POSIX-Uhr und normalisiert sie nach Nanosekunden. Ungültige
/// Rückgaben, negative Zeiten oder Nanosekunden außerhalb `[0, 1e9)` ergeben
/// `None` statt Wrap/Panik.
fn clock_ns(clock: libc::clockid_t) -> Option<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: gültiger Zeiger auf timespec; Aufrufer übergibt eine gültige Uhr.
    if unsafe { libc::clock_gettime(clock, &mut ts) } != 0 {
        return None;
    }
    timespec_to_ns(ts.tv_sec, ts.tv_nsec)
}

fn timespec_to_ns(tv_sec: i64, tv_nsec: i64) -> Option<u64> {
    if tv_sec < 0 || !(0..1_000_000_000).contains(&tv_nsec) {
        return None;
    }
    (tv_sec as u64)
        .checked_mul(1_000_000_000)?
        .checked_add(tv_nsec as u64)
}

/// Offset `CLOCK_REALTIME − CLOCK_BOOTTIME`, einmalig beim Start gemessen.
/// Wandelt `ts`-Werte (auf `CLOCK_BOOTTIME`-Basis) in Wall-Clock-Zeit um
/// (für SIEM-Korrelation). Ungenau bei NTP-Schritten oder Suspend während des
/// Laufs (dokumentiert). Basis ist BOOTTIME – dieselbe Uhr wie das Kernel-Feld
/// `start_boot_time` und das neue `ts_boot`.
fn wall_offset() -> u64 {
    realtime_ns().saturating_sub(boottime_ns())
}

/// Ereigniszeitstempel für die Ausgabe: Kernel-Bootzeit des Events, falls
/// gesetzt, sonst Daemon-Bootzeit als defensiver Fallback (Feld nie 0).
fn event_ts(sensor_boot_ns: u64) -> u64 {
    if sensor_boot_ns == 0 {
        boottime_ns()
    } else {
        sensor_boot_ns
    }
}

/// Prozesszustand, dekodiert aus dem Zustandsfeld in `/proc/<pid>/stat`.
/// Eingespeist in die reine `classify()` (kein `/proc`-Zugriff dort).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ProcState {
    Running,
    Zombie,
    Dead,
    NotFound,
    /// `/proc/<pid>/stat` existiert, aber der Zustand ist unbekannt oder nicht
    /// parsebar. Kein lebend-Nachweis; `classify` behandelt ihn wie `Running`
    /// für reine errno-Regeln, markiert ihn aber nicht als belegt lebend.
    Unknown,
}

/// Rohe Felder aus `/proc/<pid>/stat`, die wir benötigen.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct ProcStat {
    state: char,
    starttime_ticks: u64,
}

/// Einziger Parser für `/proc/<pid>/stat`. Liest `state` (Feld 3) und
/// `starttime` (Feld 22) ab der LETZTEN `)`: `comm` (Feld 2) steht in Klammern
/// und darf selbst Leerzeichen und `)` enthalten (z. B. `a) S (b`). Ein
/// naives Trennen an Leerzeichen würde Zustand und Startzeit verfälschen.
/// Rein und host-testbar (nimmt den Dateiinhalt, nicht die PID).
fn parse_proc_stat(contents: &str) -> Option<ProcStat> {
    let comm_end = contents.rfind(')')?;
    let rest = contents.get(comm_end + 1..)?.strip_prefix(' ')?;
    let mut fields = rest.split_whitespace();
    // Erster Wert nach comm ist Feld 3 = state.
    let state = fields.next()?.chars().next()?;
    // Danach Felder 4..; starttime ist Feld 22 → das 19. verbleibende (4+18).
    let starttime_ticks: u64 = fields.nth(18)?.parse().ok()?;
    Some(ProcStat {
        state,
        starttime_ticks,
    })
}

/// Liest die Startzeit (Feld 22, `starttime`) aus `/proc/<pid>/stat` in ns.
/// `None`, wenn der Prozess nicht mehr existiert. `/proc` liefert die Zeit auf
/// `CLOCK_BOOTTIME`-Basis; der Kernel-Wert wird hierauf bezogen.
fn proc_start_time_ns(pid: u32, clk_tck: i64) -> Option<u64> {
    if clk_tck <= 0 {
        return None;
    }
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let ticks = parse_proc_stat(&stat)?.starttime_ticks;
    // Ceil-Division, s. `start_time_matches` (Toleranz in vollen Ticks).
    ticks.checked_mul(tick_ns(clk_tck)?)
}

/// Liest den Prozesszustand aus `/proc/<pid>/stat` und übersetzt ihn in
/// `ProcState`. `NotFound`, wenn die Datei fehlt (Prozess weg bzw. PID
/// wiederverwendet und wieder weg).
fn proc_state(pid: u32) -> ProcState {
    let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return ProcState::NotFound;
    };
    match parse_proc_stat(&stat).map(|p| p.state) {
        Some('Z') => ProcState::Zombie,
        Some('X' | 'x') => ProcState::Dead,
        Some('R' | 'S' | 'D' | 'T' | 't' | 'W' | 'I') => ProcState::Running,
        // Alles andere (einschließlich unklarer Zeichen) ist kein Beleg für
        // einen lebenden Prozess.
        _ => ProcState::Unknown,
    }
}

/// Nanosekunden pro Clock-Tick, aufgerundet (`ceil`), damit die
/// Toleranzrechnung selbst bei nicht-teilbarem `NSEC_PER_SEC / clk_tck` korrekt
/// bleibt (z. B. `USER_HZ = 300`). Ungültige Taktraten ergeben `None`, damit
/// Aufrufer fail-closed entscheiden können.
fn tick_ns(clk_tck: i64) -> Option<u64> {
    if clk_tck <= 0 {
        None
    } else {
        Some(1_000_000_000u64.div_ceil(clk_tck as u64))
    }
}

/// Trägt `event_ns` (CLOCK_BOOTTIME aus dem Kernel) gegen `/proc/<pid>/stat`-`starttime` ab.
fn start_time_matches(pid: u32, event_ns: u64, clk_tck: i64) -> bool {
    match proc_start_time_ns(pid, clk_tck) {
        Some(ns) => matches_boottime(ns, event_ns, clk_tck),
        None => false,
    }
}

/// Vergleich auf `CLOCK_BOOTTIME`-Basis. Die Toleranz ist bewusst EIN voller
/// Tick (S7): `/proc/<pid>/stat` rundet den exakten `ns`-Wert aus dem Kernel
/// über `nsec_to_clock_t` auf ganze Ticks ab. Die Toleranz gilt nur vorwärts:
/// das Kernel-Ereignis kann nicht vor der abgerundeten Startzeit liegen. Ein
/// strengerer Vergleich würde das eigene Ereignis fälschlich als
/// „Gone/PID-Reuse“ markieren; ein symmetrischer Vergleich würde eine
/// Wiederverwendung innerhalb eines Ticks fälschlich akzeptieren.
fn matches_boottime(stat_ns: u64, event_ns: u64, clk_tck: i64) -> bool {
    match tick_ns(clk_tck) {
        Some(tick) => event_ns
            .checked_sub(stat_ns)
            .is_some_and(|diff| diff <= tick),
        None => false,
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Datei-Identität für den Hash-Cache (race-frei vom geöffneten FD via fstat).
/// Treffer nur, wenn alle Werte unverändert sind: `size`, `mtime` und `ctime`
/// (jeweils sek+nsec). `ctime` erkennt auch Änderungen, die `mtime` unberührt
/// lassen (chmod/chown/rename).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdent {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
}

impl FileIdent {
    fn from_metadata(m: &std::fs::Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            size: m.len(),
            mtime_sec: m.mtime(),
            mtime_nsec: m.mtime_nsec(),
            ctime_sec: m.ctime(),
            ctime_nsec: m.ctime_nsec(),
        }
    }
}

/// Cache-Schlüssel aus `fstat`, oder `None`, wenn keine verlässliche Identität
/// vorliegt. Ein Null-Schlüssel ist verboten: sonst würden verschiedene Dateien
/// mit Metadatenfehler denselben Schlüssel `(0, 0)` teilen und falsche
/// `cached`-Hashes erhalten.
fn cache_key(metadata: &std::io::Result<std::fs::Metadata>) -> Option<FileIdent> {
    metadata.as_ref().ok().map(FileIdent::from_metadata)
}

/// Wann ein Datei-Hash aus dem Cache getroffen bzw. in ihn aufgenommen werden
/// darf. `fileless` (`/memfd:`) und `deleted` Objekte sind flüchtig: dev+ino
/// sind dort keine verlässliche Identität (memfd-FD kann wiederverwendet, eine
/// gelöschte Datei sofort am selben dev/ino neu erzeugt werden). Für sie wird
/// der Cache nie gelesen und nie geschrieben → nie `cached`.
fn cache_allowed(flags: &[Flag]) -> bool {
    !flags.contains(&Flag::Fileless) && !flags.contains(&Flag::Deleted)
}

/// Pfad-Präfixe für einen Exec über einen übergebenen Deskriptor.
const FD_EXEC_PREFIXES: [&str; 2] = ["/dev/fd/", "/proc/self/fd/"];

/// `true`, wenn der vom Kernel gemeldete Pfad auf einen übergebenen Deskriptor
/// zeigt (`execveat` mit `AT_EMPTY_PATH` bzw. `/dev/fd/N`-Form).
///
/// Bewusst aus dem **Ereignis** berechnet und nicht aus `/proc/<pid>/exe`:
/// anders als `fileless`/`deleted` hängt dieses Flag nicht daran, ob der
/// Prozess beim Verarbeiten noch lebt – es steht bereits in der Zeile, wenn
/// das Ziel längst beendet ist ( siehe Fund „kurzlebige Prozesse").
fn is_fd_exec(path: &str) -> bool {
    FD_EXEC_PREFIXES
        .iter()
        .any(|p| path.len() > p.len() && path.starts_with(p))
}

/// Obergrenze für einen einzelnen Datei-Hash in Bytes. Ohne Budget könnte eine
/// sehr große ausführbare Datei die Ereignisschleife blockieren, bis der
/// Ringpuffer überläuft. Überschreitungen melden `unreadable`, kein Hash.
const MAX_HASH_BYTES: u64 = 64 * 1024 * 1024;

fn hash_within_budget(size: u64) -> bool {
    size <= MAX_HASH_BYTES
}

/// Datei-Hash-Cache mit fester Obergrenze (LRU). Schlüssel ist `(dev, ino)`;
/// ein Treffer gilt nur, wenn zusätzlich `size`, `mtime` (sek+nsec) UND `ctime`
/// (sek+nsec) unverändert sind (siehe [`FileIdent`]). Weicht einer der Werte ab,
/// wird frisch gehasht. Bei voller Obergrenze verdrängt `insert` das älteste
/// Element (MRU-Reihenfolge über einen monotonen Zähler) — kein kompletter
/// `clear()`.
#[derive(Default)]
struct HashCache {
    map: HashMap<(u64, u64), CacheValue>,
    order: BTreeSet<u64>,
    /// Rückwärtsindex Ordnung → Schlüssel, damit das Verdrängen des ältesten
    /// Eintrags kein O(n)-Suchen über alle Werte braucht.
    order_index: HashMap<u64, (u64, u64)>,
    counter: u64,
    cap: usize,
}

struct CacheValue {
    ident: FileIdent,
    hash: String,
    order: u64,
}

impl HashCache {
    const DEFAULT_CAP: usize = 65536;

    fn default() -> Self {
        Self::with_cap(Self::DEFAULT_CAP)
    }

    fn with_cap(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: BTreeSet::new(),
            order_index: HashMap::new(),
            counter: 0,
            cap,
        }
    }

    /// Treffer nur bei identischer [`FileIdent`]. Ein Treffer rückt das Element
    /// auf „zuletzt verwendet“ (MRU), damit LRU korrekt arbeitet.
    fn get(&mut self, id: &FileIdent) -> Option<String> {
        let key = (id.dev, id.ino);
        let matches = self.map.get(&key).is_some_and(|v| v.ident == *id);
        if !matches {
            return None;
        }
        let v = self.map.get_mut(&key).expect("oben geprüft");
        self.order.remove(&v.order);
        self.order_index.remove(&v.order);
        self.counter = self.counter.wrapping_add(1);
        v.order = self.counter;
        self.order.insert(v.order);
        self.order_index.insert(v.order, key);
        Some(v.hash.clone())
    }

    fn insert(&mut self, id: &FileIdent, hash: String) {
        let key = (id.dev, id.ino);
        if let Some(v) = self.map.get_mut(&key) {
            // Datei am selben dev/ino geändert: Werte ersetzen, bleibt im Cache.
            self.order.remove(&v.order);
            self.order_index.remove(&v.order);
            v.ident = *id;
            v.hash = hash;
            self.counter = self.counter.wrapping_add(1);
            v.order = self.counter;
            self.order.insert(v.order);
            self.order_index.insert(v.order, key);
            return;
        }
        // Feste Obergrenze: das älteste Element verdrängen.
        if self.map.len() >= self.cap {
            if let Some(&old) = self.order.iter().next() {
                if let Some(k) = self.order_index.remove(&old) {
                    self.map.remove(&k);
                }
                self.order.remove(&old);
            }
        }
        self.counter = self.counter.wrapping_add(1);
        let v = CacheValue {
            ident: *id,
            hash,
            order: self.counter,
        };
        self.order.insert(v.order);
        self.order_index.insert(v.order, key);
        self.map.insert(key, v);
    }

    #[cfg(test)]
    fn check_invariants(&self) {
        assert_eq!(self.map.len(), self.order.len());
        assert_eq!(self.map.len(), self.order_index.len());
        for (&order, &key) in &self.order_index {
            assert!(self.order.contains(&order));
            assert_eq!(self.map.get(&key).map(|v| v.order), Some(order));
        }
    }
}

/// Rein: bildet `errno` + Prozesszustand auf den `hash_state`-Vertrag ab.
/// Kein `/proc`-Zugriff — damit deterministisch host-testbar.
///
/// - Prozess nicht (mehr) vorhanden, tot oder Zombie → `gone` (egal welcher errno).
/// - Unbekannter Zustand verhält sich bei `errno` wie `Running`, wird aber nie
///   als belegter Lebendnachweis verwendet.
/// - `ESRCH`/`ENOENT` → `gone` (race-bedingt verschwundene PID).
/// - `EACCES`/`EPERM` bei lebendem Prozess → `unreadable`.
/// - anderer errno bei lebendem Prozess (z. B. `EMFILE`, `ENOMEM`, `EIO`)
///   → `unreadable`; das ist ein Daemon-Problem, der Aufrufer meldet es auf
///   stderr (errno-Name, ohne Ereignisinhalte), damit es nicht unbemerkt als
///   „unlesbar" im Strom verschwindet.
fn classify(errno: Option<i32>, state: ProcState) -> HashState {
    if matches!(
        state,
        ProcState::NotFound | ProcState::Dead | ProcState::Zombie
    ) {
        return HashState::Gone;
    }
    match errno {
        Some(libc::ESRCH) | Some(libc::ENOENT) => HashState::Gone,
        _ => HashState::Unreadable,
    }
}

/// Dünner Aufrufer: liest den errno des gescheiterten Öffnens aus (vom
/// Aufrufer übergeben, da nur dort beobachtbar), bestimmt den
/// `/proc`-Prozesszustand und delegiert an die reine `classify()`.
fn classify_open_failure(pid: u32, errno: Option<i32>) -> HashState {
    classify(errno, proc_state(pid))
}

/// Öffnet `/proc/<pid>/exe` genau einmal, leitet die Flags aus demselben FD ab
/// und hasht denselben FD (kein TOCTOU zwischen Flag- und Hash-Ermittlung).
/// Ein `HashCache` vermeidet wiederholtes Lesen derselben, unveränderten Datei.
/// Liefert zusätzlich die per `fstat` gelesene Identität `(ino, size)` desselben
/// FDs – oder `None`, wenn sie nicht lesbar war. Der Aufrufer vergleicht sie
/// mit der Sensor-Identität, bevor ein Hash attributiert wird.
fn open_hash_flags(
    pid: u32,
    cache: &mut HashCache,
) -> (Option<String>, HashState, Vec<Flag>, Option<(u64, u64)>) {
    let exe = format!("/proc/{pid}/exe");
    // Öffnen folgt dem Symlink auf die tatsächlich ausgeführte Datei.
    let mut f = match File::open(&exe) {
        Ok(f) => f,
        Err(e) => {
            // hash_state-Vertrag (Punkt 4): reine Zuordnung in classify().
            let errno = e.raw_os_error();
            let state = classify_open_failure(pid, errno);
            // Daemon-Fehler (nicht Zugriffsrechte, nicht verschwundene PID):
            // laut melden, damit z. B. ein FD-Leck nicht als „unlesbar" verschwindet.
            if state == HashState::Unreadable
                && !matches!(errno, Some(libc::EACCES) | Some(libc::EPERM))
            {
                eprintln!("exec-observer: Öffnen von /proc/{pid}/exe fehlgeschlagen: {e}");
            }
            return (None, state, Vec::new(), None);
        }
    };

    // Flags aus dem geöffneten FD: readlink liefert den Pfad des Objekts.
    // Ein `/memfd:`-Objekt ist immer auch "(deleted)" — semantisch ist es aber
    // EIN Flag: fileless (Deleted heißt „auf Platte ersetzt“, NICHT memfd).
    let mut flags: Vec<Flag> = Vec::new();
    if let Ok(link) = fs::read_link(format!("/proc/self/fd/{}", f.as_raw_fd())) {
        let s = link.to_string_lossy().into_owned();
        if s.starts_with("/memfd:") {
            flags.push(Flag::Fileless);
        } else if s.contains("(deleted)") {
            flags.push(Flag::Deleted);
        }
    }

    // Datei-Identität für den Cache (fstat auf denselben FD, race-frei).
    // Ohne Metadaten gibt es keinen Schlüssel: eine Null-Identität dürfte
    // sonst mehrere verschiedene Dateien auf denselben Cache-Eintrag abbilden.
    let ident = cache_key(&f.metadata());
    let Some(ident) = ident else {
        // fstat-Fehler gehören nicht in den Cache; der Aufrufer unterscheidet
        // sie nicht von einem Hash-Fehler.
        return (None, HashState::Unreadable, flags, None);
    };
    let opened_ident = Some((ident.ino, ident.size));
    // Auch ein Cache-Treffer darf keine unbegrenzte Datei ersetzen: die Größe
    // steht vor dem Lesen fest.
    if !hash_within_budget(ident.size) {
        eprintln!("exec-observer: /proc/{pid}/exe überschreitet das Hash-Budget");
        return (None, HashState::Unreadable, flags, opened_ident);
    }
    // fileless/deleted: nie aus dem Cache treffen, nie in den Cache schreiben.
    if cache_allowed(&flags) {
        if let Some(hash) = cache.get(&ident) {
            flags.push(Flag::Cached);
            return (Some(hash), HashState::Ok, flags, opened_ident);
        }
    }

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    let mut remaining = MAX_HASH_BYTES;
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let n = n as u64;
                // Die Datei kann nach fstat noch wachsen; das Budget begrenzt
                // die tatsächlich gelesenen Bytes.
                if n > remaining {
                    eprintln!("exec-observer: /proc/{pid}/exe überschreitet das Hash-Budget");
                    return (None, HashState::Unreadable, flags, opened_ident);
                }
                remaining -= n;
                hasher.update(&buf[..n as usize]);
            }
            Err(_) => return (None, HashState::Unreadable, flags, opened_ident),
        }
    }
    let hash = hex(&hasher.finalize());
    if cache_allowed(&flags) {
        cache.insert(&ident, hash.clone());
    }
    (Some(hash), HashState::Ok, flags, opened_ident)
}

/// Schreibkontext: lückenlose `seq`, gepufferte Append-Senke, `clk_tck`,
/// Offset monotone→Wall-Clock-Zeit und der Datei-Hash-Zwischenspeicher.
/// Puffergröße der Senke: `SINK_CAPACITY` Bytes. Leerungsregel: nach jeder
/// Zeile (synchrones `flush` in `emit`).
///
/// Absturzverhalten: Ein brutaler Abbruch (SIGKILL, Power-Loss) verliert
/// höchstens die Zeile, deren `write_all`/`flush` zum Absturzzeitpunkt noch
/// offen war. Bereits geleerte Zeilen bleiben vollständig erhalten und sind
/// einzeln gültiges JSON. Ein `stop`-Ereignis fehlt dann und zeigt den
/// nicht-ordentlichen Abbruch an (wertegestützte „Ende-marker“-Doku).
/// Pufferkapazität der Senke (Bytes). Größer als jede realisierbare Zeile,
/// damit eine Zeile samt `\n` in genau einem OS-`write`-Aufruf rausgeht.
const SINK_CAPACITY: usize = 16 * 1024;

impl Writer {
    /// Zählt ein strukturell ungültiges Ringpuffer-Ereignis. Nur das erste
    /// meldet auf stderr; die Summe erscheint beim Beenden als `lost`. So
    /// bleibt eine Versionsabweichung sichtbar, ohne den Fehlerstrom zu fluten.
    fn note_parse_error(&mut self, err: EventParseError) {
        if self.parse_errors == 0 {
            eprintln!("exec-observer: ungültiges Ringpuffer-Ereignis: {err:?}");
        }
        self.parse_errors = self.parse_errors.saturating_add(1);
    }

    /// Schreibt je Ereignis genau eine Zeile (`format_line`) mit abschließendem
    /// `\n` und leert sofort per `flush()` (Leerungsregel: **nach jeder Zeile**).
    ///
    /// Da vor dem nächsten `write_all` der Puffer leer ist, enthält ein
    /// OS-`write()`-Aufruf nie mehrere Zeilen und endet nie „mitten in einer
    /// Zeile“ – sofern die Zeile kleiner als `SINK_CAPACITY` bleibt (dann wird
    /// der komplette `line\n`-Block in einem speicheradressierten `write()`
    /// geschrieben, bei O_APPEND atomar am Dateiende). Ein `write_all` aus
    /// `format_line` kann also nie mehrere Zeilen enthalten – der Aufrufer baut
    /// aus genau einem Ereignis genau eine Zeile.
    fn emit(&mut self, event: &Event) -> std::io::Result<()> {
        // Die Sequenznummer gehört zur erfolgreich geschriebenen Zeile: Erst
        // formatieren, dann schreiben, erst nach dem Flush erhöhen. Eine
        // fehlgeschlagene Ausgabe hinterlässt daher keine Lücke.
        let line = format_line(self.seq, event);
        self.sink.write_all(line.as_bytes())?;
        self.sink.write_all(b"\n")?;
        self.sink.flush()?;
        self.seq = self
            .seq
            .checked_add(1)
            .expect("Ereigniszähler läuft nicht über");
        Ok(())
    }

    fn emit_lost(&mut self, count: u64) -> std::io::Result<()> {
        let ts = boottime_ns();
        self.emit(&Event::Lost {
            ts,
            wall: ts.saturating_add(self.wall),
            count,
        })
    }

    fn emit_exec(
        &mut self,
        ev: &ExecEvent,
        path: &str,
        comm: &[u8],
        sha256: Option<String>,
        hash_state: HashState,
        flags: Vec<Flag>,
    ) -> std::io::Result<()> {
        // Zeitstempel aus der Kernel-Bootzeit (CLOCK_BOOTTIME, `ts_boot`) statt
        // aus der Daemon-Uhr → gleiche Basis wie `start_boot_time` (kein
        // Mischbasis-Fehler mehr) und kein Prozess-/Daemon-Verarbeitungsverzug.
        let ts = event_ts(ev.ts_boot);
        let argc = if ev.has_argc != 0 {
            Some(ev.argc as u64)
        } else {
            None
        };
        let event = Event::Exec {
            ts,
            wall: ts.saturating_add(self.wall),
            pid: ev.pid,
            ppid: ev.ppid,
            uid: ev.uid,
            euid: ev.euid,
            comm: comm.to_vec(),
            path: path.as_bytes().to_vec(),
            argc,
            sha256,
            hash_state,
            flags,
        };
        self.emit(&event)?;
        // Nur erfolgreich geschriebene Zeilen zählen (Erhaltung B4).
        self.written += 1;
        Ok(())
    }

    /// Verarbeitet EIN Ereignis. Reihenfolge bewusst so gewählt:
    /// (a) Pfad, (b) comm, (c) Flags aus dem Ereignis – alles ohne `/proc`.
    /// (d) erster `/proc`-Zugriff (hier startet die Verzögerungsmessung),
    /// (e) Startzeit-Check (PID-Reuse-Schutz), (f) Sensor-Identität prüfen
    /// (ohne sie kein Hash), (g) öffnet `/proc/<pid>/exe` **vor**
    /// Identität/Cache/Hash, (h) Identitätsvergleich Sensor↔FD (`superseded`
    /// bei späterer Exec-Stufe derselben PID), (i) Startzeit-Recheck.
    /// Die Zeile wird erst am Ende gebaut (`emit_exec`) – das Öffnen steht
    /// also vor dem Zeilenbau und vor dem Cache-Zugriff.
    fn process(&mut self, ev: &ExecEvent) -> std::io::Result<()> {
        // (a) Dateiname aus dem Tracepoint (kann relativ sein). Das Kernel-
        //     `__data_loc`-Länge schließt das abschließende NUL ein → abschneiden.
        let filename_len = (ev.filename_len as usize).min(MAX_FILENAME);
        let raw = &ev.filename[..filename_len];
        let n = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let path = String::from_utf8_lossy(&raw[..n]).into_owned();

        // (b) comm ohne abschließende NUL-Bytes.
        let comm: Vec<u8> = ev.comm.iter().take_while(|&&b| b != 0).copied().collect();

        // (c) argc_min- und path_trunc-Flags aus dem Kernel-Ereignis.
        let mut flags: Vec<Flag> = Vec::new();
        if ev.argc_min != 0 {
            flags.push(Flag::ArgcMin);
        }
        if ev.path_trunc != 0 {
            flags.push(Flag::PathTrunc);
        }
        // fd_exec ebenfalls aus dem Ereignis – unabhängig vom Prozesszustand.
        if is_fd_exec(&path) {
            flags.push(Flag::FdExec);
        }

        // (d) Verzögerungsmessung (nur mit `--stats`): ab JETZT wird `/proc`
        //     angefasst. Der Messpunkt steht VOR dem Bauen der Zeile und VOR
        //     dem Cache-Zugriff (Schritt (e) öffnet `/proc/<pid>/exe` als
        //     Erstes, noch bevor Identität/Cache/Hash drankommen) – genau die
        //     Stelle, an der feststeht, ob der Prozess noch lebt.
        let t_proc = if self.stats.enabled {
            Some(boottime_ns())
        } else {
            None
        };
        let delay_us = match t_proc {
            Some(t) if ev.ts_boot != 0 => Some(t.saturating_sub(ev.ts_boot) / 1000),
            _ => None,
        };

        // (e) Startzeit vor dem Hashen prüfen (PID-Reuse-Schutz). Bei Nichtüberein-
        //     stimmung wird die exe-Datei nicht angefasst (ggf. falscher Prozess).
        if !start_time_matches(ev.pid, ev.start_boot_time, self.clk_tck) {
            self.stats.record(HashState::Gone, delay_us);
            return self.emit_exec(ev, &path, &comm, None, HashState::Gone, flags);
        }

        // (f) Ereignis-Identität aus dem Sensor ((ino, size) zum
        //     Ereigniszeitpunkt). Fehlt sie, darf kein Hash attributiert
        //     werden – unabhängig davon, was `/proc` gerade zeigt.
        let sensor_ident = if ev.has_exe_ident != 0 {
            Some((ev.exe_ino, ev.exe_size))
        } else {
            None
        };
        if sensor_ident.is_none() {
            self.stats.record_ident_missing();
            self.stats.record(HashState::Unreadable, delay_us);
            return self.emit_exec(ev, &path, &comm, None, HashState::Unreadable, flags);
        }

        // (g) Flags und Hash über ein und denselben geöffneten FD.
        let (sha256, hash_state, exe_flags, opened_ident) =
            open_hash_flags(ev.pid, &mut self.cache);
        flags.extend(exe_flags);

        // (h) Identitätsvergleich Sensor ↔ geöffneter FD: Gehört der FD noch
        //     zum Sensorereignis? Nein → `superseded` (spätere Exec-Stufe
        //     derselben PID); der Hash wird verworfen, statt ihn der falschen
        //     Zeile zuzuordnen.
        let hash_state = match resolve_exe_identity(sensor_ident, opened_ident) {
            ExeIdentity::Match => {
                // (i) Startzeit nach dem Hashen erneut prüfen. Unterschied ist:
                //     - Prozess weg → Gone (Hash der Datei war obsolet).
                //     - Prozess lebt mit ANDERER Startzeit (erneuter exec desselben PIDs)
                //       → Reused: Hash gehörte zur vorherigen Binary, wird verworfen.
                verify_hash_state_after(ev.pid, ev.start_boot_time, self.clk_tck, hash_state)
            }
            ExeIdentity::Mismatch => HashState::Superseded,
            // Die Sensoridentität ist hier immer `Some` (oben geprüft); fehlt
            // die FD-Identität, hat das Öffnen bereits versagt und
            // `hash_state` trägt `Gone`/`Unreadable`.
            ExeIdentity::Unavailable => hash_state,
        };
        self.stats.record(hash_state, delay_us);
        let (sha256, flags) = finalize_exec_output(sha256, flags, hash_state);

        self.emit_exec(ev, &path, &comm, sha256, hash_state, flags)
    }
}

/// Entfernt einen Hash und alle aus dem geöffneten FD abgeleiteten Flags, falls
/// die abschließende Identitätsprüfung den Hash ungültig gemacht hat. Nur bei
/// `Ok` bleiben Hash und Flags erhalten; `ArgcMin`, `PathTrunc` und `FdExec`
/// stammen aus dem Ereignis und bleiben auch bei `Gone`/`Reused`/`Superseded`
/// erhalten.
fn finalize_exec_output(
    sha256: Option<String>,
    flags: Vec<Flag>,
    hash_state: HashState,
) -> (Option<String>, Vec<Flag>) {
    match hash_state {
        HashState::Ok => (sha256, flags),
        HashState::Gone | HashState::Unreadable | HashState::Reused | HashState::Superseded => (
            None,
            flags
                .into_iter()
                .filter(|flag| !matches!(flag, Flag::Fileless | Flag::Deleted | Flag::Cached))
                .collect(),
        ),
    }
}

/// Laufzeitstatistik für `--stats`.
///
/// Erfasst je `hash_state` die Anzahl und die **Verzögerung** zwischen
/// `ts_boot` des Ereignisses (Kernel-Zeit des Sensors) und dem **ersten
/// Zugriff auf `/proc/<pid>/…`** – also dem Moment, in dem überhaupt feststeht,
/// ob der Prozess noch lebt. Diese Messung ist der Grund, warum kurzlebige
/// Ziele `gone` liefern: der Sensor kennt den Exec sofort, der Daemon sieht ihn
/// erst, wenn ihn die Poll-Schleife weckt.
///
/// Wirkt **nur auf stderr beim Beenden**; keine Zeile im Strom ändert sich.
/// Größte gespeicherte Verzögerungsstichprobe je Zustand. Die Zähler bleiben
/// exakt, die Perzentile arbeiten auf einer rotierenden Stichprobe.
const MAX_DELAY_SAMPLES: usize = 10_000;

#[derive(Default)]
struct ProcStats {
    enabled: bool,
    /// Zähler je Zustand: ok, gone, unreadable, reused, superseded.
    counts: [u64; 5],
    /// Verzögerungen in µs je Zustand (gleiche Reihenfolge, begrenzt).
    delays_us: [Vec<u64>; 5],
    /// Ereignisse ohne Sensor-Identität (`has_exe_ident == 0`): kein Hash
    /// attributierbar, Zustand `unreadable`.
    ident_missing: u64,
}

impl ProcStats {
    fn idx(state: HashState) -> usize {
        match state {
            HashState::Ok => 0,
            HashState::Gone => 1,
            HashState::Unreadable => 2,
            HashState::Reused => 3,
            HashState::Superseded => 4,
        }
    }

    /// Zählt ein Ereignis ohne Sensor-Identität (nur mit `--stats`).
    fn record_ident_missing(&mut self) {
        if self.enabled {
            self.ident_missing += 1;
        }
    }

    fn record(&mut self, state: HashState, delay_us: Option<u64>) {
        if !self.enabled {
            return;
        }
        let i = Self::idx(state);
        self.counts[i] += 1;
        if let Some(d) = delay_us {
            let samples = &mut self.delays_us[i];
            if samples.len() < MAX_DELAY_SAMPLES {
                samples.push(d);
            } else {
                // Feste Stichprobe: älteste Ersetzung im Ring, keine wachsende Liste.
                let slot = (self.counts[i] as usize - 1) % MAX_DELAY_SAMPLES;
                samples[slot] = d;
            }
        }
    }

    /// Kennzahlen einer Stichprobe: (Anzahl, min, median, p99, max) in µs.
    fn describe(v: &[u64]) -> Option<(usize, u64, u64, u64, u64)> {
        if v.is_empty() {
            return None;
        }
        let mut x = v.to_vec();
        x.sort_unstable();
        let n = x.len();
        let median = if n % 2 == 1 {
            x[n / 2]
        } else {
            (x[n / 2 - 1] + x[n / 2]) / 2
        };
        // p99: nächster Rang (nearest rank)
        let p99_idx = ((99 * n as u64).div_ceil(100)).saturating_sub(1) as usize;
        Some((n, x[0], median, x[p99_idx.min(n - 1)], x[n - 1]))
    }

    /// Block für stderr; mit Anfangs-/Endmarke, damit Skripte ihn leicht
    /// herausziehen können. `kernel_seen`/`written`/`lost` sind die
    /// Erhaltungszähler seit Start (Kernel-Versuche, geschriebene exec-Zeilen,
    /// Kernel-Verluste); es gilt geschrieben + lost == kernel_seen.
    fn render(&self, kernel_seen: u64, written: u64, lost: u64) -> String {
        let total: u64 = self.counts.iter().sum();
        let mut out = String::new();
        out.push_str("exec-observer: --stats begin\n");
        out.push_str(&format!(
            "exec-observer: --stats: {total} exec-Ereignisse, Verzögerung \
             ts_boot→erster /proc-Zugriff\n"
        ));
        out.push_str(&format!(
            "exec-observer: --stats: kernel_seen={kernel_seen} geschrieben={written} lost={lost}\n"
        ));
        for (i, name) in ["ok", "gone", "unreadable", "reused", "superseded"]
            .iter()
            .enumerate()
        {
            let c = self.counts[i];
            match Self::describe(&self.delays_us[i]) {
                Some((n, min, med, p99, max)) => out.push_str(&format!(
                    "exec-observer: --stats:   {name:<10} n={c:<6} \
                     min={min}µs median={med}µs p99={p99}µs max={max}µs ({n} Messwerte)\n"
                )),
                None => out.push_str(&format!(
                    "exec-observer: --stats:   {name:<10} n={c:<6} (keine Messwerte)\n"
                )),
            }
        }
        out.push_str(&format!(
            "exec-observer: --stats:   ident_missing n={}\n",
            self.ident_missing
        ));
        out.push_str("exec-observer: --stats end\n");
        out
    }
}

/// Ergebnis des Identitätsvergleichs zwischen Sensorereignis und geöffnetem
/// `/proc/<pid>/exe`-FD. Reine Entscheidungslogik (host-testbar).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExeIdentity {
    /// Beide Identitäten vorhanden und gleich: der FD gehört zum Ereignis.
    Match,
    /// Beide vorhanden, aber verschieden: zwischen Ereignis und Öffnen wurde
    /// erneut exec't (`superseded`).
    Mismatch,
    /// Mindestens eine Seite fehlt (keine Attribuierung möglich).
    Unavailable,
}

/// Vergleicht die Sensor-Identität `(ino, size)` zum Ereigniszeitpunkt mit der
/// `fstat`-Identität `(st_ino, st_size)` des geöffneten FDs. `s_dev`/`st_dev`
/// bleiben außen vor: auf btrfs weicht `st_dev` von der Superblock-Nummer ab
/// (gemessen: Mount `0:35`, Datei-`st_dev` `0:37`).
fn resolve_exe_identity(sensor: Option<(u64, u64)>, opened: Option<(u64, u64)>) -> ExeIdentity {
    match (sensor, opened) {
        (Some(s), Some(o)) if s == o => ExeIdentity::Match,
        (Some(_), Some(_)) => ExeIdentity::Mismatch,
        _ => ExeIdentity::Unavailable,
    }
}

/// Schritt (f): verfeinert den `hash_state`, nachdem `/proc/<pid>/exe` gehasht
/// wurde. Pure Entscheidungslogik (host-testbar):
/// - vorläufiger Status `Ok` → erneuter Startzeit-Vergleich:
///   - Prozess weg → `gone`; Startzeit identisch → `ok`; andere Startzeit
///     (erneuter exec desselben PIDs) → `reused`.
/// - andere vorläufige Status (`gone`/`unreadable`) bleiben unverändert.
fn verify_hash_state_after(
    pid: u32,
    event_boot_time: u64,
    clk_tck: i64,
    hash_state: HashState,
) -> HashState {
    match hash_state {
        HashState::Ok => match proc_start_time_ns(pid, clk_tck) {
            None => HashState::Gone,
            Some(ns) if matches_boottime(ns, event_boot_time, clk_tck) => HashState::Ok,
            Some(_) => HashState::Reused,
        },
        other => other,
    }
}

/// Per-CPU-Kernelzählerstand mit Differenzbildung (DROPS/SEEN).
/// Rein und host-testbar: summiert die Per-CPU-Werte je Lesung genau einmal.
/// Die Zähler sind monoton (wrapping-sicher subtrahiert); der Startstand darf
/// ungleich 0 sein (Map kann beim Daemonstart bereits zählen).
#[derive(Debug, Default, Clone, Copy)]
struct CounterDelta {
    base: u64,
    last: u64,
}

impl CounterDelta {
    /// Startstand aus der ersten Lesung.
    fn start(reading: &[u64]) -> Self {
        let total: u64 = reading.iter().copied().sum();
        Self {
            base: total,
            last: total,
        }
    }

    /// Verarbeitet eine neue Lesung, liefert die Differenz seit der LETZTEN
    /// Lesung und merkt den neuen Stand.
    fn update(&mut self, reading: &[u64]) -> u64 {
        let total: u64 = reading.iter().copied().sum();
        let delta = total.wrapping_sub(self.last);
        self.last = total;
        delta
    }

    /// Gesamtdifferenz seit dem Start.
    fn total(&self) -> u64 {
        self.last.wrapping_sub(self.base)
    }
}

/// Schreiber für die Senke: hält die Sequenznummer, den Puffer, den
/// Hash-Cache und (falls `--stats` gegeben) die Laufzeitstatistik.
struct Writer {
    seq: u64,
    sink: BufWriter<File>,
    clk_tck: i64,
    wall: u64,
    cache: HashCache,
    stats: ProcStats,
    /// Strukturell ungültige Ringpuffer-Ereignisse (z. B. ABI-Abweichung).
    parse_errors: u64,
    /// Erfolgreich geschriebene `exec`-Zeilen (für die Erhaltung
    /// geschrieben + lost == kernel_seen).
    written: u64,
}

impl Drop for Writer {
    fn drop(&mut self) {
        let _ = self.sink.flush();
    }
}

/// Capability-Indizes (Linux `include/uapi/linux/capability.h`).
const CAP_DAC_READ_SEARCH: u32 = 2;
const CAP_SYS_PTRACE: u32 = 19;
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;
const CAP_SETPCAP: u32 = 8;

/// Gewünschte (vorläufige) Mindestmenge nach dem eBPF-Load.
const KEEP_WANTED: u64 = bit(CAP_DAC_READ_SEARCH) | bit(CAP_SYS_PTRACE) | bit(CAP_BPF);

/// Zusage zur Compile-Zeit: `CAP_PERFMON` gehört ausdrücklich NICHT in die
/// Mindestmenge (es wird vom eBPF-Load gebraucht, danach aber abgegeben).
const _: () = assert!(KEEP_WANTED & bit(CAP_PERFMON) == 0);

const fn bit(cap: u32) -> u64 {
    1u64 << cap
}

/// Zielmenge der Capability-Reduktion: `KEEP_WANTED` gekappt auf das, was der
/// Prozess wirklich hat.
///
/// Der Schnitt ist notwendig, weil `capset` eine Capability nicht neu verleihen
/// kann: war eine gewünschte Capability nie im Permitted-Set (z. B. weil das
/// Bounding-Set sie ausgeschlossen hat), schlägt jede Anhebung mit `EPERM` fehl.
/// Vor dieser Schnittbildung lief der Daemon dann per Best-Effort-Warnung mit
/// der **größeren** Ausgangsmenge weiter (Fund 2: in einem Umfeld mit
/// `perfmon` blieb `CAP_PERFMON` erhalten).
///
/// Ergebnis ist damit immer `⊆ KEEP_WANTED` – reine Funktion, host-testbar.
fn capability_target(available_permitted: u64) -> u64 {
    KEEP_WANTED & available_permitted
}

/// Test-Override der Wunschmenge (nur Feature "cap-matrix", Punkt 3): Mit
/// `--caps=ptrace,dac` gibt der Matrixlauf die Zielmenge nach dem Laden vor,
/// um zu prüfen, ob der Daemon ohne `CAP_BPF` noch DROPS/SEEN lesen kann.
/// Im normalen Build existiert weder Option noch Override; die Produktions-
/// menge bleibt `KEEP_WANTED`.
#[cfg(feature = "cap-matrix")]
static CAPS_OVERRIDE: OnceLock<u64> = OnceLock::new();

/// Wunschmenge für die Reduktion: Override (Test-Feature) oder `KEEP_WANTED`.
fn wanted_capabilities() -> u64 {
    #[cfg(feature = "cap-matrix")]
    if let Some(&o) = CAPS_OVERRIDE.get() {
        return o;
    }
    // capability_target(u64::MAX) == KEEP_WANTED; so bleibt die Funktion auch
    // im normalen Build referenziert (kein dead_code) und die Produktions-
    // menge unverändert.
    capability_target(u64::MAX)
}

/// Parst `--caps=a,b,...` (nur Feature "cap-matrix"). Namen: `bpf`,
/// `perfmon`, `ptrace` (CAP_SYS_PTRACE), `dac` (CAP_DAC_READ_SEARCH).
/// Unbekannte Namen → `Err` (der Aufrufer beendet mit Exit-Code ≠ 0).
#[cfg(feature = "cap-matrix")]
fn parse_caps_override(arg: &str) -> Result<u64, String> {
    let mut mask = 0u64;
    for name in arg.split(',') {
        let b = match name.trim() {
            "bpf" => bit(CAP_BPF),
            "perfmon" => bit(CAP_PERFMON),
            "ptrace" | "sys_ptrace" => bit(CAP_SYS_PTRACE),
            "dac" | "dac_read_search" => bit(CAP_DAC_READ_SEARCH),
            other => return Err(format!("unbekannte Capability: {other:?}")),
        };
        mask |= b;
    }
    Ok(mask)
}

/// Setzt die zwei 32-Bit-Wörter des `capget(v3)`-Puffers zur u64-Maske
/// zusammen. Wort 0 trägt die Caps 0–31, Wort 1 die Caps 32–63.
///
/// Reine Funktion, damit die Zusammensetzung host-testbar ist (Randfälle an
/// den Wortgrenzen: Bits 31, 32, 38, 39, 40). Vorher stand die Verschiebung
/// inline in [`cap_get`]; ein Vertauschen der Wörter wäre dort nicht
/// auffallbar gewesen.
#[inline]
fn compose_cap_words(low: u32, high: u32) -> u64 {
    u64::from(low) | (u64::from(high) << 32)
}

/// Aktuelle Permitted-Menge des Prozesses (0 = nicht lesbar).
fn cap_get() -> Option<u64> {
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let mut hdr = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(), CapData::default()];
    // SAFETY: Zeiger auf Kernel-Lese-Puffer; Version 3 erwartet zwei
    // v2-Strukturen à 3×u32.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut hdr as *mut CapHeader,
            data.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return None;
    }
    Some(compose_cap_words(data[0].permitted, data[1].permitted))
}

/// Alle fünf Linux-Capability-Mengen eines Prozesses als Bitmasken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct CapabilitySets {
    effective: u64,
    permitted: u64,
    inheritable: u64,
    ambient: u64,
    bounding: u64,
}

/// Höchster Capability-Index, der in Schleifen berührt wird. Schützt vor
/// absurden Werten aus `/proc/sys/kernel/cap_last_cap` (Start-Hang).
const MAX_CAP_INDEX: i32 = 63;

fn clamp_last_cap(raw: i32) -> i32 {
    raw.clamp(0, MAX_CAP_INDEX)
}

/// Parst die Capability-Zeilen aus `/proc/self/status`. Reine Funktion für
/// Host-Tests; fehlende oder ungültige Zeilen ergeben `None` statt
/// stillschweigender Nullen.
fn parse_capability_status(contents: &str) -> Option<CapabilitySets> {
    let mut effective = None;
    let mut permitted = None;
    let mut inheritable = None;
    let mut ambient = None;
    let mut bounding = None;
    for line in contents.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let Ok(mask) = u64::from_str_radix(value.trim(), 16) else {
            continue;
        };
        match name {
            "CapEff" => effective = Some(mask),
            "CapPrm" => permitted = Some(mask),
            "CapInh" => inheritable = Some(mask),
            "CapAmb" => ambient = Some(mask),
            "CapBnd" => bounding = Some(mask),
            _ => {}
        }
    }
    Some(CapabilitySets {
        effective: effective?,
        permitted: permitted?,
        inheritable: inheritable?,
        ambient: ambient?,
        bounding: bounding?,
    })
}

fn read_capability_sets() -> Option<CapabilitySets> {
    let contents = fs::read_to_string("/proc/self/status").ok()?;
    parse_capability_status(&contents)
}

/// Erwarteter Endzustand nach der Reduktion. Effektiv/Permitted sind immer die
/// Zielmenge; Inheritable/Ambient sind immer leer. Das Bounding-Set kann nur
/// gekürzt werden, wenn `CAP_SETPCAP` im effektiven Satz vorhanden war; sonst
/// bleibt es unverändert, weil der Kernel das Prunen verbietet.
fn expected_post_reduction(before: CapabilitySets, target: u64) -> CapabilitySets {
    CapabilitySets {
        effective: target,
        permitted: target,
        inheritable: 0,
        ambient: 0,
        bounding: if before.effective & bit(CAP_SETPCAP) != 0 {
            target
        } else {
            before.bounding
        },
    }
}

/// Reduziert nach abgeschlossenem Setup die Capability-Mengen auf eine
/// vorläufige Mindestmenge (P1) – **vor** dem Schreiben der `start`-Zeile, damit
/// ein Leser dieser Zeile den reduzierten Zustand sieht. Beibehalten werden
/// Effektiv und Permitted:
///
///   - `CAP_SYS_PTRACE` (19): `/proc/<pid>/exe` fremder Prozesse
///     (`PTRACE_MODE_READ_FSCREDS`).
///   - `CAP_DAC_READ_SEARCH` (2): Durchsuchen/Lesen fremder Verzeichnisse und
///     Dateien (Ziel-exe kann jedem User gehören).
///   - `CAP_BPF` (39): Lesen der `DROPS`-/`SEEN`-Maps, wenn
///     `kernel.unprivileged_bpf_disabled != 0` (Annahme; Experiment mit
///     `--caps=` und Feature "cap-matrix" läuft, DESIGN.md §2).
///
/// `CAP_PERFMON` (und alle übrigen) werden abgegeben. Die Zielmenge ist
/// `KEEP_WANTED ∩ vorhanden` (siehe [`capability_target`]); `inheritable` wird
/// auf 0 gesetzt, Ambient über `PR_CAP_AMBIENT/CLEAR_ALL` geleert, und das
/// Bounding-Set (`PR_CAPBSET_DROP`) wird auf genau die Zielmenge reduziert,
/// sofern der Prozess `CAP_SETPCAP` effektiv besitzt.
///
/// **Nicht mehr Best-Effort:** `capget`, `PR_SET_NO_NEW_PRIVS`, `capset`,
/// `PR_CAP_AMBIENT/CLEAR_ALL` und ein möglicher `PR_CAPBSET_DROP` beenden den
/// Daemon geordnet – mit Fehlermeldung und errno auf stderr. Anschließend
/// werden alle fünf erreichten Mengen zurückgelesen und gegen die Zielmenge
/// geprüft. Ein `PR_CAPBSET_DROP` ohne effektives `CAP_SETPCAP` ist
/// ausgenommen: ohne das Cap darf der Kernel gar nicht (EPERM); dann bleibt
/// das Bounding-Set unverändert. Stillschweigend mit mehr Rechten
/// weiterzulaufen kann der Daemon damit nicht.
/// (`PR_SET_NO_NEW_PRIVS` ist Härtung und wird ebenfalls geprüft, nicht nur
/// gesetzt.)
fn restrict_capabilities() -> Result<(), String> {
    const PR_CAPBSET_DROP: libc::c_int = 24;
    const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
    const PR_CAP_AMBIENT: libc::c_int = 47;
    const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_int = 4;

    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

    let last_cap: i32 = fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .map(clamp_last_cap)
        .unwrap_or(40);

    unsafe {
        if libc::syscall(libc::SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("exec-observer: PR_SET_NO_NEW_PRIVS fehlgeschlagen: {err}");
            return Err(format!("PR_SET_NO_NEW_PRIVS: {err}"));
        }
        // Momentan tatsächlich vorhandene Permitted-Menge. Davon hängt ab, was
        // überhaupt behalten werden *kann* (capset kann keine Capability neu
        // verleihen, nur abgeben). Syscall- und `/proc`-Quelle müssen
        // übereinstimmen, sonst starten wir auf keiner belastbaren Sicht.
        let current = match cap_get() {
            Some(p) => p,
            None => {
                eprintln!(
                    "exec-observer: capget fehlgeschlagen: {}",
                    std::io::Error::last_os_error()
                );
                return Err("capget fehlgeschlagen".into());
            }
        };
        // Vollständige Mengen als zweite Quelle: `/proc/self/status` bestätigt die
        // Syscall-Werte. Eine Abweichung bricht ab, statt auf einer inkonsistenten
        // Sicht weiterzumachen.
        let before = match read_capability_sets() {
            Some(sets) => sets,
            None => {
                eprintln!("exec-observer: Capability-Mengen nicht lesbar");
                return Err("Capability-Mengen nicht lesbar".into());
            }
        };
        if current != before.permitted {
            eprintln!(
                "exec-observer: Capability-Quellen stimmen nicht überein: capget=0x{current:x}, /proc=0x{:x}",
                before.permitted
            );
            return Err("Capability-Quellen stimmen nicht überein".into());
        }

        // Zielmenge: Wunschmenge ∩ vorhandene Menge. So kann der Daemon nie
        // mit MEHR Capabilities weiterlaufen als er je hatte, und nie mit
        // mehr als vorgesehen (siehe capability_target-Test). Mit Feature
        // "cap-matrix" tritt `--caps=...` an die Stelle von KEEP_WANTED.
        let target = wanted_capabilities() & current;
        // Grundwahrheit für tests/cap-matrix.sh: was hatte der Prozess, was
        // sollte er behalten, was hat er danach wirklich? (Ein Lauf maß Cap*=
        // 0 an einem laufenden Daemon; ohne diese Zeile ist nicht unterscheid-
        // bar, ob der Daemon oder die Messung daneben lag.)
        eprintln!("exec-observer: Capabilities: vorhanden=0x{current:x} → Ziel=0x{target:x}");

        // Bounding-Set auf die Zielmenge reduzieren. PR_CAPBSET_DROP verlangt
        // CAP_SETPCAP im EFFEKTIVEN Satz: wer minimal gestartet wird (genau
        // die Caps aus KEEP_WANTED, wie tests/cap-matrix.sh in Fall b/e), hat
        // sie nicht und darf gar nichts aus dem Bounding-Set entfernen. Dann
        // ist das ein Kernel-Verbot, kein Daemon-Fehler, und ohne Belang: die
        // Macht des Prozesses kommt aus Effektiv/Permitted, die capset gleich
        // (fatal) reduziert; neuerwerben könnte der Daemon Caps nur über
        // execve – das tut er nie. Nur wenn CAP_SETPCAP effektiv vorhanden ist,
        // ist ein Scheitern ein echter Fehler.
        if before.effective & bit(CAP_SETPCAP) != 0 {
            let mut cap = 0;
            while cap <= last_cap {
                let b: u64 = 1u64 << (cap as u32);
                if (target & b) == 0
                    && libc::syscall(libc::SYS_prctl, PR_CAPBSET_DROP, cap, 0, 0, 0) != 0
                {
                    let err = std::io::Error::last_os_error();
                    eprintln!("exec-observer: PR_CAPBSET_DROP({cap}) fehlgeschlagen: {err}");
                    return Err(format!("PR_CAPBSET_DROP({cap}): {err}"));
                }
                cap += 1;
            }
        } else {
            eprintln!(
                "exec-observer: Bounding-Set unverändert: kein CAP_SETPCAP (minimaler Start); \
                 Effektiv/Permitted wurden trotzdem reduziert"
            );
        }

        // Ambient zuerst leeren: `capset` setzt Inheritable auf 0, und Ambient
        // darf danach nicht mehr gesetzt sein.
        if libc::syscall(
            libc::SYS_prctl,
            PR_CAP_AMBIENT,
            PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        ) != 0
        {
            let err = std::io::Error::last_os_error();
            eprintln!("exec-observer: PR_CAP_AMBIENT/CLEAR_ALL fehlgeschlagen: {err}");
            return Err(format!("PR_CAP_AMBIENT/CLEAR_ALL: {err}"));
        }

        // Eff/Prm/Inh auf die Zielmenge setzen (Inheritable = 0).
        let mut hdr = CapHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let data = [
            CapData {
                effective: (target & 0xFFFF_FFFF) as u32,
                permitted: (target & 0xFFFF_FFFF) as u32,
                inheritable: 0,
            },
            CapData {
                effective: ((target >> 32) & 0xFFFF_FFFF) as u32,
                permitted: ((target >> 32) & 0xFFFF_FFFF) as u32,
                inheritable: 0,
            },
        ];
        if libc::syscall(libc::SYS_capset, &mut hdr as *mut CapHeader, data.as_ptr()) != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("exec-observer: Capability-Reduktion (Eff/Prm/Inh) fehlgeschlagen: {err}");
            return Err(format!("capset (Eff/Prm/Inh): {err}"));
        }

        // Erreichte Mengen zurücklesen und gegen alle Zusagen prüfen:Effektiv und
        // Permitted müssen der Zielmenge entsprechen, Inheritable und Ambient
        // müssen leer sein, und das Bounding-Set dem erwarteten Endzustand.
        let achieved = match read_capability_sets() {
            Some(sets) => sets,
            None => {
                eprintln!("exec-observer: erreichte Capability-Mengen nicht lesbar");
                return Err("erreichte Capability-Mengen nicht lesbar".into());
            }
        };
        let expected = expected_post_reduction(before, target);
        if achieved != expected {
            eprintln!(
                "exec-observer: Zielmenge nicht erreicht: erreicht={achieved:?}, erwartet={expected:?}"
            );
            return Err(format!(
                "Zielmenge nicht erreicht (erreicht {achieved:?}, erwartet {expected:?})"
            ));
        }
    }

    Ok(())
}

/// Löst einen Senkenpfad gegen Symlink-Umleitungen in übergeordneten
/// Verzeichnissen auf. Leere Pfade und Pfade ohne Dateinamen werden abgelehnt;
/// fehlende Elternverzeichnisse werden nicht erzeugt.
fn resolve_sink_path(requested: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if requested.trim().is_empty() {
        return Err("leerer Senkenpfad".into());
    }
    let requested_path = Path::new(requested);
    let absolute = if requested_path.is_absolute() {
        requested_path.to_path_buf()
    } else {
        std::env::current_dir()?.join(requested_path)
    };
    let file_name = absolute
        .file_name()
        .ok_or("Senkenpfad ohne Dateinamen")?
        .to_os_string();
    let parent = absolute
        .parent()
        .ok_or("Senkenpfad ohne Elternverzeichnis")?;
    let canonical_parent = parent
        .canonicalize()
        .map_err(|e| format!("Elternverzeichnis ungültig: {e}"))?;
    Ok(canonical_parent.join(file_name))
}

/// Öffnet die Senke manipulationssicher: Elternverzeichnis wird als FD
/// festgehalten, der Dateiname wird mit `O_NOFOLLOW` geöffnet, danach werden
/// Dateityp, Linkzahl und Modus am selben FD geprüft. FIFOs blockieren durch
/// `O_NONBLOCK` nicht; Symlinks, Verzeichnisse, Geräte und mehrfach verlinkte
/// Dateien werden abgelehnt. Eine bestehende reguläre Datei erhält `0600`.
fn open_sink_file(requested: &str) -> Result<File, Box<dyn std::error::Error>> {
    let resolved = resolve_sink_path(requested)?;
    let parent = resolved
        .parent()
        .ok_or("Senkenpfad ohne Elternverzeichnis")?;
    let parent_fd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)
        .map_err(|e| format!("Elternverzeichnis nicht öffnbar: {e}"))?;
    let file_name = CString::new(
        resolved
            .file_name()
            .ok_or("Senkenpfad ohne Dateinamen")?
            .as_encoded_bytes(),
    )
    .map_err(|_| "Senkenpfad enthält NUL-Byte")?;
    // SAFETY: gültiger Eltern-FD und NUL-terminierter Dateiname; Rückgabe wird
    // sofort auf Fehler geprüft und danach als `File` übernommen.
    let fd = unsafe {
        libc::openat(
            parent_fd.as_raw_fd(),
            file_name.as_ptr(),
            libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_APPEND
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: Dateideskriptor stammt aus erfolgreichem `openat`.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err("Senke ist keine reguläre Datei".into());
    }
    if metadata.nlink() != 1 {
        return Err("Senke hat mehrere harte Links".into());
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        // SAFETY: `fchmod` wirkt auf den bereits geprüften FD.
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(file)
}

/// Das fertige eBPF-Objekt, eingebettet per `include_bytes_aligned!`.
/// `EXEC_EBPF_OBJECT` setzt das `build.rs` auf den absoluten Pfad des soeben
/// gebauten Objekts — es existiert nur zur Compile-Zeit. Zur Laufzeit gibt es
/// weder einen Objekt-Dateipfad noch eine `AYA_BUILD_OBJ`-Abhängigkeit; damit
/// kann ein User-kontrolliertes cwd oder `target/` dem Root-Prozess kein
/// injizierbares BPF-Programm unterschieben (S3).
const EBPF_OBJECT: &[u8] = include_bytes_aligned!(concat!(env!("EXEC_EBPF_OBJECT")));

const USAGE: &str = r#"exec-observer – Exec-Beobachter-Daemon

Aufruf:
  exec-observer [SENKE] [--stats]

Argumente:
  SENKE      Append-Logdatei (Default: "exec-observer.log")

Optionen:
  -h, --help     Diese Hilfe anzeigen
  -V, --version  Version anzeigen
  --stats       Zusätzliche Statistik auf stderr beim Beenden: Anzahl je
                hash_state und die Verzögerung (min/median/p99/max, µs)
                zwischen ts_boot des Ereignisses und dem ersten Zugriff auf
                /proc/<pid>. Kein Einfluss auf die Senke.

Das eBPF-Objekt ist in die Binärdatei eingebettet (kein Objektpfad nötig).
Benötigt root (eBPF laden) und Linux mit CONFIG_DEBUG_INFO_BTF.
"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{}", USAGE);
        #[cfg(feature = "cap-matrix")]
        print!("  --caps=a,b,..  Zielmenge nach dem Laden vorgeben (NUR Test-Feature\n                   \"cap-matrix\"; Namen: bpf, perfmon, ptrace, dac)\n");
        return Ok(());
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("exec-observer {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // K9: frühe, klare Fehlermeldung statt kryptischem eBPF-Ladefehler.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "exec-observer: bitte als root ausführen – eBPF-Programme erfordern CAP_BPF/CAP_PERFMON"
        );
        std::process::exit(1);
    }
    install_signal_handlers().map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    // --stats wirkt nur auf stderr beim Beenden (Diagnose Verarbeitungsverzug).
    // Die Senke ist das erste Argument, das keine Option ist – sonst würde
    // „--stats" als Dateiname gelesen.
    let stats = args.iter().any(|a| a == "--stats");
    // --caps=... nur mit Feature "cap-matrix" (Punkt 3): Zielmenge nach dem
    // Laden vorgeben (z. B. --caps=ptrace,dac für den BPF-Laufzeittest).
    #[cfg(feature = "cap-matrix")]
    for a in args.iter().skip(1) {
        if let Some(list) = a.strip_prefix("--caps=") {
            match parse_caps_override(list) {
                Ok(mask) => {
                    eprintln!("exec-observer: Test-Override Zielmenge: 0x{mask:x}");
                    let _ = CAPS_OVERRIDE.set(mask);
                }
                Err(e) => {
                    eprintln!("exec-observer: {e}");
                    std::process::exit(2);
                }
            }
        }
    }
    #[cfg(not(feature = "cap-matrix"))]
    if args.iter().skip(1).any(|a| a.starts_with("--caps=")) {
        eprintln!("exec-observer: --caps=... braucht das Build-Feature \"cap-matrix\"");
        std::process::exit(2);
    }
    let sink_path = args
        .iter()
        .skip(1)
        .find(|a| !a.starts_with('-'))
        .cloned()
        .unwrap_or_else(|| "exec-observer.log".to_string());

    // ── 1. BTF-Offsets (fail-closed) ──────────────────────────────────
    let btf = btf::Btf::from_sysfs()?;
    // Reihenfolge == Index der OFFSETS-Map (uapi): real_parent, tgid, cred,
    // uid, euid, start_boottime, group_leader, mm, exe_file, f_inode, i_ino,
    // i_size. Fehlt eines, startet der Beobachter nicht (fail-closed).
    let spec: [(&str, &str); 12] = [
        ("task_struct", "real_parent"),
        ("task_struct", "tgid"),
        ("task_struct", "cred"),
        ("cred", "uid"),
        ("cred", "euid"),
        ("task_struct", "start_boottime"),
        ("task_struct", "group_leader"),
        ("task_struct", "mm"),
        ("mm_struct", "exe_file"),
        ("file", "f_inode"),
        ("inode", "i_ino"),
        ("inode", "i_size"),
    ];
    // Alle Offsets zuerst auflösen; fehlt eines, startet der Beobachter nicht.
    let offsets: Vec<u64> = spec
        .iter()
        .map(|(struct_name, field_name)| {
            let off = btf
                .field_offset(struct_name, field_name)
                .ok_or_else(|| format!("BTF-Feld fehlt: {struct_name}.{field_name}"))?
                as u64;
            if off > MAX_TASK_OFFSET {
                return Err(format!(
                    "BTF-Offset unplausibel: {struct_name}.{field_name} = {off}"
                ));
            }
            Ok(off)
        })
        .collect::<Result<_, _>>()?;

    // ── 2. eBPF laden + Offsets setzen ────────────────────────────────
    let mut bpf = Ebpf::load(EBPF_OBJECT).map_err(|e| format!("eBPF laden: {e}"))?;

    let map = bpf.take_map("OFFSETS").ok_or("OFFSETS-Map fehlt")?;
    let mut offsets_map: Array<_, u64> = map.try_into()?;
    for (i, off) in offsets.iter().enumerate() {
        offsets_map.set(i as u32, off, 0)?;
    }
    // Erst nach allen zwölf Einträgen die Bereitschaftsmarke setzen. Der Sensor
    // verweigert ohne sie jeden Offset-Zugriff statt Null zu lesen.
    let map = bpf
        .take_map("OFFSETS_READY")
        .ok_or("OFFSETS_READY-Map fehlt")?;
    let mut ready_map: Array<_, u8> = map.try_into()?;
    ready_map.set(0, 1, 0)?;

    // ── 3. Tracepoints anhängen ───────────────────────────────────────
    for (prog, cat, name) in [
        ("sys_enter_execve", "syscalls", "sys_enter_execve"),
        ("sys_enter_execveat", "syscalls", "sys_enter_execveat"),
        ("sched_process_exec", "sched", "sched_process_exec"),
    ] {
        let p: &mut TracePoint = bpf
            .program_mut(prog)
            .ok_or(format!("Programm fehlt: {prog}"))?
            .try_into()?;
        p.load()?;
        p.attach(cat, name)?;
    }

    // ── 4. Ringpuffer + Drop-Zähler ───────────────────────────────────
    let events_map = bpf.take_map("EVENTS").ok_or("EVENTS-Map fehlt")?;
    let mut events: RingBuf<_> = events_map.try_into()?;
    let ring_fd = events.as_fd().as_raw_fd();

    let drops_map = bpf.take_map("DROPS").ok_or("DROPS-Map fehlt")?;
    let drops: PerCpuArray<_, u64> = drops_map.try_into()?;
    let mut drops_ctr = CounterDelta::start(&match drops.get(&0, 0) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("exec-observer: Fehler beim Lesen von DROPS: {e}");
            std::process::exit(1);
        }
    });

    // SEEN zählt jeden `sched_process_exec`-Versuch (gesendet + verworfen).
    // Differenz seit Start = `kernel_seen`; Erhaltung: geschrieben + lost.
    let seen_map = bpf.take_map("SEEN").ok_or("SEEN-Map fehlt")?;
    let seen: PerCpuArray<_, u64> = seen_map.try_into()?;
    let mut seen_ctr = CounterDelta::start(&match seen.get(&0, 0) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("exec-observer: Fehler beim Lesen von SEEN: {e}");
            std::process::exit(1);
        }
    });

    let stop_mid = read_boot_id()?;
    let sink = open_sink_file(&sink_path).map_err(|e| format!("Senke öffnen: {e}"))?;

    let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let wall = wall_offset();
    let mut writer = Writer {
        seq: 0,
        sink: BufWriter::with_capacity(SINK_CAPACITY, sink),
        clk_tck,
        wall,
        cache: HashCache::default(),
        stats: ProcStats {
            enabled: stats,
            ..ProcStats::default()
        },
        parse_errors: 0,
        written: 0,
    };
    let mid = stop_mid.clone();
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    // ── 6. Capabilities reduzieren – VOR der start-Zeile ───────────────
    // Damit wer die start-Zeile liest, den reduzierten Zustand sieht; vorher
    // war die Reduktion NACH der start-Zeile, ein Leser konnte also den vollen
    // Satz Capabilities beobachten. Fehler → geordneter Abbruch (stderr,
    // stop-Zeile, Exit != 0).
    if let Err(e) = restrict_capabilities() {
        let ts = boottime_ns();
        let _ = writer.emit(&Event::Stop {
            ts,
            wall: ts.saturating_add(wall),
            mid: mid.clone(),
        });
        return Err(e.into());
    }

    // ── 7. start-Ereignis ─────────────────────────────────────────────
    let ts = boottime_ns();
    writer.emit(&Event::Start {
        ts,
        wall: ts + wall,
        mid,
        kernel,
    })?;

    // ── 8. Signal-Handler ───────────────────────────────────────────────
    // Bereits in Schritt 0 installiert, damit auch Abbrüche während BTF/eBPF-Load
    // über `STOP` erkannt werden.

    // ── 9. Poll-Schleife ──────────────────────────────────────────────
    eprintln!("exec-observer: lauscht (Senke {sink_path})");
    loop {
        if STOP.load(Ordering::SeqCst) {
            break;
        }
        // poll mit 100 ms Timeout, damit das Signal erkannt wird.
        let mut pfd = libc::pollfd {
            fd: ring_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, 100) };
        if ret < 0 {
            // Ein Signal meldet sich über STOP; EINTR ist dann kein Fehler.
            if STOP.load(Ordering::SeqCst) {
                break;
            }
            let errno = std::io::Error::last_os_error().raw_os_error();
            if errno == Some(libc::EINTR) {
                continue;
            }
            // Dauerhafte Poll-Fehler (z. B. ungültiger Ringpuffer-FD) dürfen
            // keine Busy-Loop erzeugen: geordnet mit stop-Zeile beenden.
            let err = std::io::Error::from_raw_os_error(errno.unwrap_or(libc::EIO));
            eprintln!("exec-observer: poll fehlgeschlagen: {err}");
            writer.emit(&Event::Stop {
                ts: boottime_ns(),
                wall: boottime_ns().saturating_add(wall),
                mid: stop_mid.clone(),
            })?;
            return Err(err.into());
        }
        if ret > 0 && (pfd.revents & libc::POLLIN) != 0 {
            // Stopp WIRD VOR dem Holen geprüft, nicht danach: Die alte
            // Reihenfolge (`while let Some` + Abbruch innen) verwarf ein
            // bereits geholtes, aber unverarbeitetes Ereignis stillschweigend
            // (gezählt in SEEN, nie geschrieben, nie in DROPS) – exakt die
            // Signatur des gesuchten −1. Ein nach TERM noch verarbeitetes
            // Ereignis ist dagegen harmlos (es wird gezählt).
            while !STOP.load(Ordering::SeqCst) {
                let Some(item) = events.next() else {
                    break;
                };
                let bytes: &[u8] = &item;
                match parse_exec_event(bytes) {
                    Ok(ev) => {
                        // Ein einzelnes kaputtes Ereignis (z. B. /proc-Read-Fehler)
                        // darf den Daemon nicht beenden; es wird nur gemeldet.
                        if let Err(e) = writer.process(&ev) {
                            eprintln!("exec-observer: Ereignis übersprungen ({e})");
                        }
                    }
                    Err(err) => writer.note_parse_error(err),
                }
            }
        }

        // Verlorene Ereignisse (Ringpuffer-Überlauf) melden. Die Differenz
        // seit der letzten Lesung liefert CounterDelta (eine Summe je Lesung).
        let delta = drops_ctr.update(&match drops.get(&0, 0) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("exec-observer: Fehler beim Lesen von DROPS: {e}");
                writer.emit(&Event::Stop {
                    ts: boottime_ns(),
                    wall: boottime_ns().saturating_add(wall),
                    mid: stop_mid.clone(),
                })?;
                if writer.stats.enabled {
                    eprint!("{}", writer.stats.render(0, writer.written, 0));
                }
                return Err(e.into());
            }
        });
        if delta > 0 {
            writer.emit_lost(delta)?;
        }
    }

    // ── 10. Shutdown-Drain mit Konvergenz (Entscheidung 7 + B4): Beim
    // geordneten Stopp erst alle noch im Ring liegenden Ereignisse
    // verarbeiten, dann stop. Danach Zähler lesen und nachleeren, bis eine
    // Runde nichts mehr findet: Versuche, die GENAU während des Auslesens
    // fertig wurden, wären sonst in SEEN, aber nicht in geschrieben enthalten
    // (praktisch 0, dokumentiert in SCHEMA.md §9). Deckel: 9 Runden, damit
    // Dauerausführende den Stopp nicht ewig verzögern.
    for _ in 0..9 {
        let mut n = 0u64;
        while let Some(item) = events.next() {
            n += 1;
            let bytes: &[u8] = &item;
            match parse_exec_event(bytes) {
                Ok(ev) => {
                    if let Err(e) = writer.process(&ev) {
                        eprintln!("exec-observer: Ereignis übersprungen ({e})");
                    }
                }
                Err(err) => writer.note_parse_error(err),
            }
        }
        let delta = drops_ctr.update(&match drops.get(&0, 0) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("exec-observer: Fehler beim Lesen von DROPS: {e}");
                std::process::exit(1);
            }
        });
        if delta > 0 {
            writer.emit_lost(delta)?;
        }
        seen_ctr.update(&match seen.get(&0, 0) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("exec-observer: Fehler beim Lesen von SEEN: {e}");
                std::process::exit(1);
            }
        });
        if n == 0 {
            break;
        }
    }

    // Endstände als Differenzen seit Start (B4-Erhaltung).
    let kernel_seen = seen_ctr.total();
    // `lost` sind nur die Kernel-seitigen Verluste (DROPS-Differenz);
    // Strukturfehler erscheinen separat als Sammel-`lost` im Strom.
    let lost_total = drops_ctr.total();

    // ── 11. stop-Ereignis ─────────────────────────────────────────────
    // Strukturell ungültige Ereignisse erscheinen als ein Sammel-`lost`, bevor
    // der Lauf mit `stop` endet. So bleibt ein ABI-Problem im Strom sichtbar.
    if writer.parse_errors > 0 {
        writer.emit_lost(writer.parse_errors)?;
    }
    let ts = boottime_ns();
    writer.emit(&Event::Stop {
        ts,
        wall: ts + wall,
        mid: stop_mid,
    })?;

    // --stats: nur stderr, keine Zeile im Strom verändert sich.
    if writer.stats.enabled {
        eprint!(
            "{}",
            writer.stats.render(kernel_seen, writer.written, lost_total)
        );
    }
    eprintln!("exec-observer: beendet");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── HASH-CACHE (synthetische Stat-Werte) ──────────────────────────

    fn ident(size: u64, mtime: i64, mtime_nsec: i64, ctime: i64, ctime_nsec: i64) -> FileIdent {
        FileIdent {
            dev: 1,
            ino: 2,
            size,
            mtime_sec: mtime,
            mtime_nsec,
            ctime_sec: ctime,
            ctime_nsec,
        }
    }

    fn changed(
        id: &FileIdent,
        size: u64,
        mtime_sec: i64,
        mtime_nsec: i64,
        ctime_sec: i64,
        ctime_nsec: i64,
    ) -> FileIdent {
        FileIdent {
            dev: id.dev,
            ino: id.ino,
            size,
            mtime_sec,
            mtime_nsec,
            ctime_sec,
            ctime_nsec,
        }
    }

    #[test]
    fn hash_cache_hit_when_all_identity_equal() {
        let mut c = HashCache::default();
        let id = ident(100, 5000, 42, 6000, 99);
        c.insert(&id, "a".repeat(64));
        assert_eq!(c.get(&id).unwrap(), "a".repeat(64));
    }

    /// Gleiche size/mtime, aber anderes ctime → kein Cache-Treffer (neu hashen).
    #[test]
    fn hash_cache_ctime_change_misses() {
        let mut c = HashCache::default();
        let base = ident(100, 5000, 42, 6000, 99);
        c.insert(&base, "a".repeat(64));
        let ctime_changed = changed(&base, 100, 5000, 42, 6001, 0);
        assert_eq!(c.get(&ctime_changed), None);
    }

    #[test]
    fn hash_cache_size_change_misses() {
        let mut c = HashCache::default();
        let base = ident(100, 5000, 42, 6000, 99);
        c.insert(&base, "a".repeat(64));
        let size_changed = changed(&base, 101, 5000, 42, 6000, 99);
        assert_eq!(c.get(&size_changed), None);
    }

    #[test]
    fn hash_cache_mtime_change_misses() {
        let mut c = HashCache::default();
        let base = ident(100, 5000, 42, 6000, 99);
        c.insert(&base, "a".repeat(64));
        let mtime_changed = changed(&base, 100, 5001, 0, 6000, 99);
        assert_eq!(c.get(&mtime_changed), None);
    }

    #[test]
    fn hash_cache_mtime_nsec_change_misses() {
        let mut c = HashCache::default();
        let base = ident(100, 5000, 42, 6000, 99);
        c.insert(&base, "a".repeat(64));
        let nano_changed = changed(&base, 100, 5000, 43, 6000, 99);
        assert_eq!(c.get(&nano_changed), None);
    }

    #[test]
    fn hash_cache_reinsert_keeps_entry() {
        let mut c = HashCache::default();
        let id = ident(100, 5000, 42, 6000, 99);
        c.insert(&id, "a".repeat(64));
        // geänderte Datei am selben dev/ino → frischer Hash, danach treffen.
        let changed_id = changed(&id, 101, 6000, 1, 7000, 2);
        c.insert(&changed_id, "b".repeat(64));
        assert_eq!(c.get(&changed_id).unwrap(), "b".repeat(64));
        assert_eq!(c.get(&id), None);
    }

    /// LRU: bei voller Obergrenze wird das ÄLTESTE verdrängt, nicht der komplette Cache.
    #[test]
    fn hash_cache_lru_evicts_oldest_only() {
        let mut c = HashCache::with_cap(2);
        let mut id1 = ident(1, 1, 0, 1, 0);
        let mut id2 = ident(2, 1, 0, 1, 0);
        let id3 = ident(3, 1, 0, 1, 0);
        id1.ino = 10;
        id2.ino = 11;
        c.insert(&id1, "1".repeat(64));
        c.insert(&id2, "2".repeat(64));
        // id1 und id2 vorhanden; Treffer auf id1 → id1 wird MRU.
        assert!(c.get(&id1).is_some());
        c.insert(&id3, "3".repeat(64)); // verdrängt das älteste (id2)
        assert_eq!(c.get(&id2), None, "id2 (ältestes) verdrängt");
        assert_eq!(c.get(&id1).unwrap(), "1".repeat(64));
        assert_eq!(c.get(&id3).unwrap(), "3".repeat(64));
    }

    /// Die LRU-Obergrenze wird auch bei reinen Inserts nie überschritten.
    #[test]
    fn hash_cache_lru_bound_is_never_exceeded() {
        let mut c = HashCache::with_cap(3);
        for i in 0..10u64 {
            let id = FileIdent {
                dev: 1,
                ino: i,
                size: 1,
                mtime_sec: 1,
                mtime_nsec: 0,
                ctime_sec: 1,
                ctime_nsec: 0,
            };
            c.insert(&id, format!("{i:x}").repeat(64));
        }
        assert!(c.map.len() <= 3, "map = {}", c.map.len());
        assert_eq!(c.order.len(), c.map.len());
        c.check_invariants();
    }

    // ── fd_exec (Punkt 2): nur aus dem Ereignispfad ───────────────────

    #[test]
    fn fd_exec_prefixes_are_detected() {
        assert!(is_fd_exec("/dev/fd/3"));
        assert!(is_fd_exec("/proc/self/fd/3"));
        assert!(is_fd_exec("/proc/self/fd/42"));
        assert!(is_fd_exec("/dev/fd/0"));
    }

    #[test]
    fn fd_exec_non_prefixes_are_not_detected() {
        assert!(!is_fd_exec("/bin/true"));
        assert!(!is_fd_exec("/memfd:exec-cases (deleted)"));
        assert!(!is_fd_exec("/tmp/exec-cases-del.abc123 (deleted)"));
        // ohne Schrägstrich: Verzeichnis selbst, kein Deskriptor
        assert!(!is_fd_exec("/dev/fd"));
        assert!(!is_fd_exec("/proc/self/fd"));
        // nur Präfix-Treffer am Anfang zählt
        assert!(!is_fd_exec("/opt/dev/fd/3"));
        assert!(!is_fd_exec(""));
    }

    #[test]
    fn fd_exec_flag_reaches_the_line() {
        // End-zu-End im Host: Writer::process mit fd-Pfad → Flag in der Zeile,
        // ganz ohne /proc und ohne lebenden Prozess.
        let ev = ExecEvent {
            pid: 1,
            ppid: 1,
            uid: 1000,
            euid: 1000,
            tid: 1,
            argc: 3,
            argc_min: 0,
            has_argc: 1,
            path_trunc: 0,
            _pad0: [0; 5],
            start_boot_time: 1,
            ts_boot: 1,
            comm: *b"h\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            filename_len: 0,
            filename: [0u8; MAX_FILENAME],
            _pad1: [0; 6],
            exe_ino: 0,
            exe_size: 0,
            has_exe_ident: 0,
            _pad2: [0; 7],
        };
        // Dateiname muss ebenfalls im Event stehen; process() liest ihn ab 0.
        let mut ev = ev;
        let name = b"/dev/fd/3";
        ev.filename[..name.len()].copy_from_slice(name);
        ev.filename_len = name.len() as u16;

        let dir = std::env::temp_dir().join(format!("fd-exec-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("sink.log");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
            .expect("Senke");
        let clk = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        let mut w = Writer {
            seq: 0,
            sink: BufWriter::with_capacity(4096, file),
            clk_tck: clk,
            wall: 0,
            cache: HashCache::default(),
            stats: ProcStats::default(),
            parse_errors: 0,
            written: 0,
        };
        // Der Prozess mit pid=1 existiert und die Startzeit passt nicht
        // zwangsläufig – process() würde dann `gone` liefern, ABER das
        // fd_exec-Flag steht bereits VOR dem Hashen in `flags` und wird
        // mitgegeben. Genau das ist der Punkt: unabhängig von /proc.
        let _ = w.process(&ev);
        drop(w);
        let line = std::fs::read_to_string(&path).expect("gelesen");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            line.contains("\"fd_exec\""),
            "fd_exec fehlt in der Zeile: {line}"
        );
    }

    #[test]
    fn parse_exec_event_accepts_exact_layout() {
        let ev = ExecEvent {
            pid: 1,
            ppid: 1,
            uid: 1,
            euid: 1,
            tid: 1,
            argc: 0,
            argc_min: 0,
            has_argc: 0,
            path_trunc: 0,
            _pad0: [0; 5],
            start_boot_time: 1,
            ts_boot: 1,
            comm: [0; 16],
            filename_len: 0,
            filename: [0; MAX_FILENAME],
            _pad1: [0; 6],
            exe_ino: 0,
            exe_size: 0,
            has_exe_ident: 0,
            _pad2: [0; 7],
        };
        let bytes = bytemuck::bytes_of(&ev);
        assert!(parse_exec_event(bytes).is_ok());
    }

    #[test]
    fn parse_exec_event_reports_wrong_lengths() {
        let ev = ExecEvent {
            pid: 1,
            ppid: 1,
            uid: 1,
            euid: 1,
            tid: 1,
            argc: 0,
            argc_min: 0,
            has_argc: 0,
            path_trunc: 0,
            _pad0: [0; 5],
            start_boot_time: 1,
            ts_boot: 1,
            comm: [0; 16],
            filename_len: 0,
            filename: [0; MAX_FILENAME],
            _pad1: [0; 6],
            exe_ino: 0,
            exe_size: 0,
            has_exe_ident: 0,
            _pad2: [0; 7],
        };
        let bytes = bytemuck::bytes_of(&ev);
        assert!(matches!(
            parse_exec_event(&bytes[..bytes.len() - 1]),
            Err(EventParseError::WrongLength(len)) if len == bytes.len() - 1
        ));
        assert!(matches!(
            parse_exec_event(&bytes[..0]),
            Err(EventParseError::WrongLength(0))
        ));
    }

    // ── Senkenöffnung (harte Links/Symlinks/FIFOs/Modi) ────────────────

    fn sink_test_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("exec-observer-sink-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("Temp-Verzeichnis");
        dir
    }

    #[test]
    fn sink_rejects_final_symlink() {
        let dir = sink_test_dir("symlink");
        let target = dir.join("target.log");
        let link = dir.join("sink.log");
        std::fs::write(&target, b"x").expect("Zieldatei");
        std::os::unix::fs::symlink(&target, &link).expect("Symlink");
        assert!(open_sink_file(&link.to_string_lossy()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sink_rejects_fifo_without_blocking() {
        let dir = sink_test_dir("fifo");
        let path = dir.join("sink.log");
        let cpath = CString::new(path.as_os_str().as_encoded_bytes().to_vec()).expect("Pfad");
        // SAFETY: gültiger, NUL-terminierter Pfad; Rückgabe wird geprüft.
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        assert!(open_sink_file(&path.to_string_lossy()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sink_rejects_hardlink_alias() {
        let dir = sink_test_dir("hardlink");
        let path = dir.join("sink.log");
        let alias = dir.join("alias.log");
        std::fs::write(&path, b"x").expect("Datei");
        std::fs::hard_link(&path, &alias).expect("Hardlink");
        assert!(open_sink_file(&path.to_string_lossy()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sink_normalizes_existing_mode_and_resolves_parent_symlink() {
        let dir = sink_test_dir("parent");
        let real = dir.join("real");
        std::fs::create_dir_all(&real).expect("Verzeichnis");
        let link_parent = dir.join("link");
        std::os::unix::fs::symlink(&real, &link_parent).expect("Eltern-Symlink");
        let requested = link_parent.join("sink.log");
        std::fs::write(&requested, b"x").expect("Datei");
        std::fs::set_permissions(&requested, std::fs::Permissions::from_mode(0o644))
            .expect("Modus");
        open_sink_file(&requested.to_string_lossy()).expect("Senke");
        let metadata = std::fs::metadata(real.join("sink.log")).expect("Metadaten");
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sink_rejects_empty_or_parentless_paths() {
        assert!(resolve_sink_path("").is_err());
        assert!(resolve_sink_path("/").is_err());
        assert!(open_sink_file("").is_err());
    }

    // ── cache_allowed (fileless/deleted → nie Cache) ──────────────────

    #[test]
    fn hash_budget_accepts_limit_and_rejects_larger_files() {
        assert!(hash_within_budget(MAX_HASH_BYTES));
        assert!(!hash_within_budget(MAX_HASH_BYTES + 1));
    }

    #[test]
    fn metadata_failure_has_no_cache_key() {
        let failed: std::io::Result<std::fs::Metadata> = Err(std::io::Error::other("fstat"));
        assert_eq!(cache_key(&failed), None);
    }

    #[test]
    fn reused_or_gone_discards_hash_and_fd_flags() {
        for state in [
            HashState::Gone,
            HashState::Reused,
            HashState::Unreadable,
            HashState::Superseded,
        ] {
            let (sha256, flags) = finalize_exec_output(
                Some("a".repeat(64)),
                vec![
                    Flag::Fileless,
                    Flag::Deleted,
                    Flag::Cached,
                    Flag::ArgcMin,
                    Flag::PathTrunc,
                    Flag::FdExec,
                ],
                state,
            );
            assert_eq!(sha256, None, "kein Hash bei {state:?}");
            assert_eq!(
                flags,
                vec![Flag::ArgcMin, Flag::PathTrunc, Flag::FdExec],
                "nur ereignisbezogene Flags bei {state:?}"
            );
        }
    }

    #[test]
    fn ok_keeps_hash_and_all_flags() {
        let (sha256, flags) = finalize_exec_output(
            Some("a".repeat(64)),
            vec![Flag::Fileless, Flag::Cached],
            HashState::Ok,
        );
        assert_eq!(sha256, Some("a".repeat(64)));
        assert_eq!(flags, vec![Flag::Fileless, Flag::Cached]);
    }

    #[test]
    fn cache_allowed_fileless_and_deleted_never_cache() {
        assert!(!cache_allowed(&[Flag::Fileless]));
        assert!(!cache_allowed(&[Flag::Deleted]));
        assert!(!cache_allowed(&[Flag::Fileless, Flag::Deleted]));
        assert!(cache_allowed(&[]));
        assert!(cache_allowed(&[Flag::ArgcMin]));
        assert!(cache_allowed(&[Flag::Lossy]));
        assert!(cache_allowed(&[Flag::Cached]));
    }

    // ── cached-Flag über einen echten, doppelten Aufruf ───────────────

    #[test]
    fn open_hash_flags_sets_cached_flag_only_on_hit() {
        let mut cache = HashCache::default();
        let pid = std::process::id();
        let (h1, s1, f1, _) = open_hash_flags(pid, &mut cache);
        assert_eq!(s1, HashState::Ok, "eigene Binary ist lesbar");
        assert!(!f1.contains(&Flag::Cached), "erster Aufruf hashst frisch");
        let (h2, s2, f2, _) = open_hash_flags(pid, &mut cache);
        assert_eq!(s2, HashState::Ok);
        assert_eq!(h1, h2, "Hash identisch, unverändert");
        assert!(
            f2.contains(&Flag::Cached),
            "zweiter Aufruf trifft den Cache: flags = {f2:?}"
        );
        assert_eq!(h2, Some(h1.unwrap()));
    }

    // ── hash_state: jeder Fall mit eigenem Test ───────────────────────

    #[test]
    fn hash_state_ok_when_exe_readable() {
        let mut cache = HashCache::default();
        let (sha, state, flags, _) = open_hash_flags(std::process::id(), &mut cache);
        assert_eq!(state, HashState::Ok, "eigene Binary lesbar → ok");
        assert!(sha.is_some());
        assert!(flags.is_empty() || !flags.contains(&Flag::Cached));
    }

    #[test]
    fn hash_state_gone_when_process_does_not_exist() {
        let pid: u32 = u32::MAX; // kein realer Prozess
        assert_eq!(proc_state(pid), ProcState::NotFound);
        let mut cache = HashCache::default();
        let (sha, state, _, _) = open_hash_flags(pid, &mut cache);
        assert_eq!(state, HashState::Gone);
        assert!(sha.is_none());
    }

    #[test]
    fn hash_state_unreadable_when_open_fails_but_alive() {
        // eigene PID lebt → ein Öffnen-Fehler wäre unreadable, nie gone.
        assert_eq!(proc_state(std::process::id()), ProcState::Running);
        assert_eq!(
            classify_open_failure(std::process::id(), Some(libc::EACCES)),
            HashState::Unreadable
        );
        // Deterministische unreadable-Bedingung: ein Zombie-Prozess ist per
        // /proc „lebend“ (Zustand Z), aber `/proc/<pid>/exe` lässt sich nicht
        // öffnen (kein mm). → open scheitert bei lebendem Prozess → unreadable.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork fehlgeschlagen");
        if child == 0 {
            unsafe { libc::_exit(0) };
        }
        // Warten, bis das Kind Zombie (Z) ist.
        let mut state = String::new();
        for _ in 0..1000 {
            state = fs::read_to_string(format!("/proc/{child}/status"))
                .unwrap_or_default()
                .lines()
                .find(|l| l.starts_with("State:"))
                .unwrap_or_default()
                .to_string();
            if state.contains("Z (zombie)") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(
            state.contains("Z (zombie)"),
            "Kind wurde nicht Zombie: {state:?}"
        );
        let mut cache = HashCache::default();
        let (sha, state, _, _) = open_hash_flags(child as u32, &mut cache);
        assert!(sha.is_none(), "Zombie hat keinen lesbaren Hash");
        assert_eq!(
            state,
            HashState::Gone,
            "Zombie (Z) gilt als nicht lebend → gone (Prozess beendet, nicht abgeholt)"
        );
        assert!(
            !matches!(
                proc_state(child as u32),
                ProcState::Running | ProcState::Unknown
            ),
            "Zombie zählt nicht als lebend"
        );
        unsafe {
            libc::waitpid(child, std::ptr::null_mut(), 0);
        }
    }

    // ── Punkt 4: reine classify(errno, ProcState) ─────────────────────

    #[test]
    fn classify_running_with_eacces_is_unreadable() {
        assert_eq!(
            classify(Some(libc::EACCES), ProcState::Running),
            HashState::Unreadable
        );
    }

    #[test]
    fn classify_running_with_eperm_is_unreadable() {
        assert_eq!(
            classify(Some(libc::EPERM), ProcState::Running),
            HashState::Unreadable
        );
    }

    #[test]
    fn classify_enoent_and_esrch_are_gone() {
        assert_eq!(
            classify(Some(libc::ENOENT), ProcState::Running),
            HashState::Gone
        );
        assert_eq!(
            classify(Some(libc::ESRCH), ProcState::Running),
            HashState::Gone
        );
    }

    #[test]
    fn classify_running_with_daemon_errno_is_unreadable() {
        // Nicht der Prozess, sondern der Daemon ist das Problem (z. B. EMFILE).
        // Der Aufrufer meldet das zusätzlich auf stderr.
        assert_eq!(
            classify(Some(libc::EMFILE), ProcState::Running),
            HashState::Unreadable
        );
        assert_eq!(
            classify(Some(libc::ENOMEM), ProcState::Running),
            HashState::Unreadable
        );
    }

    #[test]
    fn classify_dead_and_notfound_are_gone() {
        assert_eq!(
            classify(Some(libc::EACCES), ProcState::Dead),
            HashState::Gone
        );
        assert_eq!(
            classify(Some(libc::EACCES), ProcState::NotFound),
            HashState::Gone
        );
        assert_eq!(classify(None, ProcState::NotFound), HashState::Gone);
    }

    #[test]
    fn classify_zombie_is_always_gone() {
        for errno in [
            None,
            Some(libc::EACCES),
            Some(libc::EPERM),
            Some(libc::ENOENT),
            Some(libc::ESRCH),
            Some(libc::EMFILE),
        ] {
            assert_eq!(
                classify(errno, ProcState::Zombie),
                HashState::Gone,
                "Zombie ist immer gone, errno = {errno:?}"
            );
        }
    }

    // ── Punkt 4: /proc/<pid>/stat-Parser (comm mit Klammern/Leerzeichen) ──

    /// Baut eine `/proc/<pid>/stat`-Zeile mit vorgegebenem `comm` und
    /// `starttime` (Feld 22), Feld 3 = `state`.
    fn stat_line(comm: &str, state: char, starttime: u64) -> String {
        let mut fields = vec![state.to_string()];
        fields.extend((4..=21).map(|i| i.to_string()));
        fields.push(starttime.to_string());
        format!("123 ({comm}) {}", fields.join(" "))
    }

    #[test]
    fn parse_proc_stat_simple_comm() {
        let p = parse_proc_stat(&stat_line("a", 'R', 4242)).expect("parse");
        assert_eq!(p.state, 'R');
        assert_eq!(p.starttime_ticks, 4242);
    }

    #[test]
    fn parse_proc_stat_comm_with_space() {
        let p = parse_proc_stat(&stat_line("a b", 'S', 7)).expect("parse");
        assert_eq!(
            p.state, 'S',
            "Leerzeichen im comm darf den Zustand nicht verschieben"
        );
        assert_eq!(p.starttime_ticks, 7);
    }

    #[test]
    fn parse_proc_stat_comm_with_paren_and_space() {
        // `a) S (b` enthält genau die Zeichen, die einen naiven Parser täuschen.
        let p = parse_proc_stat(&stat_line("a) S (b", 'D', 99)).expect("parse");
        assert_eq!(p.state, 'D', "ab der letzten ) lesen");
        assert_eq!(p.starttime_ticks, 99);
    }

    #[test]
    fn parse_proc_stat_comm_with_parens() {
        let p = parse_proc_stat(&stat_line("((", 'Z', 123)).expect("parse");
        assert_eq!(p.state, 'Z');
        assert_eq!(p.starttime_ticks, 123);
        let p = parse_proc_stat(&stat_line(")", 'X', 456)).expect("parse");
        assert_eq!(p.state, 'X');
        assert_eq!(p.starttime_ticks, 456);
    }

    #[test]
    fn parse_proc_stat_without_closing_paren_is_none() {
        assert!(parse_proc_stat("123 R 0 0").is_none());
    }

    #[test]
    fn parse_proc_stat_unknown_state_is_not_running() {
        assert_eq!(
            parse_proc_stat(&stat_line("a", 'Q', 1)).map(|p| p.state),
            Some('Q')
        );
    }

    #[test]
    fn classify_unknown_state_follows_errno_rules() {
        assert_eq!(
            classify(Some(libc::EACCES), ProcState::Unknown),
            HashState::Unreadable
        );
        assert_eq!(
            classify(Some(libc::ENOENT), ProcState::Unknown),
            HashState::Gone
        );
    }

    #[test]
    fn parse_proc_stat_too_short_is_none() {
        // KEIN `)` und zu wenige Felder → None statt Panik.
        assert!(parse_proc_stat("").is_none());
        assert!(parse_proc_stat("123 (a) R").is_none());
    }

    // ── Zusammensetzung der zwei 32-Bit-Wörter (Teilauftrag 1) ────────────
    // Wort 0 = Caps 0–31, Wort 1 = Caps 32–63. Randfälle genau an der Wort-
    // grenze: Bit 31 (oberstes Bit von Wort 0) und Bit 32 (unterstes Bit von
    // Wort 1) müssen unterscheidbar bleiben – ein Vertauschen der Wörter
    // würde Bit 31 auf Bit 63 schieben und hier auffallen.

    #[test]
    fn compose_cap_words_puts_bit31_in_the_low_word() {
        assert_eq!(compose_cap_words(1 << 31, 0), 1u64 << 31);
    }

    #[test]
    fn compose_cap_words_puts_bit32_in_the_high_word() {
        assert_eq!(compose_cap_words(0, 1), 1u64 << 32);
        // beide Nachbarn gleichzeitig → exakt die beiden Bits, nichts dazwischen
        assert_eq!(compose_cap_words(1 << 31, 1), (1u64 << 31) | (1u64 << 32));
    }

    #[test]
    fn compose_cap_words_reaches_bits_35_38_39_40() {
        // Bits am oberen Ende – alle im Hochwort. Bit 35 = CAP_WAKE_ALARM: das
        // ist der Treffer aus dem Root-Lauf („vorhanden=0xc800080004" gegen
        // Bounding 0xc000080004). 38 = CAP_PERFMON, 39 = CAP_BPF,
        // 40 = CAP_CHECKPOINT_RESTORE.
        assert_eq!(compose_cap_words(0, 1 << 3), 1u64 << 35);
        assert_eq!(compose_cap_words(0, 1 << 6), 1u64 << 38);
        assert_eq!(compose_cap_words(0, 1 << 7), 1u64 << 39);
        assert_eq!(compose_cap_words(0, 1 << 8), 1u64 << 40);
        // alle vier zusammen: 35|38|39|40 = 0x1c8
        assert_eq!(
            compose_cap_words(0, 0x1c8),
            (1u64 << 35) | (1u64 << 38) | (1u64 << 39) | (1u64 << 40)
        );
    }

    #[test]
    fn compose_cap_words_explains_the_root_run_mask() {
        // Der gemessene Lauf: Bounding 0xc000080004 (Bits 2,19,38,39) plus
        // geerbt Bit 35 → vorhanden 0xc800080004. Wort 0 trägt 2 und 19,
        // Wort 1 die Bits 3, 6, 7 (→ 35, 38, 39).
        assert_eq!(compose_cap_words(0x0008_0004, 0xc8), 0xc800_0800_04);
        // und das Bounding allein (Wort 1 = 0xc0 → nur Bits 38, 39)
        assert_eq!(compose_cap_words(0x0008_0004, 0xc0), 0xc000_0800_04);
    }

    #[test]
    fn compose_cap_words_has_no_crosstalk_between_words() {
        // Wort 0 voll, Wort 1 leer → exakt die niedrigen 32 Bit (nicht mehr).
        assert_eq!(compose_cap_words(u32::MAX, 0), 0xFFFF_FFFF);
        // Wort 0 leer, Wort 1 voll → exakt die hohen 32 Bit.
        assert_eq!(compose_cap_words(0, u32::MAX), 0xFFFF_FFFF_0000_0000);
        // beides voll → alles; und 0/0 bleibt 0 (nicht u32::MAX durch default).
        assert_eq!(compose_cap_words(u32::MAX, u32::MAX), u64::MAX);
        assert_eq!(compose_cap_words(0, 0), 0);
    }

    #[test]
    fn compose_cap_words_matches_a_known_mask() {
        // 0xc800080004 = die Maskenform aus dem Root-Lauf (Bits 2, 19, 35, 38, 39)
        // – low trägt Bits 2 und 19, high die Bits 3, 6, 7 (→ 35, 38, 39).
        assert_eq!(compose_cap_words(0x0008_0004, 0xc8), 0xc800_0800_04);
    }

    // ── CounterDelta (Punkt 2): Per-CPU-Differenzbildung ──────────────

    #[test]
    fn counter_delta_starts_at_zero_with_zero_reading() {
        let mut c = CounterDelta::start(&[0, 0, 0]);
        assert_eq!(c.total(), 0);
        assert_eq!(c.update(&[0, 0, 0]), 0);
        assert_eq!(c.total(), 0);
    }

    #[test]
    fn counter_delta_sums_per_cpu_values_once_per_reading() {
        // Drei CPUs: 1+2+3 = 6, keine doppelte Summierung.
        let mut c = CounterDelta::start(&[1, 2, 3]);
        assert_eq!(c.total(), 0);
        // Zähler ändern sich zwischen Lesungen (eine CPU +3).
        assert_eq!(c.update(&[1, 2, 6]), 3);
        assert_eq!(c.total(), 3);
        // Nur Umverteilung zwischen CPUs (Summe gleich) → Delta 0.
        assert_eq!(c.update(&[4, 2, 3]), 0);
        assert_eq!(c.total(), 3);
    }

    #[test]
    fn counter_delta_accepts_nonzero_start() {
        // Map zählte beim Daemonstart bereits (Anfangswert != 0): nur
        // Differenzen danach zählen.
        let mut c = CounterDelta::start(&[10, 20]);
        assert_eq!(c.total(), 0);
        assert_eq!(c.update(&[10, 20]), 0);
        assert_eq!(c.update(&[11, 22]), 3);
        assert_eq!(c.total(), 3);
    }

    #[test]
    fn counter_delta_wraps_safely() {
        let mut c = CounterDelta::start(&[u64::MAX]);
        // Zählerüberlauf: 2 − MAX wrapping = 3, keine Panik, kein Sprung.
        assert_eq!(c.update(&[2]), 3);
        assert_eq!(c.total(), 3);
    }

    // ── ProcStats (Teilauftrag: --stats) ────────────────────────────────

    fn stats_on() -> ProcStats {
        ProcStats {
            enabled: true,
            ..ProcStats::default()
        }
    }

    #[test]
    fn proc_stats_counts_per_hash_state() {
        let mut st = stats_on();
        st.record(HashState::Ok, Some(10));
        st.record(HashState::Ok, Some(20));
        st.record(HashState::Gone, Some(30));
        st.record(HashState::Unreadable, None); // kein Messwert (ts_boot = 0)
        st.record(HashState::Reused, Some(1));
        st.record(HashState::Superseded, Some(2));
        assert_eq!(st.counts[ProcStats::idx(HashState::Ok)], 2);
        assert_eq!(st.counts[ProcStats::idx(HashState::Gone)], 1);
        assert_eq!(st.counts[ProcStats::idx(HashState::Unreadable)], 1);
        assert_eq!(st.counts[ProcStats::idx(HashState::Reused)], 1);
        assert_eq!(st.counts[ProcStats::idx(HashState::Superseded)], 1);
        // unreadable hat keinen Messwert → keine Stichprobe
        assert!(
            ProcStats::describe(&st.delays_us[ProcStats::idx(HashState::Unreadable)]).is_none()
        );
    }

    #[test]
    fn proc_stats_counts_ident_missing_separately() {
        let mut st = stats_on();
        st.record_ident_missing();
        st.record_ident_missing();
        assert_eq!(st.ident_missing, 2);
        assert!(st.render(0, 0, 0).contains("ident_missing n=2"));
        // Ohne --stats keine Zählung.
        let mut off = ProcStats::default();
        off.record_ident_missing();
        assert_eq!(off.ident_missing, 0);
    }

    #[test]
    fn proc_stats_ignores_everything_when_disabled() {
        let mut st = ProcStats::default(); // enabled = false
        st.record(HashState::Ok, Some(5));
        st.record(HashState::Gone, Some(5));
        assert_eq!(
            st.counts.iter().sum::<u64>(),
            0,
            "ohne --stats keine Zählung"
        );
        assert!(!st.render(0, 0, 0).contains("--stats: 1"));
    }

    #[test]
    fn proc_stats_percentiles_are_sane() {
        let mut st = stats_on();
        // 1..=100 → min 1, max 100, median 50/51, p99 = 99
        for i in 1..=100u64 {
            st.record(HashState::Ok, Some(i));
        }
        let (n, min, med, p99, max) =
            ProcStats::describe(&st.delays_us[ProcStats::idx(HashState::Ok)]).unwrap();
        assert_eq!((n, min, max), (100, 1, 100));
        assert!((med == 50 || med == 51), "median={med}");
        assert_eq!(p99, 99);
    }

    #[test]
    fn proc_stats_delay_samples_stay_bounded() {
        let mut st = stats_on();
        for i in 0..(MAX_DELAY_SAMPLES as u64 + 10) {
            st.record(HashState::Ok, Some(i));
        }
        let i = ProcStats::idx(HashState::Ok);
        assert_eq!(st.counts[i] as usize, MAX_DELAY_SAMPLES + 10);
        assert_eq!(st.delays_us[i].len(), MAX_DELAY_SAMPLES);
    }

    #[test]
    fn proc_stats_render_is_parseable() {
        let mut st = stats_on();
        st.record(HashState::Ok, Some(42));
        st.record_ident_missing();
        let r = st.render(7, 5, 2);
        assert!(r.contains("exec-observer: --stats begin"));
        assert!(r.contains("exec-observer: --stats end"));
        assert!(!r.contains("hash_state=["), "kein Platzhalter im Block");
        assert!(r.contains("n=1"));
        assert!(r.contains("kernel_seen=7 geschrieben=5 lost=2"));
        assert!(r.contains("ident_missing n=1"));
        // Die Reihenfolge ist ok, gone, unreadable, reused, superseded
        let i_ok = r.find("ok").expect("ok gefunden");
        let i_gone = r.find("gone").expect("gone gefunden");
        assert!(i_ok < i_gone, "ok-Zeile vor gone-Zeile");
    }

    // cap_get() gegen /proc/self/status: schlägt das fehl, ist die
    // Schnittbildung stillschweigend 0 – und der Daemon läuft mit KEINEN
    // Capabilities (genau das zeigte der Root-Lauf von cap-matrix).

    #[test]
    fn cap_get_agrees_with_proc_self_status() {
        let from_syscall = cap_get().expect("capget muss gelingen");
        let from_proc: u64 = std::fs::read_to_string("/proc/self/status")
            .expect("/proc/self/status")
            .lines()
            .find_map(|l| l.strip_prefix("CapPrm:").map(|v| v.trim()))
            .and_then(|v| u64::from_str_radix(v, 16).ok())
            .expect("CapPrm-Zeile");
        assert_eq!(
            from_syscall, from_proc,
            "capget=0x{from_syscall:x} vs /proc=0x{from_proc:x}"
        );
    }

    // ── CAPABILITY-ZIELMENGE (Teilauftrag 2: nie größer als vorgesehen) ──────

    #[test]
    fn capability_target_is_the_full_minimum_when_everything_is_available() {
        // Volle Root-Menge → genau die drei gewollten Caps.
        assert_eq!(capability_target(u64::MAX), KEEP_WANTED);
        assert_eq!(KEEP_WANTED, 0x0000_0080_0008_0004);
    }

    #[test]
    fn capability_target_falls_back_without_a_cap() {
        // Ohne CAP_SYS_PTRACE (gesenktes Bounding-Set) → nur dac_read+bpf.
        let no_ptrace = KEEP_WANTED & !bit(CAP_SYS_PTRACE);
        assert_eq!(capability_target(no_ptrace), 0x0000_0080_0000_0004);
    }

    #[test]
    fn capability_target_never_keeps_perfmon() {
        // CAP_PERFMON war im Root-Satz enthalten und darf nie überleben.
        let available = bit(CAP_PERFMON) | KEEP_WANTED;
        assert_eq!(capability_target(available), KEEP_WANTED);
        assert_eq!(capability_target(available) & bit(CAP_PERFMON), 0);
    }

    // ── --caps=...-Override (nur Feature "cap-matrix", Punkt 3) ──────────

    #[cfg(feature = "cap-matrix")]
    #[test]
    fn caps_override_parses_known_names() {
        assert_eq!(
            parse_caps_override("ptrace,dac").unwrap(),
            bit(CAP_SYS_PTRACE) | bit(CAP_DAC_READ_SEARCH)
        );
        assert_eq!(
            parse_caps_override("bpf,perfmon,sys_ptrace,dac_read_search").unwrap(),
            bit(CAP_BPF) | bit(CAP_PERFMON) | bit(CAP_SYS_PTRACE) | bit(CAP_DAC_READ_SEARCH)
        );
        assert!(parse_caps_override("sys_admin").is_err());
        assert!(parse_caps_override("").is_err());
    }

    #[test]
    fn capability_target_is_never_larger_than_available() {
        // Invariante: Ergebnis ⊆ Wunschmenge ⊆ vorhandene Menge. Mit einer
        // anderen Menge weiterlaufen kann der Daemon damit nicht.
        for available in [
            0u64,
            bit(CAP_SYS_PTRACE),
            bit(CAP_DAC_READ_SEARCH),
            bit(CAP_BPF),
            bit(CAP_PERFMON),
            KEEP_WANTED,
            u64::MAX,
        ] {
            let target = capability_target(available);
            assert_eq!(target & !KEEP_WANTED, 0, "Zielmenge enthält Ungewolltes");
            assert_eq!(target & !available, 0, "Zielmenge größer als vorhanden");
        }
    }

    #[test]
    fn capability_target_with_nothing_available_keeps_nothing() {
        assert_eq!(capability_target(0), 0);
    }

    #[test]
    fn last_cap_is_clamped_to_valid_indices() {
        assert_eq!(clamp_last_cap(-1), 0);
        assert_eq!(clamp_last_cap(40), 40);
        assert_eq!(clamp_last_cap(63), 63);
        assert_eq!(clamp_last_cap(64), 63);
        assert_eq!(clamp_last_cap(i32::MAX), 63);
    }

    #[test]
    fn capability_status_parser_reads_all_five_sets() {
        let contents = "\
Name:\ttrue
CapInh:\t0000000000000000
CapPrm:\t000000c000080004
CapEff:\t000000c000080004
CapBnd:\t000000c000080004
CapAmb:\t0000000000000000
";
        assert_eq!(
            parse_capability_status(contents),
            Some(CapabilitySets {
                effective: 0x0000_00c0_0008_0004,
                permitted: 0x0000_00c0_0008_0004,
                inheritable: 0,
                ambient: 0,
                bounding: 0x0000_00c0_0008_0004,
            })
        );
        assert_eq!(parse_capability_status("CapPrm: 1\n"), None);
        assert_eq!(parse_capability_status("CapEff: xyz\n"), None);
    }

    #[test]
    fn expected_post_reduction_keeps_bounding_without_setpcap() {
        let before = CapabilitySets {
            effective: 0x0000_00c0_0008_0004,
            permitted: 0x0000_00c0_0008_0004,
            inheritable: 0,
            ambient: 0,
            bounding: 0x0000_00c0_0008_0004,
        };
        assert_eq!(
            expected_post_reduction(before, KEEP_WANTED),
            CapabilitySets {
                effective: KEEP_WANTED,
                permitted: KEEP_WANTED,
                inheritable: 0,
                ambient: 0,
                bounding: 0x0000_00c0_0008_0004,
            }
        );
    }

    #[test]
    fn expected_post_reduction_prunes_bounding_with_setpcap() {
        let before = CapabilitySets {
            effective: u64::MAX,
            permitted: u64::MAX,
            inheritable: u64::MAX,
            ambient: u64::MAX,
            bounding: u64::MAX,
        };
        assert_eq!(
            expected_post_reduction(before, KEEP_WANTED),
            CapabilitySets {
                effective: KEEP_WANTED,
                permitted: KEEP_WANTED,
                inheritable: 0,
                ambient: 0,
                bounding: KEEP_WANTED,
            }
        );
    }

    #[test]
    fn hash_state_reused_when_starttime_changed() {
        let clk = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as i64;
        let own = proc_start_time_ns(std::process::id(), clk).expect("eigene Startzeit");
        // unveränderte Startzeit → bleibt ok
        assert_eq!(
            verify_hash_state_after(std::process::id(), own, clk, HashState::Ok),
            HashState::Ok
        );
        // simulierte andere Startzeit (PID-Wiederverwendung) → reused
        let other = own + 1_000_000_000;
        assert_eq!(
            verify_hash_state_after(std::process::id(), other, clk, HashState::Ok),
            HashState::Reused
        );
        // nicht-Ok-Vorstufen bleiben unverändert durchlaufen
        assert_eq!(
            verify_hash_state_after(std::process::id(), other, clk, HashState::Gone),
            HashState::Gone
        );
        assert_eq!(
            verify_hash_state_after(std::process::id(), other, clk, HashState::Unreadable),
            HashState::Unreadable
        );
        // Prozess weg nach dem Hashen → gone
    }

    // ── EREIGNIS-IDENTITÄT (ino/size): gleich / ungleich / fehlend ──

    #[test]
    fn exe_identity_match_when_ino_and_size_equal() {
        assert_eq!(
            resolve_exe_identity(Some((11, 22)), Some((11, 22))),
            ExeIdentity::Match
        );
    }

    #[test]
    fn exe_identity_mismatch_when_ino_differs() {
        // Spätere Exec-Stufe derselben PID (andere Datei) → superseded.
        assert_eq!(
            resolve_exe_identity(Some((11, 22)), Some((99, 22))),
            ExeIdentity::Mismatch
        );
    }

    #[test]
    fn exe_identity_mismatch_when_size_differs() {
        assert_eq!(
            resolve_exe_identity(Some((11, 22)), Some((11, 23))),
            ExeIdentity::Mismatch
        );
    }

    #[test]
    fn exe_identity_unavailable_when_sensor_identity_missing() {
        // Keine Attribuierung ohne Sensor-Identität (→ unreadable, Zähler
        // ident_missing), selbst wenn der FD lesbar wäre.
        assert_eq!(
            resolve_exe_identity(None, Some((11, 22))),
            ExeIdentity::Unavailable
        );
        assert_eq!(resolve_exe_identity(None, None), ExeIdentity::Unavailable);
    }

    #[test]
    fn exe_identity_unavailable_when_opened_identity_missing() {
        assert_eq!(
            resolve_exe_identity(Some((11, 22)), None),
            ExeIdentity::Unavailable
        );
    }

    // ── ZEITBASIS (Punkt 6): einheitlich CLOCK_BOOTTIME ───────────────

    fn mono_now_ns() -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
    }

    #[test]
    fn boottime_is_at_least_monotonic() {
        // CLOCK_BOOTTIME zählt ab Boot inklusive Suspend → nie kleiner als
        // CLOCK_MONOTONIC. Gleiche Basis wie Kernel-Feld start_boot_time/ts_boot.
        let mono = mono_now_ns();
        let boot = boottime_ns();
        assert!(mono > 0, "Monotonic-Uhr lief");
        assert!(boot >= mono, "boot={boot} ≥ mono={mono}");
    }

    #[test]
    fn timespec_conversion_rejects_invalid_clock_values() {
        assert_eq!(timespec_to_ns(1, 2), Some(1_000_000_002));
        assert_eq!(timespec_to_ns(0, 999_999_999), Some(999_999_999));
        assert_eq!(timespec_to_ns(-1, 0), None);
        assert_eq!(timespec_to_ns(1, -1), None);
        assert_eq!(timespec_to_ns(1, 1_000_000_000), None);
        assert_eq!(timespec_to_ns(i64::MAX, 999_999_999), None);
    }

    #[test]
    fn boottime_comparison_is_one_sided_and_fail_closed() {
        // /proc rundet ab: dasselbe Ereignis liegt auf oder nach dem Feldwert.
        assert!(matches_boottime(1_000, 1_000, 100));
        assert!(matches_boottime(1_000, 1_000 + 9_999_999, 100));
        // Ein /proc-Wert in der Zukunft gehört einer anderen Instanz.
        assert!(!matches_boottime(1_001, 1_000, 100));
        assert!(!matches_boottime(1_000, 1_000 + 10_000_001, 100));
        // Ungültige Taktrate: keine Übereinstimmung statt 1-s-Toleranz.
        assert!(!matches_boottime(1_000, 1_000, 0));
        assert!(!matches_boottime(1_000, 1_000, -1));
        assert_eq!(proc_start_time_ns(std::process::id(), 0), None);
    }

    #[test]
    fn wall_offset_maps_boottime_to_realtime() {
        // wall = ts(boot) + wall_offset muss ≈ realtime ergeben (Toleranz: die
        // Zeit zwischen Offset-Messung und Testaufruf, hier großzügig 10 s).
        let boot = boottime_ns();
        let wall = boot.saturating_add(wall_offset());
        let real = realtime_ns();
        let delta = wall.abs_diff(real);
        assert!(
            delta < 10_000_000_000,
            "wall={wall} realtime={real} delta={delta}ns"
        );
    }

    #[test]
    fn boot_id_must_not_be_empty() {
        assert_eq!(
            normalize_boot_id("4a3f-...-boot-id\n"),
            Some("4a3f-...-boot-id".to_string())
        );
        assert_eq!(normalize_boot_id(""), None);
        assert_eq!(normalize_boot_id("   \n"), None);
    }

    #[test]
    fn event_ts_uses_sensor_boottime_with_fallback() {
        // gesetztes ts_boot wird durchgereicht (Kernel-Basis);
        // 0 (unbekannt/nicht gesetzt) fällt auf die Daemon-Bootzeit zurück.
        let before = boottime_ns();
        assert_eq!(event_ts(1_234_567_u64), 1_234_567_u64);
        let ts0 = event_ts(0);
        assert!(ts0 >= before, "Fallback liegt in der Gegenwart oder später");
        assert!(ts0 <= boottime_ns());
    }
}
