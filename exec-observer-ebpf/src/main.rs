#![no_std]
#![no_main]

//! eBPF-Sensor des Exec-Beobachters (Phase 6c / Schritt 2).
//!
//! Drei Tracepoints:
//!   - `sys_enter_execve` / `sys_enter_execveat`: zählen `argv`-Pointer,
//!     speichern `argc` in `ARGS` (Key = Prozess-TGID + Thread-TID, passend zu
//!     `old_pid` im `sched_process_exec`-Tracepoint; Thread-Execs bleiben so
//!     eindeutig und überschreiben einander nicht).
//!     Als Gültigkeits-Cookie wird die `start_boottime` des `group_leader`
//!     abgelegt – dieselbe Identität, die `sched_process_exec` liest (der
//!     Tracepoint feuert nach `de_thread`, das dem ausführenden Thread die
//!     Leader-Startzeit gibt).
//!   - `sched_process_exec`: liest Identität + `argc` (Key = TGID+TID),
//!     löscht den Eintrag, schreibt ein `ExecEvent` in den Ringpuffer.
//!     Zusätzlich liest er die Datei-Identität `(i_ino, i_size)` aus
//!     `mm->exe_file` zum Ereigniszeitpunkt; der Daemon vergleicht sie mit
//!     `fstat` des geöffneten FDs und verwirft überholte Hashes
//!     (`superseded`), statt falsche zu liefern.
//!
//! Offsets für `task_struct`-Felder werden vom Daemon aus der BTF gelesen und
//! als Konstanten über die `OFFSETS`-Map gesetzt (manuelles CO-RE, fail-closed
//! wenn ein Feld fehlt).
//!
//! Ringpuffer-Überläufe sind für den Nutzer nicht still: Fehlgeschlagene
//! Reservierungen zählen per CPU in `DROPS`; der Daemon meldet sie als
//! `lost`-Ereignisse.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_task, bpf_probe_read_kernel,
        bpf_probe_read_kernel_buf, bpf_probe_read_user,
    },
    macros::{map, tracepoint},
    maps::{Array, LruHashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
    EbpfContext,
};

use exec_observer_uapi::{
    args_key, resolve_argc, ArgsEntry, ExecEvent, MAX_FILENAME, MAX_TASK_OFFSET, OFFSETS_LEN,
    OFF_CRED, OFF_EUID, OFF_EXE_FILE, OFF_F_INODE, OFF_GROUP_LEADER, OFF_INO, OFF_I_SIZE, OFF_MM,
    OFF_REAL_PARENT, OFF_START_BOOT_TIME, OFF_TGID, OFF_UID, PATH_BUF_SIZE, TASK_COMM_LEN,
};

/// Obergrenze für gezählte `argv`-Pointer (S4: verhindert Amplifikation durch
/// riesige argv-Arrays). Ab hier zählt `count_argv` nur noch bis zum ersten
/// Lesen; `argc_min` meldet dann eine Untergrenze.
const ARGC_LIMIT: u32 = 1024;
const MAX_ARGS_ENTRIES: u32 = 65536;

// ── Maps ───────────────────────────────────────────────────────────────

/// BTF-Offsets (vom Daemon gesetzt): real_parent, tgid, cred, uid, euid,
/// start_boottime, group_leader, mm, exe_file, f_inode, i_ino, i_size.
#[map]
pub static OFFSETS: Array<u64> = Array::with_max_entries(OFFSETS_LEN, 0);

/// Bereitschaftsmarke für `OFFSETS`: Der Daemon setzt sie erst, nachdem er alle
/// sieben Offsets geschrieben hat. Die Array-Map initialisiert fehlende Werte
/// mit Null; ohne diese Marke könnte der Sensor keinen fehlenden Offset von
/// einem gültigen Offset 0 unterscheiden und Kernel-Speicher an `task + 0`
/// lesen.
#[map]
pub static OFFSETS_READY: Array<u8> = Array::with_max_entries(1, 0);

/// Prozess-PID/TID → [`ArgsEntry`] (uapi, enthält `start_boottime`-Cookie und
/// Eintrittszeit für die Gültigkeitsprüfung, siehe `resolve_argc`). Der
/// kombinierte Schlüssel verhindert, dass gleichzeitige Execs verschiedener
/// Threads desselben Prozesses einander überschreiben. LRU, damit auch Einträge
/// fehlgeschlagener execve-Aufrufe nach oben begrenzt bleiben (sonst gäbe es
/// keine Obergrenze).
#[map]
pub static ARGS: LruHashMap<u64, ArgsEntry> = LruHashMap::with_max_entries(MAX_ARGS_ENTRIES, 0);

/// Exec-Ereignisse für den Daemon.
#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Pro-CPU-Zähler für verlorene Ereignisse (Reservierung fehlgeschlagen).
#[map]
pub static DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Pro-CPU-Zähler ALLER `sched_process_exec`-Versuche (gesendet + verworfen).
/// Der Daemon bildet die Differenz seit Start (`kernel_seen`) und prüft die
/// Erhaltung geschrieben + lost == kernel_seen (B4).
#[map]
pub static SEEN: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Per-CPU-Zwischenablage für den Dateinamen (statt eines großen Stack-
/// Puffers; BPF-Stack-Limit 512 Bytes). Größe = `PATH_BUF_SIZE` (PATH_MAX):
/// soviel ist pro Ereignis erreichbar. Der Inhalt wird danach auf das
/// Event-Feld `filename` (max. `MAX_FILENAME`) gekürzt kopiert.
#[map]
pub static PATH_BUF: PerCpuArray<[u8; PATH_BUF_SIZE]> = PerCpuArray::with_max_entries(1, 0);

// ── Helfer ─────────────────────────────────────────────────────────────

#[inline]
fn offsets_ready() -> Result<(), i32> {
    match OFFSETS_READY.get(0) {
        Some(1) => Ok(()),
        _ => Err(-1),
    }
}

#[inline]
fn get_offset(idx: u32) -> Result<u64, i32> {
    match OFFSETS.get(idx) {
        Some(v) if *v <= MAX_TASK_OFFSET => Ok(*v),
        _ => Err(-1),
    }
}

/// Liest ein `u64` (z. B. einen Zeiger) an `addr + off` aus Kernel-Speicher.
#[inline]
fn read_u64_at(addr: u64, off: u64) -> Result<u64, i32> {
    let addr = addr.checked_add(off).ok_or(-1)?;
    unsafe { bpf_probe_read_kernel(addr as *const u64) }
}

/// Liest ein `u32` an `addr + off` aus Kernel-Speicher.
#[inline]
fn read_u32_at(addr: u64, off: u64) -> Result<u32, i32> {
    let addr = addr.checked_add(off).ok_or(-1)?;
    unsafe { bpf_probe_read_kernel(addr as *const u32) }
}

/// Verlangt einen Nicht-Null-Zeiger, bevor task_struct-Zeiger dereferenziert
/// werden.
#[inline]
fn nonzero_addr(addr: u64) -> Result<u64, i32> {
    if addr == 0 {
        Err(-1)
    } else {
        Ok(addr)
    }
}

/// Zählt die `argv`-Pointer (NULL-terminiertes Array in Userspace). Liefert
/// `(argc, argc_min)`. `argc_min` wird nur gesetzt, wenn `argc` eine echte
/// Untergrenze ist (Lesefehler oder Abbruch am Limit ohne Terminator).
fn count_argv(argv_ptr: u64) -> (u32, u8) {
    let mut argc: u32 = 0;
    let mut terminated = false;
    let mut i: u32 = 0;
    while i < ARGC_LIMIT {
        let p: Result<u64, i32> =
            unsafe { bpf_probe_read_user((argv_ptr + (i as u64) * 8) as *const u64) };
        match p {
            Ok(0) => {
                terminated = true;
                break;
            }
            Ok(_) => {
                argc += 1;
            }
            Err(_) => {
                // Lesefehler: abbrechen, Zählstand ist Untergrenze.
                break;
            }
        }
        i += 1;
    }
    // Am Limit ohne Terminator: prüfe noch die Position `ARGC_LIMIT`.
    // Trennt „regulär abgeschlossen mit exakt ARGC_LIMIT Argumenten“ (K1) von
    // „wirklich mehr Argumente vorhanden“ (→ unterschätzte Untergrenze).
    if !terminated && i == ARGC_LIMIT {
        if let Ok(0) = unsafe { bpf_probe_read_user((argv_ptr + (i as u64) * 8) as *const u64) } {
            terminated = true;
        }
    }
    let argc_min = if terminated { 0 } else { 1 };
    (argc, argc_min)
}

/// Liest die `start_boottime` des `group_leader` des aktuellen Tasks – die
/// stabile Prozess-Identität. Führt ein Nicht-Hauptthread `execve` aus, macht
/// `de_thread` ihn zum neuen Leader und übernimmt dessen `start_boottime`; der
/// `sched_process_exec`-Tracepoint feuert erst danach. Deshalb wird an beiden
/// Enden (hier am `sys_enter`, unten am `sched_process_exec`) dieselbe
/// group_leader-Identität verwendet, nicht die eigene Startzeit des Threads.
/// Fehler (Offset-Map nicht gesetzt, Lesefehler) → `None`: dann wird kein
/// Eintrag gespeichert und `argc` später als unbekannt behandelt – nie falsch.
fn group_leader_start_boottime() -> Option<u64> {
    let off_gl = get_offset(OFF_GROUP_LEADER).ok()?;
    let off_start = get_offset(OFF_START_BOOT_TIME).ok()?;
    let task = nonzero_addr(unsafe { bpf_get_current_task() }).ok()?;
    let leader = nonzero_addr(read_u64_at(task, off_gl).ok()?).ok()?;
    read_u64_at(leader, off_start).ok()
}

/// Liest die Datei-Identität zum Ereigniszeitpunkt:
/// `current->mm->exe_file->f_inode->{i_ino, i_size}`.
///
/// `sched_process_exec` feuert erst nach dem erfolgreichen Exec; `mm->exe_file`
/// zeigt dann bereits auf die neue Datei (Annahme, empirisch geprüft über den
/// Integrationsfall „Sensoridentität der Helferstufe == stat des Helfers“).
/// `s_dev` wird bewusst nicht gelesen: auf btrfs weicht `st_dev` von der
/// Superblock-Nummer ab (gemessen: Mount `0:35`, Datei-`st_dev` `0:37`).
/// Jeder Fehlschlag (Offset fehlt, Nullzeiger, Lesefehler) → `None`: Der
/// Daemon darf dann keinen Hash attributieren (`unreadable`, Zähler
/// `ident_missing`), statt einen falschen Hash zu liefern.
fn exe_file_identity() -> Option<(u64, u64)> {
    let off_mm = get_offset(OFF_MM).ok()?;
    let off_exe = get_offset(OFF_EXE_FILE).ok()?;
    let off_f_inode = get_offset(OFF_F_INODE).ok()?;
    let off_ino = get_offset(OFF_INO).ok()?;
    let off_size = get_offset(OFF_I_SIZE).ok()?;
    let task = nonzero_addr(unsafe { bpf_get_current_task() }).ok()?;
    let mm = nonzero_addr(read_u64_at(task, off_mm).ok()?).ok()?;
    let file = nonzero_addr(read_u64_at(mm, off_exe).ok()?).ok()?;
    let inode = nonzero_addr(read_u64_at(file, off_f_inode).ok()?).ok()?;
    let ino = read_u64_at(inode, off_ino).ok()?;
    // `i_size` ist `loff_t` (s64); das Bitmuster wird unverändert als `u64`
    // transportiert und mit `st_size` verglichen (reguläre Dateien ≥ 0).
    let size = read_u64_at(inode, off_size).ok()?;
    Some((ino, size))
}

/// Inkrementiert den Drop-Zähler der aktuellen CPU. Bei Per-CPU-Maps ohne
/// Konkurrenz auf derselben CPU reicht ein plain Store/Load.
fn count_drop() {
    if let Some(p) = DROPS.get_ptr_mut(0) {
        unsafe {
            *p += 1;
        }
    }
}

/// Zählt jeden `sched_process_exec`-Versuch – auch solche, die danach als
/// `lost` enden. Nur so kann der Daemon `geschrieben + lost == kernel_seen`
/// prüfen, statt die Ereigniszahl zu schätzen.
fn count_seen() {
    if let Some(p) = SEEN.get_ptr_mut(0) {
        unsafe {
            *p += 1;
        }
    }
}

// ── sys_enter_execve ───────────────────────────────────────────────────

#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    count_and_store(ctx, 24)
}

#[tracepoint]
pub fn sys_enter_execveat(ctx: TracePointContext) -> u32 {
    count_and_store(ctx, 32)
}

/// Liest `argv` aus dem Syscall-Tracepoint (Offset `argv_off`), zählt die
/// Pointer und speichert das Ergebnis unter `args_key()` (Prozess-PID/TGID)
/// zusammen mit der `start_boottime` des Prozesses (Gültigkeits-Cookie).
fn count_and_store(ctx: TracePointContext, argv_off: usize) -> u32 {
    let argv: u64 = match unsafe { ctx.read_at::<u64>(argv_off) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    // Ein NULL-Zeiger ist kein lesbares Array: keinen Zählerstand speichern und
    // später `argc` als unbekannt behandeln, statt einen Lesefehler als Untergrenze
    // mit `has_argc = 1` zu speichern.
    if argv == 0 {
        return 0;
    }
    // Ohne vollständig gesetzte Offsets keine Identität speichern.
    if offsets_ready().is_err() {
        return 0;
    }
    let (argc, argc_min) = count_argv(argv);
    // Prozess-Identität mitführen (group_leader, nicht der Thread selbst):
    // Ohne sie wäre ein veralteter Eintrag (von einem fehlgeschlagenen execve)
    // nach PID-Wiederverwendung nicht vom korrekten unterscheidbar (K10); mit
    // der group_leader-Startzeit matcht sie am `sched_process_exec` auch beim
    // Exec aus einem Nicht-Hauptthread (K5).
    let Some(start_boottime) = group_leader_start_boottime() else {
        return 0;
    };
    let key = args_key_current();
    let entry = ArgsEntry {
        start_boottime,
        enter_boot_ns: unsafe { aya_ebpf::helpers::bpf_ktime_get_boot_ns() },
        argc,
        argc_min,
        _pad: [0; 3],
    };
    let _ = ARGS.insert(&key, &entry, 0);
    0
}

/// K6-Beleg (ARGS-Keying): Der ARGS-Schlüssel ist die Kombination aus TGID und
/// TID des aufrufenden Tasks. `bpf_get_current_pid_tgid()` liefert beide IDs
/// des *aktuell laufenden* Tasks – beim `sys_enter_execve`-Tracepoint kann das
/// ein beliebiger Thread des Prozesses sein. Da `sched_process_exec` den
/// ausführenden Thread als `old_pid` (TID) meldet und die TGID aus `task_struct`
/// liest, greift die `ARGS.get`-Seite unter demselben Schlüssel – argc bleibt
/// auch bei Nicht-Hauptthread-Execs korrekt, und gleichzeitige Execs
/// verschiedener Threads überschreiben einander nicht.
#[inline]
fn args_key_current() -> u64 {
    aya_ebpf::helpers::bpf_get_current_pid_tgid()
}

/// Schlüssel für die ARGS-Map (nur diese Funktionen – single source of truth
/// für das Keying; beide Nutzungsstellen verwenden sie).
#[inline]
fn args_key_for_exec(pid: u32, old_pid: u32) -> u64 {
    args_key(pid, old_pid)
}

// ── sched_process_exec ─────────────────────────────────────────────────

#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    count_seen();
    match try_sched_process_exec(ctx) {
        Ok(()) => 0,
        // Jeder verworfene Exec ist ein verlorenes Ereignis: Der Sensor kann
        // ihn weder als `exec` noch als `lost` unterscheiden, also zählt der
        // Fehlerpfad in DROPS. Das erhält die Verlustbilanz.
        Err(_) => {
            count_drop();
            0
        }
    }
}

fn try_sched_process_exec(ctx: TracePointContext) -> Result<(), i32> {
    // Offsets aus der BTF (vom Daemon gesetzt). Fehlen sie oder ist die Map
    // nicht als vollständig markiert, scheitert das Ereignis und wird als
    // Verlust gezählt (fail-closed auf Daemon-Seite beim Laden).
    offsets_ready()?;
    let off_real_parent = get_offset(OFF_REAL_PARENT)?;
    let off_tgid = get_offset(OFF_TGID)?;
    let off_cred = get_offset(OFF_CRED)?;
    let off_uid = get_offset(OFF_UID)?;
    let off_euid = get_offset(OFF_EUID)?;
    let off_start_boot_time = get_offset(OFF_START_BOOT_TIME)?;
    let off_group_leader = get_offset(OFF_GROUP_LEADER)?;

    // Tracepoint-Felder (sched_process_exec): __data_loc_filename @8,
    // pid @12, old_pid @16.
    let data_loc: u32 = unsafe { ctx.read_at(8)? };
    let old_pid: u32 = unsafe { ctx.read_at(16)? };

    let task = nonzero_addr(unsafe { bpf_get_current_task() })?;

    // Identität aus task_struct (manuelles CO-RE).
    let pid: u32 = read_u32_at(task, off_tgid)?;
    let real_parent: u64 = nonzero_addr(read_u64_at(task, off_real_parent)?)?;
    let ppid: u32 = read_u32_at(real_parent, off_tgid)?;
    let cred: u64 = nonzero_addr(read_u64_at(task, off_cred)?)?;
    let uid: u32 = read_u32_at(cred, off_uid)?;
    let euid: u32 = read_u32_at(cred, off_euid)?;
    // Identität = start_boottime des group_leader (nach `de_thread` ist der
    // ausführende Task selbst der Leader, vorher der alte Leader); identisch zu
    // der in `ARGS` gespeicherten und zu dem, was `/proc/<pid>/stat` liefert.
    let group_leader: u64 = nonzero_addr(read_u64_at(task, off_group_leader)?)?;
    let start_boot_time: u64 = read_u64_at(group_leader, off_start_boot_time)?;

    // Datei-Identität zum Ereigniszeitpunkt (ino + size). Fehlt sie, trägt
    // das Ereignis `has_exe_ident = 0` und der Daemon attributiert keinen
    // Hash (statt einen ggf. überholten zu liefern).
    let (exe_ino, exe_size, has_exe_ident) = match exe_file_identity() {
        Some((ino, size)) => (ino, size, 1),
        None => (0, 0, 0),
    };

    let comm: [u8; TASK_COMM_LEN] = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);

    // argc aus der ARGS-Map (Key = TGID+TID des aufrufenden Tasks,
    // gesetzt von `count_and_store` unter demselben Schlüssel – K6-Beleg, siehe
    // `args_key_current`/`args_key_for_exec`). `old_pid` ist dagegen die TID des
    // ausführenden Tasks; bei exec durch einen Nicht-Hauptthread wiche der Key
    // sonst ab (argc fälschlich null). `resolve_argc` prüft den Eintrag
    // zusätzlich gegen die Prozess-Identität (`start_boot_time` des
    // group_leader – dieselbe Identität, die `count_and_store` speichert) und
    // seine Frische: ein veralteter Eintrag eines fehlgeschlagenen execve nach
    // PID-Wiederverwendung durch einen Start ohne `sys_enter` (z. B. modprobe)
    // wird verworfen und argc als unbekannt behandelt – die Linie „Mittelweg
    // A–B“ für K10. Eintrag danach immer löschen. `has_argc` unterscheidet
    // „argc=0“ von „unbekannt“.
    let key = args_key_for_exec(pid, old_pid);
    // SAFETY: ktime-get-Boot-Helper ohne Nebeneffekte/Zeigerargumente.
    let now_boot_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_boot_ns() };
    let (argc, argc_min, has_argc) =
        resolve_argc(unsafe { ARGS.get(&key) }, start_boot_time, now_boot_ns);
    let _ = ARGS.remove(&key);

    // Dateiname aus __data_loc, direkt in das reservierte Ereignis schreiben
    // (kein großes Struct auf dem BPF-Stack). `__data_loc` kodiert
    // `(len << 16) | off`: untere 16 Bit = Offset, obere 16 Bit = Länge.
    let data_off = (data_loc & 0xffff) as usize;
    let data_len = ((data_loc >> 16) & 0xffff) as usize;
    let base = ctx.as_ptr() as u64;

    let Some(mut entry) = EVENTS.reserve::<ExecEvent>(0) else {
        count_drop();
        return Err(-1);
    };
    {
        let event = entry.write(ExecEvent {
            pid,
            ppid,
            uid,
            euid,
            tid: old_pid,
            argc,
            argc_min,
            has_argc,
            path_trunc: 0,
            _pad0: [0; 5],
            start_boot_time,
            // Kernel-Bootzeit (CLOCK_BOOTTIME) zum Ereigniszeitpunkt –
            // dieselbe Basis wie `start_boot_time`, daher direkt vergleichbar.
            ts_boot: now_boot_ns,
            comm,
            filename_len: 0,
            filename: [0u8; MAX_FILENAME],
            _pad1: [0; 6],
            exe_ino,
            exe_size,
            has_exe_ident,
            _pad2: [0; 7],
        });
        if data_len > 0 {
            // Dateiname über die Per-CPU-Zwischenablage `PATH_BUF` kopieren
            // (kein großer Stack-Puffer, erreichbare Länge = PATH_BUF_SIZE).
            let read_len = data_len.min(PATH_BUF_SIZE);
            let per = match PATH_BUF.get_ptr_mut(0) {
                Some(p) => p,
                None => {
                    entry.discard(0);
                    return Err(-1);
                }
            };
            // Kein `?`: Auf einem Fehlerpfad müsste das reservierte Ringbuf-Ereignis
            // sonst verworfen werden, ohne dass `submit`/`discard` die vom Verifier
            // geforderte Referenz freigibt ("Unreleased reference").
            let read = {
                // SAFETY: `per` ist ein gültiger, nicht-null Per-CPU-Map-Wert
                // (get_ptr_mut geprüft); read_len ≤ PATH_BUF_SIZE.
                let dst = unsafe { core::slice::from_raw_parts_mut(per as *mut u8, read_len) };
                unsafe { bpf_probe_read_kernel_buf((base + data_off as u64) as *const u8, dst) }
            };
            match read {
                Ok(()) => {
                    let copy_len = read_len.min(MAX_FILENAME);
                    event.path_trunc = if read_len > copy_len { 1 } else { 0 };
                    unsafe {
                        // SAFETY: `per` ist ein gültiger, nicht-null Per-CPU-Map-Wert
                        // (get_ptr_mut geprüft); read_len ≤ PATH_BUF_SIZE.
                        core::ptr::copy_nonoverlapping(
                            (*per).as_ptr(),
                            event.filename.as_mut_ptr(),
                            copy_len,
                        );
                    }
                    event.filename_len = read_len as u16; // erkannte (evtl. gekürzte) Länge
                }
                Err(_) => {
                    entry.discard(0);
                    return Err(-1);
                }
            }
        }
    }
    entry.submit(0);
    Ok(())
}

// ── Panic / Lizenz ─────────────────────────────────────────────────────

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
