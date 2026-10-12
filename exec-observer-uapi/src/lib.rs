//! Gemeinsames Userspace-/Kernel-ABI des Exec-Beobachters.
//!
//! Dieses `no_std`-Crate ist die einzige Quelle für das `#[repr(C)]`-Layout des
//! [`ExecEvent`] und die Indizes der `OFFSETS`-Map. Da beide Seiten (eBPF-Sensor
//! und Daemon) daraus lesen, kann das ABI nicht mehr auseinanderdriften. Das
//! Layout ist ein bytemuck-`Pod`: Der Daemon deserialisiert Ringpuffer-Bytes
//! via `bytemuck::try_from_bytes` ohne manuelle Feld-Offsets.
#![no_std]

use bytemuck::{Pod, Zeroable};

/// Länge des `comm`-Felds (entspricht `TASK_COMM_LEN` im Kernel).
pub const TASK_COMM_LEN: usize = 16;

/// Maximale Länge des Dateinamens im Ereignis (Event-Feld `filename`).
/// Längere Pfade werden auf diese Länge gekürzt; `path_trunc` markiert das.
///
/// Die erreichbare Gesamtlänge ist `PATH_BUF_SIZE` (Per-CPU-Zwischenablage im
/// eBPF-Sensor); das Event-Feld bleibt bewusst kompakt, um Ringpuffer-Platz zu
/// sparen (der kanonische Pfad steht ohnehin über `/proc/<pid>/exe` bereit).
pub const MAX_FILENAME: usize = 256;

/// Erreichbare Pfadlänge im eBPF-Sensor: Per-CPU-Zwischenablage (PATH_BUF),
/// so groß wie `PATH_MAX` im Kernel. Pfade bis hierhin werden erkannt und
/// gezählt; ins Event-Feld passen davon nur `MAX_FILENAME` Bytes.
pub const PATH_BUF_SIZE: usize = 4096;

/// Offset-Indizes in der `OFFSETS`-Map (vom Daemon gesetzt).
pub const OFF_REAL_PARENT: u32 = 0;
pub const OFF_TGID: u32 = 1;
pub const OFF_CRED: u32 = 2;
pub const OFF_UID: u32 = 3;
pub const OFF_EUID: u32 = 4;
pub const OFF_START_BOOT_TIME: u32 = 5;
/// `task_struct.group_leader` (Zeiger). Anker der ARGS-Identität: bei
/// `execve` aus einem Nicht-Hauptthread übernimmt der ausführende Thread die
/// Identität des Thread-Group-Leaders (`de_thread`), inklusive dessen
/// `start_boottime`. Deshalb wird an beiden Enden die `start_boottime` des
/// `group_leader` verglichen, nicht die des aktuellen Threads.
pub const OFF_GROUP_LEADER: u32 = 6;
/// `task_struct.mm` (Zeiger auf `mm_struct`). Ausgangspunkt der
/// Dateidentität zum Ereigniszeitpunkt: `mm->exe_file` zeigt nach dem
/// erfolgreichen Exec bereits auf die neue Datei.
pub const OFF_MM: u32 = 7;
/// `mm_struct.exe_file` (Zeiger auf `struct file`, `__rcu`).
pub const OFF_EXE_FILE: u32 = 8;
/// `file.f_inode` (Zeiger auf `struct inode`).
pub const OFF_F_INODE: u32 = 9;
/// `inode.i_ino` (`u64`): Inode-Nummer der ausgeführten Datei.
pub const OFF_INO: u32 = 10;
/// `inode.i_size` (`loff_t`, 8 Byte): Dateigröße der ausgeführten Datei.
/// Zusammen mit `i_ino` die Ereignis-Identität; `s_dev` ist auf btrfs nicht
/// mit `st_dev` vergleichbar und wird bewusst nicht verwendet.
pub const OFF_I_SIZE: u32 = 11;

/// Anzahl der Einträge in der `OFFSETS`-Map (vom Daemon gesetzt).
pub const OFFSETS_LEN: u32 = 12;

/// Plausibilitätsgrenze für BTF-Offsets im eBPF-Sensor. `task_struct` ist auf
/// unterstützten Kerneln deutlich kleiner; größere Werte deuten auf eine
/// falsche BTF-Auflösung oder Map-Befüllung hin.
pub const MAX_TASK_OFFSET: u64 = 0x1_0000;

/// Gültigkeitsdauer eines `ARGS`-Eintrags ab `sys_enter` in Nanosekunden.
/// Normale `execve`-Pfade erreichen `sched_process_exec` unmittelbar danach;
/// ältere Einträge werden als unbekannt behandelt statt als gültig.
pub const ARGS_ENTRY_TTL_NS: u64 = 5_000_000_000;

/// Packt Prozess- und Thread-ID in den `ARGS`-Schlüssel. Das Layout entspricht
/// `bpf_get_current_pid_tgid()`: hohe 32 Bit TGID, niedrige 32 Bit TID.
#[inline]
pub const fn args_key(tgid: u32, tid: u32) -> u64 {
    ((tgid as u64) << 32) | (tid as u64)
}

/// Zerlegt einen mit [`args_key`] erzeugten Schlüssel.
#[inline]
pub const fn args_key_tgid(key: u64) -> u32 {
    (key >> 32) as u32
}

/// Zerlegt einen mit [`args_key`] erzeugten Schlüssel.
#[inline]
pub const fn args_key_tid(key: u64) -> u32 {
    key as u32
}

/// Spiegel der eBPF-Seite; Layout-mäßig ein bytemuck-`Pod` (`#[repr(C)]`).
///
/// `start_boot_time` wird gegen das `starttime`-Feld aus `/proc/<pid>/stat`
/// abgetragen, das ebenfalls auf `CLOCK_BOOTTIME` basiert (PID-Reuse-Schutz);
/// `ts_boot` ist die Kernel-Bootzeit zum Ereigniszeitpunkt
/// (`bpf_ktime_get_boot_ns`). Mit beiden Feldern auf derselben Zeitbasis
/// (`CLOCK_BOOTTIME`) ist `ts` im JSON direkt mit der Prozess-Startzeit
/// vergleichbar (kein Mischbasis-Fehler mehr).
/// `uid`/`euid` sind die reale und die effektive User-ID aus `struct cred`.
/// `filename_len` ist die erkannte Kernel-Pfadlänge (bis `PATH_BUF_SIZE`),
/// `filename` deren auf `MAX_FILENAME` gekürzter Inhalt; `path_trunc != 0`
/// zeigt an, dass gekürzt wurde.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub euid: u32,
    pub tid: u32,
    pub argc: u32,
    pub argc_min: u8,
    pub has_argc: u8,
    pub path_trunc: u8,
    /// Explizite Füllbytes nach den drei `u8`-Feldern. Der eBPF-Sensor füllt sie
    /// mit Null; so gelangen keine uninitialisierten Kernel-Stack-Bytes in den
    /// Ringpuffer. Das Layout bleibt gegenüber der impliziten Auffüllung
    /// unverändert.
    pub _pad0: [u8; 5],
    pub start_boot_time: u64,
    pub ts_boot: u64,
    pub comm: [u8; TASK_COMM_LEN],
    pub filename_len: u16,
    pub filename: [u8; MAX_FILENAME],
    /// Explizite Füllbytes am Strukturende für stabiles 8-Byte-Alignment.
    pub _pad1: [u8; 6],
    /// Inode-Nummer der zum Ereigniszeitpunkt ausgeführten Datei
    /// (`mm->exe_file->f_inode->i_ino`). Vergleichsanker gegen `fstat` des
    /// geöffneten `/proc/<pid>/exe`-FDs: weicht sie ab, wurde zwischen
    /// Sensorereignis und Daemon-Verarbeitung erneut exec't (`superseded`).
    pub exe_ino: u64,
    /// Dateigröße derselben Datei (`inode.i_size`, als `u64`-Bitmuster).
    pub exe_size: u64,
    /// `!= 0`, wenn `exe_ino`/`exe_size` gültig gelesen wurden. Fehlt die
    /// Identität, darf der Daemon keinen Hash attributieren (`unreadable`).
    pub has_exe_ident: u8,
    /// Explizite Füllbytes hinter `has_exe_ident`.
    pub _pad2: [u8; 7],
}

// SAFETY: Alle Felder sind `Copy`-Primitive bzw. -Arrays ohne Enum/Zeiger.
// Der `#[repr(C)]`-Typ hat implizite Padding-Bytes; diese werden aber nie
// gelesen (der eBPF-Sensor befüllt das Struct-Literal, der Daemon nur die
// benannten Felder). Ein byteweiser View (`try_from_bytes`) ist daher
// wohldefiniert.
unsafe impl Zeroable for ExecEvent {}
unsafe impl Pod for ExecEvent {}

/// Wert der `ARGS`-Map im eBPF-Sensor (Key = Prozess-PID/TGID).
///
/// Neben dem gezählten `argv`-Ergebnis trägt der Eintrag die `start_boottime`
/// des **`group_leader`** als Identitäts-Cookie. Diese bleibt über `exec`
/// stabil und unterscheidet jede Prozess-Instanz: Ein nach fehlgeschlagenem
/// `execve` stehen gebliebener Eintrag gehört dann zu einer *anderen*
/// Prozess-Instanz, wenn die PID wiederverwendet wird (z. B. `modprobe` ohne
/// `sys_enter`). Solche Einträge erkennt [`resolve_argc`] und liefert argc als
/// unbekannt (`null`) statt eines falschen Zählerstands.
///
/// Warum `group_leader` und nicht der ausführende Thread: Beim `execve` aus
/// einem Nicht-Hauptthread macht `de_thread` (in `begin_new_exec`) den
/// Ausführenden zum neuen Leader und setzt
/// `tsk->start_boottime = leader->start_boottime`. Der
/// `sched_process_exec`-Tracepoint feuert **nach** diesem Schritt. Läse man am
/// `sys_enter` die eigene `start_boottime` des Threads und am Tracepoint die
/// (nun leader-gewählte) des Tasks, mismatche das Cookie → argc ginge verloren
/// (K5). Die `start_boottime` des `group_leader` ist an beiden Enden dieselbe
/// (vor `de_thread`: alter Leader; danach: der Ausführende selbst).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ArgsEntry {
    pub start_boottime: u64,
    /// Kernel-Bootzeit des `sys_enter`-Eintritts. Begrenzt zusammen mit der
    /// Identität, wie lange ein gespeicherter Zählerstand gültig bleibt.
    pub enter_boot_ns: u64,
    pub argc: u32,
    pub argc_min: u8,
    /// Explizite Füllbytes; der Sensor füllt sie mit Null.
    pub _pad: [u8; 3],
}

// SAFETY: wie `ExecEvent` – nur `Copy`-Primitive, Padding wird nie gelesen.
unsafe impl Zeroable for ArgsEntry {}
unsafe impl Pod for ArgsEntry {}

/// Gültigkeitsgeprüfte Auswertung eines `ARGS`-Eintrags beim
/// `sched_process_exec` (Mitelweg A–B für Kriterium 10).
///
/// Liefert `(argc, argc_min, has_argc)`:
/// - gespeicherte `start_boottime` == Identität des `group_leader` →
///   Eintrag gültig, gezähltes `argc` wird übernommen (`has_argc = 1`);
/// - sonst (kein Eintrag, oder veralteter Eintrag nach PID-Wiederverwendung)
///   → argc unbekannt (`has_argc = 0`). Nie ein falsches `argc`.
///
/// Beide Seiten (Speichern am `sys_enter`, Auswerten am `sched_process_exec`)
/// verwenden übereinstimmend die `start_boottime` des `group_leader`; siehe
/// [`ArgsEntry`] zur Begründung (`de_thread`). Zusätzlich muss der Eintrag
/// frisch sein: `now_boot_ns - enter_boot_ns <= ARGS_ENTRY_TTL_NS`.
///
/// Reine Funktion ohne BPF-Nebenwirkungen – unit-testbar im Host.
#[inline]
pub const fn resolve_argc(
    saved: Option<&ArgsEntry>,
    group_leader_start_boottime: u64,
    now_boot_ns: u64,
) -> (u32, u8, u8) {
    match saved {
        Some(e)
            if e.start_boottime == group_leader_start_boottime
                && now_boot_ns.saturating_sub(e.enter_boot_ns) <= ARGS_ENTRY_TTL_NS =>
        {
            (e.argc, e.argc_min, 1)
        }
        _ => (0, 0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_event_size_pins_the_ring_capacity() {
        // Der eBPF-Sensor legt den Ringpuffer mit 256 KiB an (EVENTS). Die
        // Anzahl der Plätze – und damit die Schreibgrenze für den
        // Überlauf-Test in tests/cap-matrix.sh (Fall d) – hängt an der
        // Eventgröße. Hier festgenagelt, damit die Zahl im Test nicht
        // unmerklich driftet (aktuell 352 B → 744 Plätze:
        // exe_ino/exe_size/has_exe_ident für die Ereignis-Identität).
        let size = core::mem::size_of::<ExecEvent>();
        assert_eq!(
            size, 352,
            "ExecEvent-Größe geändert: Ringkapazität neu rechnen"
        );
        assert_eq!(256 * 1024 / size, 744);
    }

    fn entry(boot: u64, entered: u64, argc: u32, argc_min: u8) -> ArgsEntry {
        ArgsEntry {
            start_boottime: boot,
            enter_boot_ns: entered,
            argc,
            argc_min,
            _pad: [0; 3],
        }
    }

    #[test]
    fn args_key_combines_tgid_and_tid_without_collision() {
        assert_eq!(args_key(7, 11), ((7u64) << 32) | 11);
        assert_eq!(args_key_tgid(args_key(7, 11)), 7);
        assert_eq!(args_key_tid(args_key(7, 11)), 11);
        assert_ne!(args_key(7, 11), args_key(7, 12));
        assert_ne!(args_key(7, 11), args_key(8, 11));
    }

    #[test]
    fn matching_group_leader_identity_returns_saved_argc() {
        // Gleiche group_leader-start_boottime an sys_enter (gespeichert) und
        // sched_process_exec (hier übergeben) → argc gültig. Genau der Fall
        // K5: execve aus Nicht-Hauptthread; beide Seiten sind der Leader.
        let e = entry(111, 1_000, 1024, 1);
        assert_eq!(resolve_argc(Some(&e), 111, 1_000), (1024, 1, 1));
    }

    #[test]
    fn stale_entry_after_pid_reuse_is_unknown() {
        // Eintrag eines fehlgeschlagenen execve; PID inzwischen für einen
        // anderen Prozess (ohne sys_enter, z. B. modprobe) vergeben.
        let e = entry(111, 1_000, 5, 0);
        assert_eq!(resolve_argc(Some(&e), 999_999, 1_000), (0, 0, 0));
    }

    #[test]
    fn time_limited_entry_is_unknown_after_ttl() {
        let e = entry(111, 1_000, 5, 0);
        assert_eq!(
            resolve_argc(Some(&e), 111, 1_000 + ARGS_ENTRY_TTL_NS + 1),
            (0, 0, 0)
        );
    }

    #[test]
    fn already_matching_boottime_with_null_entry_fields() {
        // Undefinierte Füllwerte sind irrelevant, nur die Identität zählt.
        let e = entry(7, 1_000, 42, 0);
        assert_eq!(resolve_argc(Some(&e), 7, 1_000), (42, 0, 1));
    }

    #[test]
    fn missing_entry_is_unknown() {
        assert_eq!(resolve_argc(None, 111, 1_000), (0, 0, 0));
    }

    #[test]
    fn zero_boottime_is_a_valid_identity() {
        // start_boottime=0 existiert real nicht (kein Prozess startet bei
        // Boot-Zeit 0), aber konsistent: identische Werte → gültig, sobald
        // der Sensor denselben Wert speichert und liest.
        let e = entry(0, 1_000, 2, 0);
        assert_eq!(resolve_argc(Some(&e), 0, 1_000), (2, 0, 1));
    }
}
