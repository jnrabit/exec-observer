//! Reine, host-testbare Ereignis→Zeile-Formatierung (ohne BPF, ohne Root).
//!
//! Bildet ein [`Event`] auf genau eine JSON-Zeile ab (ohne abschließendes `\n`).
//! Feste Feldreihenfolge, keine Leerzeichen, geschlossenes Vokabular für `ev`,
//! `hash_state` und `flags`. Die `seq` wird vom Aufrufer übergeben (der Daemon
//! vergibt sie lückenlos ab 0 pro Lauf).

use std::borrow::Cow;

/// Formatversion des Stroms (Feld `v`). Wird bei jeder Schemaänderung erhöht.
pub const FORMAT_VERSION: u32 = 2;

/// Ereignis-Vokabular (`ev`) — geschlossen, keine Freitexte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ev {
    Start,
    Stop,
    Exec,
    Lost,
}

impl Ev {
    pub fn name(self) -> &'static str {
        match self {
            Ev::Start => "start",
            Ev::Stop => "stop",
            Ev::Exec => "exec",
            Ev::Lost => "lost",
        }
    }
}

/// Hash-Zustand (`hash_state`) — geschlossen. Ein fehlender Hash ist nie
/// stillschweigend leer: bei `Gone`/`Unreadable`/`Reused`/`Superseded` ist
/// `sha256` `None` (→ `null`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashState {
    /// Hash erfolgreich aus `/proc/<pid>/exe` gelesen.
    Ok,
    /// Prozess beendet, bevor die Datei gelesen werden konnte.
    Gone,
    /// Datei nicht lesbar (Rechte/anderer Fehler).
    Unreadable,
    /// Prozess läuft nach dem Hashen weiter, aber mit anderer Identität
    /// (erneutes `exec` desselben PIDs). Der gelesene Hash gehört zur vorherigen
    /// Binary und wird verworfen.
    Reused,
    /// Gleicher Prozess (gleiche Startzeit), aber zwischen Sensorereignis und
    /// Daemon-Verarbeitung wurde erneut exec't: Der geöffnete FD gehört zu
    /// einer späteren Exec-Stufe derselben PID. Der gelesene Hash gehört
    /// nicht zur Ereigniszeile und wird verworfen (`sha256` ist `null`).
    Superseded,
}

impl HashState {
    pub fn name(self) -> &'static str {
        match self {
            HashState::Ok => "ok",
            HashState::Gone => "gone",
            HashState::Unreadable => "unreadable",
            HashState::Reused => "reused",
            HashState::Superseded => "superseded",
        }
    }
}

/// Flags (`flags`) — geschlossenes Vokabular, kanonische Reihenfolge:
/// `fileless`, `fd_exec`, `deleted`, `argc_min`, `lossy`, `path_trunc`,
/// `cached`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flag {
    /// Ausgeführtes Abbild stammt aus `/memfd:` (anonymes Speicherobjekt).
    Fileless,
    /// Exec über einen übergebenen Deskriptor: der vom Kernel gemeldete Pfad
    /// beginnt mit `/dev/fd/` oder `/proc/self/fd/` (ermittelt aus dem
    /// **Ereignis**, nicht aus `/proc`). Beweist weder memfd noch gelöscht —
    /// deshalb eigenes Flag statt Vortäuschung einer Datei-Eigenschaft.
    FdExec,
    /// Ausgeführtes Abbild wurde auf der Platte ersetzt (`(deleted)`), ist
    /// aber NICHT fileless.
    Deleted,
    /// `argc` ist eine Untergrenze (Zählstand am Limit erreicht).
    ArgcMin,
    /// `comm`/`path` enthielten ungültiges UTF-8; ungültige Bytes wurden durch
    /// U+FFFD ersetzt. Wird von [`format_line`] automatisch gesetzt, nie vom
    /// Aufrufer.
    Lossy,
    /// Der Pfad wurde gekürzt (erkannte Kernel-Länge > `MAX_FILENAME` im
    /// Event-Feld `path`).
    PathTrunc,
    /// `sha256` stammt aus dem Datei-Hash-Cache (dev+ino+size+mtime+ctime
    /// unverändert), nicht aus erneutem Lesen der Datei.
    Cached,
}

impl Flag {
    pub fn name(self) -> &'static str {
        match self {
            Flag::Fileless => "fileless",
            Flag::FdExec => "fd_exec",
            Flag::Deleted => "deleted",
            Flag::ArgcMin => "argc_min",
            Flag::Lossy => "lossy",
            Flag::PathTrunc => "path_trunc",
            Flag::Cached => "cached",
        }
    }
}

/// Ein Beobachtungs-Ereignis mit allen typ-spezifischen Feldern.
///
/// `ts` ist die Kernel-Bootzeit (`CLOCK_BOOTTIME`) in Nanosekunden: bei
/// `Exec`-Ereignissen der Sensor-Zeitstempel `ts_boot` (Kernel-seitig), bei
/// `Start`/`Stop`/`Lost` die Daemon-Uhr. `wall` ist die Unix-Kalenderzeit in
/// Nanosekunden (Korrelation mit journalctl/u-tools), abgeleitet aus `ts` und
/// dem beim Start gemessenen Offset `realtime − boottime`.
///
/// `ts` und `seq` sind **nicht** zueinander monoton: `seq` vergibt der Daemon
/// lückenlos in Verarbeitungsreihenfolge, während `ts` die (potenziell
/// verfrühte) Kernel-Ereigniszeit trägt. Konsumenten ordnen nach `seq` und
/// behandeln `ts` als Attribut. `seq` wird separat an [`format_line`] übergeben.
/// `comm`/`path` sind rohe Kernel-Bytes (können ungültiges UTF-8 enthalten);
/// `mid`/`kernel` sind ASCII (aus `/proc`, s. Aufgaben).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Start {
        ts: u64,
        wall: u64,
        mid: String,
        kernel: String,
    },
    Stop {
        ts: u64,
        wall: u64,
        mid: String,
    },
    Exec {
        ts: u64,
        wall: u64,
        pid: u32,
        ppid: u32,
        uid: u32,
        euid: u32,
        comm: Vec<u8>,
        path: Vec<u8>,
        /// Anzahl der Argumente. `None` → `null` (kein Map-Eintrag / Lesefehler).
        argc: Option<u64>,
        /// 64 Hex-Zeichen. `None` bei `hash_state != ok` → `null`.
        sha256: Option<String>,
        hash_state: HashState,
        flags: Vec<Flag>,
    },
    Lost {
        ts: u64,
        wall: u64,
        count: u64,
    },
}

impl Event {
    pub fn ts(&self) -> u64 {
        match self {
            Event::Start { ts, .. }
            | Event::Stop { ts, .. }
            | Event::Exec { ts, .. }
            | Event::Lost { ts, .. } => *ts,
        }
    }

    pub fn wall(&self) -> u64 {
        match self {
            Event::Start { wall, .. }
            | Event::Stop { wall, .. }
            | Event::Exec { wall, .. }
            | Event::Lost { wall, .. } => *wall,
        }
    }

    pub fn ev(&self) -> Ev {
        match self {
            Event::Start { .. } => Ev::Start,
            Event::Stop { .. } => Ev::Stop,
            Event::Exec { .. } => Ev::Exec,
            Event::Lost { .. } => Ev::Lost,
        }
    }
}

/// Prüft, ob `s` genau 64 Hex-Zeichen ([0-9a-fA-F]) sind.
pub fn is_64_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Dokumentierte Invariante für Exec-Ereignisse: `hash_state == Ok` genau dann,
/// wenn `sha256` ein 64-Hex-String ist; `Gone`/`Unreadable`/`Reused`/
/// `Superseded` nur bei `sha256 == None`.
pub fn hash_state_sha256_consistent(hash_state: HashState, sha256: Option<&str>) -> bool {
    match hash_state {
        HashState::Ok => sha256.map(is_64_hex).unwrap_or(false),
        HashState::Gone | HashState::Unreadable | HashState::Reused | HashState::Superseded => {
            sha256.is_none()
        }
    }
}

/// Normalisiert inkonsistente Exec-Nutzdaten vor der Serialisierung. Ein
/// ungültiger Hash-Zustand wird als `Unreadable` ohne Hash ausgegeben; aus dem
/// geöffneten FD abgeleitete Flags werden dabei entfernt. Ereignisbezogene
/// Flags bleiben erhalten.
fn normalize_exec_hash<'a>(
    hash_state: HashState,
    sha256: Option<&'a String>,
    flags: &[Flag],
) -> (HashState, Option<&'a String>, Vec<Flag>) {
    if hash_state_sha256_consistent(hash_state, sha256.map(String::as_str)) {
        let normalized_flags = if matches!(
            hash_state,
            HashState::Gone | HashState::Unreadable | HashState::Reused | HashState::Superseded
        ) {
            flags
                .iter()
                .copied()
                .filter(|flag| !matches!(flag, Flag::Fileless | Flag::Deleted | Flag::Cached))
                .collect()
        } else {
            flags.to_vec()
        };
        return (hash_state, sha256, normalized_flags);
    }
    let normalized_flags = flags
        .iter()
        .copied()
        .filter(|flag| !matches!(flag, Flag::Fileless | Flag::Deleted | Flag::Cached))
        .collect();
    (HashState::Unreadable, None, normalized_flags)
}

/// Hängt den gemeinsamen Zeilenkopf `{"v":<v>,"seq":<seq>,"ts":<ts>,"wall":<wall>,"ev":"<ev>"` an.
/// Beschließt den Kopf ohne `,`, der Caller hängt die typ-spezifischen Felder an.
fn push_header(out: &mut String, seq: u64, ts: u64, wall: u64, ev: &str) {
    out.push_str("{\"v\":");
    out.push_str(&FORMAT_VERSION.to_string());
    out.push_str(",\"seq\":");
    out.push_str(&seq.to_string());
    out.push_str(",\"ts\":");
    out.push_str(&ts.to_string());
    out.push_str(",\"wall\":");
    out.push_str(&wall.to_string());
    out.push_str(",\"ev\":\"");
    out.push_str(ev);
    out.push('"');
}

/// Serialisiert ein Ereignis als eine JSON-Zeile (ohne `\n`).
///
/// Feste Feldreihenfolge, kompakte Form (keine Leerzeichen). `comm`/`path`
/// werden lossy zu UTF-8 konvertiert; bei ungültigen Bytes wird `lossy` gesetzt.
/// Strings werden JSON-escaped. `seq` und `v` werden hier eingefügt.
pub fn format_line(seq: u64, event: &Event) -> String {
    let mut out = String::with_capacity(256);
    match event {
        Event::Start {
            ts,
            wall,
            mid,
            kernel,
        } => {
            push_header(&mut out, seq, *ts, *wall, "start");
            out.push_str(",\"mid\":");
            push_json_string(&mut out, mid);
            out.push_str(",\"kernel\":");
            push_json_string(&mut out, kernel);
            out.push('}');
        }
        Event::Stop { ts, wall, mid } => {
            push_header(&mut out, seq, *ts, *wall, "stop");
            out.push_str(",\"mid\":");
            push_json_string(&mut out, mid);
            out.push('}');
        }
        Event::Exec {
            ts,
            wall,
            pid,
            ppid,
            uid,
            euid,
            comm,
            path,
            argc,
            sha256,
            hash_state,
            flags,
        } => {
            let (comm_str, comm_lossy) = lossy_to_string(comm);
            let (path_str, path_lossy) = lossy_to_string(path);
            let lossy = comm_lossy || path_lossy;
            let (hash_state, sha256, flags) =
                normalize_exec_hash(*hash_state, sha256.as_ref(), flags);

            push_header(&mut out, seq, *ts, *wall, "exec");
            out.push_str(",\"pid\":");
            out.push_str(&pid.to_string());
            out.push_str(",\"ppid\":");
            out.push_str(&ppid.to_string());
            out.push_str(",\"uid\":");
            out.push_str(&uid.to_string());
            out.push_str(",\"euid\":");
            out.push_str(&euid.to_string());
            out.push_str(",\"comm\":");
            push_json_string(&mut out, &comm_str);
            out.push_str(",\"path\":");
            push_json_string(&mut out, &path_str);
            out.push_str(",\"argc\":");
            match argc {
                Some(n) => out.push_str(&n.to_string()),
                None => out.push_str("null"),
            }
            out.push_str(",\"sha256\":");
            match sha256 {
                Some(h) => push_json_string(&mut out, h),
                None => out.push_str("null"),
            }
            out.push_str(",\"hash_state\":");
            push_json_string(&mut out, hash_state.name());
            out.push_str(",\"flags\":");
            push_flags(&mut out, &flags, lossy);
            out.push('}');
        }
        Event::Lost { ts, wall, count } => {
            push_header(&mut out, seq, *ts, *wall, "lost");
            out.push_str(",\"count\":");
            out.push_str(&count.to_string());
            out.push('}');
        }
    }
    out
}

/// Hängt `flags` als JSON-Array an, in kanonischer Reihenfolge (geschlossenes
/// Vokabular): `fileless`, `deleted`, `argc_min`, `lossy` (automatisch bei
/// ungültigem UTF-8), `path_trunc`, `cached`. Die Reihenfolge ist unabhängig
/// von der Einfügereihenfolge des Aufrufers und folgt der kanonischen Ordnung
/// `fileless`, `fd_exec`, `deleted`, `argc_min`, `lossy`, `path_trunc`,
/// `cached`.
fn push_flags(out: &mut String, flags: &[Flag], lossy: bool) {
    const ORDER: [Flag; 7] = [
        Flag::Fileless,
        // fd_exec direkt nach fileless: beides beschreibt, WAS ausgeführt
        // wurde (anonymes Objekt, Deskriptor-Exec), bevor über den Zustand
        // der Datei entschieden wird.
        Flag::FdExec,
        Flag::Deleted,
        Flag::ArgcMin,
        Flag::Lossy,
        Flag::PathTrunc,
        Flag::Cached,
    ];
    let names: Vec<String> = ORDER
        .iter()
        .filter(|f| (**f == Flag::Lossy && lossy) || flags.contains(f))
        .map(|f| format!("\"{}\"", f.name()))
        .collect();
    out.push('[');
    out.push_str(&names.join(","));
    out.push(']');
}

/// Konvertiert rohe Bytes lossy zu UTF-8 und meldet, ob dabei Bytes ersetzt
/// wurden (`true` = ungültige Bytes durch U+FFFD ersetzt).
fn lossy_to_string(bytes: &[u8]) -> (String, bool) {
    match String::from_utf8_lossy(bytes) {
        Cow::Borrowed(s) => (s.to_string(), false),
        Cow::Owned(s) => (s, true),
    }
}

/// Hängt `s` als JSON-String (inkl. Anführungszeichen, escaped) an.
fn push_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\u");
                out.push_str(&format!("{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec() -> Event {
        Event::Exec {
            ts: 123456789,
            wall: 999,
            pid: 4711,
            ppid: 1,
            uid: 1000,
            euid: 0,
            comm: b"ls".to_vec(),
            path: b"/usr/bin/ls".to_vec(),
            argc: Some(2),
            sha256: Some("a".repeat(64)),
            hash_state: HashState::Ok,
            flags: vec![],
        }
    }

    #[test]
    fn format_exec_matches_example() {
        let line = format_line(1, &exec());
        assert_eq!(
            line,
            r#"{"v":2,"seq":1,"ts":123456789,"wall":999,"ev":"exec","pid":4711,"ppid":1,"uid":1000,"euid":0,"comm":"ls","path":"/usr/bin/ls","argc":2,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","hash_state":"ok","flags":[]}"#
        );
    }

    #[test]
    fn format_start() {
        let e = Event::Start {
            ts: 100,
            wall: 500,
            mid: "4a3f-...-boot-id".to_string(),
            kernel: "7.2.9-nobara".to_string(),
        };
        assert_eq!(
            format_line(0, &e),
            r#"{"v":2,"seq":0,"ts":100,"wall":500,"ev":"start","mid":"4a3f-...-boot-id","kernel":"7.2.9-nobara"}"#
        );
    }

    #[test]
    fn format_stop() {
        let e = Event::Stop {
            ts: 200,
            wall: 600,
            mid: "m1".to_string(),
        };
        assert_eq!(
            format_line(3, &e),
            r#"{"v":2,"seq":3,"ts":200,"wall":600,"ev":"stop","mid":"m1"}"#
        );
    }

    #[test]
    fn format_lost() {
        let e = Event::Lost {
            ts: 300,
            wall: 700,
            count: 7,
        };
        assert_eq!(
            format_line(4, &e),
            r#"{"v":2,"seq":4,"ts":300,"wall":700,"ev":"lost","count":7}"#
        );
    }

    #[test]
    fn argc_null_when_unknown() {
        let mut e = exec();
        if let Event::Exec { argc, .. } = &mut e {
            *argc = None;
        }
        let line = format_line(1, &e);
        assert!(line.contains("\"argc\":null"), "line = {line}");
    }

    #[test]
    fn sha256_null_when_gone() {
        let mut e = exec();
        if let Event::Exec {
            sha256, hash_state, ..
        } = &mut e
        {
            *sha256 = None;
            *hash_state = HashState::Gone;
        }
        let line = format_line(1, &e);
        assert!(line.contains("\"sha256\":null"), "line = {line}");
        assert!(line.contains("\"hash_state\":\"gone\""), "line = {line}");
    }

    #[test]
    fn flags_in_canonical_order() {
        let mut e = exec();
        if let Event::Exec { flags, .. } = &mut e {
            // absichtlich unsortiert übergeben
            *flags = vec![Flag::ArgcMin, Flag::Fileless];
        }
        let line = format_line(1, &e);
        assert!(
            line.ends_with("\"flags\":[\"fileless\",\"argc_min\"]}"),
            "line = {line}"
        );
    }

    #[test]
    fn inconsistent_hash_state_normalizes_but_keeps_event_flags() {
        let mut e = exec();
        if let Event::Exec {
            hash_state,
            sha256,
            flags,
            ..
        } = &mut e
        {
            *hash_state = HashState::Gone;
            *sha256 = Some("a".repeat(64));
            *flags = vec![Flag::Cached, Flag::Fileless, Flag::ArgcMin, Flag::FdExec];
        }
        let line = format_line(1, &e);
        assert!(
            line.contains("\"hash_state\":\"unreadable\""),
            "line = {line}"
        );
        assert!(line.contains("\"sha256\":null"), "line = {line}");
        assert!(!line.contains("\"cached\""), "line = {line}");
        assert!(!line.contains("\"fileless\""), "line = {line}");
        assert!(line.contains("\"argc_min\""), "line = {line}");
        assert!(line.contains("\"fd_exec\""), "line = {line}");
    }

    #[test]
    fn flags_deleted_not_fileless() {
        let mut e = exec();
        if let Event::Exec { flags, .. } = &mut e {
            *flags = vec![Flag::Deleted];
        }
        let line = format_line(1, &e);
        assert!(line.contains("\"flags\":[\"deleted\"]"), "line = {line}");
        assert!(!line.contains("fileless"), "line = {line}");
    }

    // ── (a) ungültiges UTF-8 → lossy + U+FFFD ──────────────────────────

    #[test]
    fn invalid_utf8_sets_lossy_flag() {
        let mut e = exec();
        if let Event::Exec { comm, .. } = &mut e {
            *comm = vec![0x66, 0x6f, 0x6f, 0xff, 0xfe]; // "foo" + ungültig
        }
        let line = format_line(1, &e);
        assert!(line.contains("\"flags\":[\"lossy\"]"), "line = {line}");
        // U+FFFD als Ersatzzeichen im comm
        assert!(line.contains("\u{FFFD}"), "line = {line}");
    }

    #[test]
    fn valid_utf8_no_lossy_flag() {
        let e = exec(); // "ls" ist gültig
        let line = format_line(1, &e);
        assert!(!line.contains("lossy"), "line = {line}");
    }

    #[test]
    fn lossy_flag_only_when_actually_lossy() {
        // gültiges UTF-8 in comm/path → kein lossy
        let e = exec();
        assert!(!format_line(1, &e).contains("lossy"));

        // ungültiges Byte in path → lossy
        let mut e2 = exec();
        if let Event::Exec { path, .. } = &mut e2 {
            *path = vec![0x2f, 0x74, 0x6d, 0x70, 0x2f, 0x80]; // "/tmp/" + ungültig
        }
        assert!(format_line(1, &e2).contains("\"lossy\""));
    }

    // ── (b) Sonderzeichen → genau eine Zeile, gültiges JSON ────────────

    #[test]
    fn special_chars_single_line_valid_json() {
        let mut e = exec();
        if let Event::Exec { comm, path, .. } = &mut e {
            *comm = b"a\"b\\c\nd\x01e".to_vec();
            *path = b"/tmp/x\ty\r\n".to_vec();
        }
        let line = format_line(1, &e);
        // genau eine Zeile: kein rohes Steuerzeichen im Ergebnis
        assert!(!line.contains('\n'), "line contains raw newline: {line:?}");
        assert!(
            !line.bytes().any(|b| b < 0x20),
            "raw control byte: {line:?}"
        );
        // gültige Struktur
        assert!(
            line.starts_with('{') && line.ends_with('}'),
            "line = {line}"
        );
        // escaped: comm "a\"b\c\nd<0x01>e" → `a\"b\\c\n...`
        assert!(line.contains(r#""comm":"a\"b\\c\n"#), "line = {line}");
    }

    #[test]
    fn no_raw_control_bytes_in_any_event() {
        let mut e = exec();
        if let Event::Exec { comm, path, .. } = &mut e {
            *comm = (0u8..=31u8).collect(); // alle Steuerzeichen
            *path = vec![0x1f, 0x00, 0x7f];
        }
        let line = format_line(1, &e);
        assert!(
            !line.bytes().any(|b| b < 0x20),
            "raw control byte escaped? {line:?}"
        );
    }

    // ── (c) hash_state/sha256-Invariante ──────────────────────────────

    #[test]
    fn hash_state_sha256_invariant_all_combinations() {
        let hex64 = "a".repeat(64);
        let cases: Vec<(HashState, Option<String>, HashState, Option<String>)> = vec![
            (
                HashState::Ok,
                Some(hex64.clone()),
                HashState::Ok,
                Some(hex64.clone()),
            ),
            (HashState::Ok, None, HashState::Unreadable, None),
            (HashState::Gone, None, HashState::Gone, None),
            (
                HashState::Gone,
                Some(hex64.clone()),
                HashState::Unreadable,
                None,
            ),
            (HashState::Unreadable, None, HashState::Unreadable, None),
            (
                HashState::Unreadable,
                Some(hex64.clone()),
                HashState::Unreadable,
                None,
            ),
            (HashState::Reused, None, HashState::Reused, None),
            (
                HashState::Reused,
                Some(hex64.clone()),
                HashState::Unreadable,
                None,
            ),
            (HashState::Superseded, None, HashState::Superseded, None),
            (
                HashState::Superseded,
                Some(hex64.clone()),
                HashState::Unreadable,
                None,
            ),
        ];
        for (hs, sha, expected_state, expected_sha) in cases {
            let e = Event::Exec {
                ts: 1,
                wall: 2,
                pid: 1,
                ppid: 1,
                uid: 1,
                euid: 1,
                comm: b"x".to_vec(),
                path: b"y".to_vec(),
                argc: None,
                sha256: sha.clone(),
                hash_state: hs,
                flags: vec![Flag::Cached],
            };
            let line = format_line(0, &e);
            let expected_field = match &expected_sha {
                Some(h) => format!("\"sha256\":\"{h}\""),
                None => "\"sha256\":null".to_string(),
            };
            assert!(line.contains(&expected_field), "line = {line}");
            assert!(line.contains(&format!("\"hash_state\":\"{}\"", expected_state.name())));
            // Inkonsistente `cached`-Flags dürfen eine Normalisierung nicht überleben.
            if expected_state != HashState::Ok {
                assert!(!line.contains("\"cached\""), "line = {line}");
            }
            assert!(hash_state_sha256_consistent(
                expected_state,
                expected_sha.as_deref()
            ));
        }
    }

    #[test]
    fn is_64_hex_function() {
        assert!(is_64_hex(&"a".repeat(64)));
        assert!(is_64_hex(&"0123456789abcdef".repeat(4)));
        assert!(!is_64_hex("abc"));
        assert!(!is_64_hex(&"g".repeat(64)));
        assert!(!is_64_hex(&"a".repeat(63)));
        assert!(!is_64_hex(&"a".repeat(65)));
    }

    // ── (d) flags Vokabular vollständig ────────────────────────────────

    #[test]
    fn flag_vocabulary_complete() {
        assert_eq!(Flag::Fileless.name(), "fileless");
        assert_eq!(Flag::FdExec.name(), "fd_exec");
        assert_eq!(Flag::Deleted.name(), "deleted");
        assert_eq!(Flag::ArgcMin.name(), "argc_min");
        assert_eq!(Flag::Lossy.name(), "lossy");
        assert_eq!(Flag::PathTrunc.name(), "path_trunc");
        assert_eq!(Flag::Cached.name(), "cached");
    }

    #[test]
    fn cached_flag_renders_last_after_lossy() {
        let mut e = exec();
        if let Event::Exec { flags, comm, .. } = &mut e {
            *flags = vec![Flag::Cached]; // cached steht nach lossy, auch wenn lossy automatisch ist
            *comm = vec![0xff]; // erzwingt lossy
        }
        let line = format_line(1, &e);
        assert!(
            line.ends_with("\"flags\":[\"lossy\",\"cached\"]}"),
            "line = {line}"
        );
    }

    // ── (e) fd_exec: Rang direkt nach fileless ───────────────────────

    #[test]
    fn fd_exec_renders_directly_after_fileless() {
        let mut e = exec();
        if let Event::Exec { flags, path, .. } = &mut e {
            *flags = vec![Flag::Deleted, Flag::FdExec, Flag::Fileless]; // unsortiert
            *path = b"/dev/fd/3".to_vec();
        }
        let line = format_line(1, &e);
        assert!(
            line.ends_with("\"flags\":[\"fileless\",\"fd_exec\",\"deleted\"]}"),
            "line = {line}"
        );
    }

    #[test]
    fn fd_exec_survives_insertion_order_shuffle() {
        // Einfügereihenfolge darf keine Rolle spielen: fd_exec nach fileless,
        // auch wenn es zuletzt übergeben wird.
        let mut e = exec();
        if let Event::Exec { flags, .. } = &mut e {
            *flags = vec![Flag::FdExec, Flag::Fileless];
        }
        let line = format_line(1, &e);
        assert!(
            line.ends_with("\"flags\":[\"fileless\",\"fd_exec\"]}"),
            "line = {line}"
        );
    }

    #[test]
    fn fd_exec_alone_renders_single_flag() {
        let mut e = exec();
        if let Event::Exec { flags, .. } = &mut e {
            *flags = vec![Flag::FdExec];
        }
        let line = format_line(1, &e);
        assert!(line.ends_with("\"flags\":[\"fd_exec\"]}"), "line = {line}");
    }

    #[test]
    fn path_trunc_renders_before_cached() {
        let mut e = exec();
        if let Event::Exec { flags, .. } = &mut e {
            // absichtlich unsortiert: cached vor path_trunc übergeben
            *flags = vec![Flag::Cached, Flag::PathTrunc];
        }
        let line = format_line(1, &e);
        assert!(
            line.ends_with("\"flags\":[\"path_trunc\",\"cached\"]}"),
            "line = {line}"
        );
    }

    #[test]
    fn all_flags_together_in_canonical_order() {
        let mut e = exec();
        if let Event::Exec {
            flags, comm, path, ..
        } = &mut e
        {
            *flags = vec![
                Flag::Cached,
                Flag::PathTrunc,
                Flag::ArgcMin,
                Flag::Deleted,
                Flag::FdExec,
                Flag::Fileless,
            ]; // unsortiert
            *comm = vec![0xff]; // erzwingt lossy
            *path = b"ok".to_vec();
        }
        let line = format_line(1, &e);
        assert!(
            line.ends_with("\"flags\":[\"fileless\",\"fd_exec\",\"deleted\",\"argc_min\",\"lossy\",\"path_trunc\",\"cached\"]}"),
            "line = {line}"
        );
    }

    #[test]
    fn all_flags_together_in_order() {
        let mut e = exec();
        if let Event::Exec { flags, comm, .. } = &mut e {
            *flags = vec![Flag::ArgcMin, Flag::Deleted, Flag::Fileless]; // unsortiert
            *comm = vec![0xff]; // erzwingt lossy
        }
        let line = format_line(1, &e);
        assert!(
            line.ends_with("\"flags\":[\"fileless\",\"deleted\",\"argc_min\",\"lossy\"]}"),
            "line = {line}"
        );
    }

    // ── weitere Basis-Tests ────────────────────────────────────────────

    #[test]
    fn json_escaping_in_comm_and_path() {
        let mut e = exec();
        if let Event::Exec { comm, path, .. } = &mut e {
            *comm = b"a\"b\\c".to_vec();
            *path = b"/tmp/x\t".to_vec();
        }
        let line = format_line(1, &e);
        assert!(line.contains(r#""comm":"a\"b\\c""#), "line = {line}");
        assert!(line.contains(r#""path":"/tmp/x\t""#), "line = {line}");
    }

    #[test]
    fn seq_is_monotonic_field() {
        assert!(format_line(0, &exec()).starts_with(r#"{"v":2,"seq":0,"#));
        assert!(format_line(42, &exec()).contains(r#""seq":42"#));
    }

    #[test]
    fn ev_vocabulary() {
        assert_eq!(Ev::Start.name(), "start");
        assert_eq!(Ev::Stop.name(), "stop");
        assert_eq!(Ev::Exec.name(), "exec");
        assert_eq!(Ev::Lost.name(), "lost");
    }

    #[test]
    fn hash_state_vocabulary() {
        assert_eq!(HashState::Ok.name(), "ok");
        assert_eq!(HashState::Gone.name(), "gone");
        assert_eq!(HashState::Unreadable.name(), "unreadable");
        assert_eq!(HashState::Reused.name(), "reused");
        assert_eq!(HashState::Superseded.name(), "superseded");
    }
}
