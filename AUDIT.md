# Audit exec-observer – aktueller Stand

Datum: 11. Oktober 2026 · Version `0.1.0` · Ort: `/home/jnrabit/projekte/exec-observer`

---

## 1. Kurzfassung

Der Exec-Beobachter beobachtet `execve`-Systemaufrufe per eBPF-Tracepoints und
protokolliert pro Exec den Pfad, Argc, comm, uid/euid und einen SHA-256-Hash der
ausgeführten Datei als neue JSON-Zeile. Gegliedert in vier Crates:

| Crate | Rolle |
|---|---|
| `exec-observer-uapi` | `no_std`-ABI (`#[repr(C)]`-`ExecEvent`, OFFSET-Konstanten) – einzige Quelle für das Layout |
| `exec-observer-common` | JSON-Schema v2, Ausgabepufferung, HashState, Flags |
| `exec-observer-ebpf` | eBPF-Sensor (3 Tracepoints), manuelles CO-RE über BTF-Offsets |
| `exec-observer` | Daemon: BTF-Parser, eBPF-Load, Eventverarbeitung, SHA-256, Senke |

Eigenschaften: PID-Reuse-Schutz über `start_boottime`, `ARGS`-Map für argc
(Gültigkeits-Cookie = `start_boottime` des `group_leader`), Hash-Cache
`(dev,ino) → (size,mtime,ctime,sha256)`, Drop-Zähler (Lost-Events), härtete
Datei-Senke, Capability-Restriction (Mindestmenge, siehe §4). Das eBPF-Objekt
ist per `include_bytes_aligned!` eingebettet (kein `AYA_BUILD_OBJ`).

Hash, `hash_state` und die Flags `fileless`/`deleted` entstehen beim
**Verarbeiten** und setzen ein Ziel voraus, das dann noch lebt; für kurzlebige
Ziele ist `hash_state:"gone"` mit `sha256:null` und `flags:[]` der Normalfall
(Schema §3). `fd_exec` kommt aus dem Kernel-Pfad des Ereignisses und ist davon
unabhängig.

---

## 2. Schema v2 & ABI

### 2.1 JSON-Format (`FORMAT_VERSION = 2`)

```json
{"v":2,"seq":55,"ts":397028696796092,"wall":1791744413755543558,"ev":"exec","pid":1491549,"ppid":1485557,"uid":1000,"euid":1000,"comm":"sleep","path":"/usr/bin/sleep","argc":2,"sha256":"651468d5…","hash_state":"ok","flags":[]}
```

- `v` – Schema-Version
- `ts` – Kernel-Bootzeit (ns, `CLOCK_BOOTTIME`) zum Ereigniszeitpunkt
  (`bpf_ktime_get_boot_ns` im Sensor bzw. `CLOCK_BOOTTIME` für `start`/`lost`/
  `stop`); `wall` – Unix-Zeit (ns), abgeleitet aus dem einmalig beim Start
  gemessenen Offset `realtime − boottime`
- `euid` – effektive User-ID (sichtbar z. B. bei `sudo` = `0`)
- `hash_state` – `ok` | `gone` (Prozess zwischen Hash und Zeile verschwunden) | `unreadable` (Prozess lebt, exe nicht lesbar, oder Sensor-Identität fehlt) | `reused` (echte PID-Wiederverwendung: andere Startzeit) | `superseded` (gleiche PID/Startzeit, aber geöffneter FD gehört zu einer späteren Exec-Stufe)
- `flags` – `["fileless"]`, `["deleted"]`, `["argc_min"]`, `["lossy"]`, `["path_trunc"]`, `["cached"]`, feste Reihenfolge

Ereignisarten: `start` (mit `mid`+`kernel`), `exec`, `lost` (Ring-Überlauf), `stop` (mit `mid`).

### 2.2 ABI (`ExecEvent`, bytemuck-Pod)

`pid, ppid, uid, euid, tid, argc` (6×u32), `argc_min, has_argc, path_trunc` (u8),
`start_boot_time` (u64), `ts_boot` (u64), `comm[16]`, `filename_len` (u16),
`filename[256]`, `exe_ino` (u64), `exe_size` (u64), `has_exe_ident` (u8).
`Pod`/`Zeroable` per `unsafe impl` (das `#[repr(C)]`-Padding blockierte den
Derive-Check); Der Daemon deserialisiert via `bytemuck::try_from_bytes`.

### 2.3 `OFFSETS`-Map (manuelles CO-RE, fail-closed)

| Index | Kernel-Feld | Zweck |
|---|---|---|
| 0 | `task_struct.real_parent` | Parent-tgid |
| 1 | `task_struct.tgid` | PID |
| 2 | `task_struct.cred` | Effektive Creds |
| 3 | `cred.uid` | Reale UID (per BTF-Offset, ohne `+16`-Annahme) |
| 4 | `cred.euid` | Effektive UID |
| 5 | `task_struct.start_boottime` | PID-Reuse-Schutz |
| 6 | `task_struct.group_leader` | ARGS-Identität (Zeiger; Leader-`start_boottime` beider Seiten) |

Spezifikation als `(&str, &str)`-Tupel; Fehler → Abbruch vor dem Laden
(fail-closed). Die Reihenfolge der Tupel entspricht exakt den `OFF_*`-Indizes in
`exec-observer-uapi`.

---

## 3. Umsetzungsstatus der Befundliste

### Befunde S (sicherheits-/korrektheitskritisch)

| ID | Befund | Status |
|---|---|---|
| S1 | BTF-Parser: `UNION`-Kinds wurden nicht übersprungen | **Fix** in `btf.rs` (`i += vlen * 12`), Regressionstest (synthetisches BTF) |
| S2 | Senke world-readable | **Fix** (`0o600`, `O_NOFOLLOW`, `O_CLOEXEC`) |
| S3 | Relativer Objekt-Fallback als stiller Sicherheitsfall | **Fix** – Objekt per `include_bytes_aligned!` (`EXEC_EBPF_OBJECT` aus `build.rs`) eingebettet; zur Laufzeit kein Objektpfad/`AYA_BUILD_OBJ`, kein injizierbarer relativer Fallback. Fehlt das Objekt zur Compile-Zeit, schlägt der Build fehl (fail-closed) |
| S4 | Entwurfs-Bugs im eBPF-Argv-Scan | **Fix** – `ARGC_LIMIT` 8192 → 1024, Terminator-Check an Position `ARGC_LIMIT` |
| S5 | kexec/usermodehelper-plus | **Fix** – Hash-Cache + Boottime-Doppelcheck |
| S6 | Verlorene Events silent | **Fix** – `DROPS` PerCpuArray, `ev:"lost"` |
| S7 | Startzeit-Toleranz | **Fix/belegt** – ±1 Tick zwingend (Kernel rundet `starttime`); `tick_ns()` mit `div_ceil` |
| S8 | Kein UID-Filter | **Kein Fix** – Feature-Entscheidung, kein Bug |

### Befunde K (Zwischenfälle/Edge-Cases)

| ID | Status |
|---|---|
| K1 `argc_min`-Fehlalarm | Fix – Position-`ARGC_LIMIT`-Prüfung |
| K2 Hash-Flags | Fix – memfd → nur `fileless`, „(deleted)“ nur ohne memfd |
| K3 PID-Reuse | Fix – `HashState::Reused` statt falschem Hash |
| K4 Startzeit-Quellen | Fix – `CLOCK_BOOTTIME`-Abgleich gegen `/proc/<pid>/stat` |
| K5 Relative Pfade | Fix – Pfad-NUL-Trim, korrekte `__data_loc`-Dekodierung |
| K6 `ARGS`-Keying | Fix – Prozess-PID statt TID (`current_pid()`) |
| K7 „too many arguments“ | Fix – `Writer`-Struct |
| K8 langsame hex-Encoding | Fix – Lookup-Tabelle |
| K9 Root-Pflicht | Fix – klare `geteuid() != 0`-Meldung vor BTF-Load |
| K10 Formatierer | Fix – `cargo fmt` (Toolchain-Check) |
| K11 `/tmp`-Abhängigkeit | Fix – crates.io statt `/tmp/opencode/aya-src` |
| K12 CLI | Fix – `--help`/`--version` |
| K13 Hash-Race bei Doppel-exec | **Kein Code-Fix** – `open("/proc/<pid>/exe")` ist Magic-Link (atomar); Rest dokumentiert |

### Kurzoptionen (Kurzopt 1–7)

1.–7. umgesetzt: `push_header`, Daemon-interner Hash-Cache, BTF-Kind-Konstanten,
BPF-Load-Fehlerausgabe, `read_u32`-Helper, BTF-Spec als Tupel mit `collect`-Fehler,
String-Tabelle (v2).

---

## 4. Sicherheit & Robustheit

- **Senke**: `open` mit `O_NOFOLLOW | O_CLOEXEC`, Modus `0600` (nur Owner).
- **Capabilities**: nach dem Load wird auf die **Mindestmenge** reduziert
  (Begründung je Capability, Bounding-Menge-Regel, Kindprozess-Regel: `DESIGN.md`) – und zwar **vor** dem Schreiben der `start`-Zeile, damit ein Leser
  dieser Zeile den reduzierten Zustand sieht (vorher geschah die Reduktion
  danach). Zielmenge ist der **Schnitt** aus `{CAP_SYS_PTRACE (19),
  CAP_DAC_READ_SEARCH (2), CAP_BPF (39)}` und der tatsächlich vorhandenen
  Permitted-Menge (`capability_target`, host-getestet): `capset` kann eine
  Capability nicht neu verleihen, fehlt eine gewünschte also im Permitted-Set,
  schlug jede Anhebung mit `EPERM` fehl und der Daemon lief per Best-Effort mit
  der **größeren** Ausgangsmenge weiter (Fund 2: `CAP_PERFMON` blieb erhalten).
  `inheritable` = 0, Ambient via `PR_CAP_AMBIENT/CLEAR_ALL` geleert, Bounding via
  `PR_CAPBSET_DROP` auf genau die Zielmenge gekürzt. **Nicht mehr Best-Effort:**
  `capget`, `capset`, `PR_CAP_AMBIENT/CLEAR_ALL` und ein `PR_CAPBSET_DROP` (wenn
  er möglich wäre) beenden den Daemon geordnet – stderr mit errno,
  `stop`-Zeile, Exit ≠ 0; anschließend wird die erreichte Menge zurückgelesen
  und gegen die Zielmenge geprüft (Abweichung von „jeder Drop-Fehler fatal“,
  mit Grund siehe unten).
  Der Daemon meldet auf stderr, was er tat: `Capabilities: vorhanden=0x… →
  Ziel=0x…`. `CAP_PERFMON` ist per `const`-Assertion dauerhaft
  ausgeschlossen.
- **PID-Reuse**: **vor** dem Hashen wird `task_struct.start_boottime` gegen das
  `starttime` aus `/proc/<pid>/stat` geprüft (Toleranz 1 Tick); bei Abweichung
  kein `exe`-Read (`HashState::Gone`). **Nach** dem Hashen prüft
  `verify_hash_state_after` erneut; weicht die Startzeit nun ab, ist der gelesene
  Hash veraltet → `HashState::Reused` (`sha256:null`), nie ein falscher Hash.
- **Ringpuffer-Überlauf**: Per-CPU-Drop-Zähler → `ev:"lost"` mit Differenz.
- **Graceful Shutdown**: Signal-Handler setzt Atomic-Flag; Loop prüft das Flag auch
  *innerhalb* der Event-Queue, sodass bei großem Backlog sofort abgebrochen wird;
  einzelne kaputte Events brechen den Daemon nicht mehr ab.
- **Fail-closed**: Fehlende BTF-Offsets verhindern den Load; das eBPF-Objekt ist
  zur Compile-Zeit eingebettet (fehlt es, scheitert bereits der Build).

---

## 5. Build & Verifikation

Umgebung: Linux `7.2.9-200.nobara.fc44.x86_64`, `CONFIG_DEBUG_INFO_BTF`,
nightly-Toolchain mit `rust-src`, `aya 0.14`/`aya-ebpf 0.2.1` (crates.io-Registry).

```bash
cargo build -p exec-observer            # baut eBPF-Objekt via build.rs (aya-build)
cargo test -p exec-observer-common -p exec-observer
cargo clippy -p exec-observer -p exec-observer-common -p exec-observer-uapi
cargo fmt --check
```

Ergebnis: **Tests: 5 (uapi) + 27 (common) + 42 (daemon) grün**, Clippy ohne Warnungen, fmt sauber. eBPF-Objekt wird per `include_bytes_aligned!` direkt ins Binary eingebettet (`EXEC_EBPF_OBJECT`, kein `AYA_BUILD_OBJ`/OBJ-PFAD mehr).

```bash
cargo build -p exec-observer
bash tests/temp-selftest.sh                # Temp-Verwaltung OHNE root
sudo tests/cap-matrix.sh                   # Capability-Fälle a–e (root)
sudo tests/integration.sh                  # Kriterienmatrix K1–K19 + 14b (root)
```
eBPF-Objekt ~140 KB (143.776 B, ELF relocatable mit BTF/debug_info).
Inkrementelle Builds ~0,0s, Kalt-Build aus dem Nichts ~10 s.

### Laufzeit-Selbsttest (root)

```bash
sudo ./target/debug/exec-observer 2>exec.log   # Objekt ist eingebettet, kein AYA_BUILD_OBJ
# Beispiel-Objekte erzeugen:
for i in 1 2 3 4 5; do /usr/bin/sleep 0.2; done
sudo tail -5 exec-observer.log
Ctrl-C  # → ev:"stop" (erscheint nach Prozess-Ende in der Datei)
```

Bestätigt: `path` korrekt (`/usr/bin/sleep`, `/sbin/modprobe`, `/usr/bin/sudo`),
`euid` korrekt (setuid-Effekt bei `sudo` → `0`), `argc` korrekt; `modprobe`
(usermodehelper, ohne `execve`-Argv-Durchgang) plangemäß `argc:null`, `hash_state:"ok"`.

---

## 6. Bekannte Grenzen / spätere Optionen

- **UID-Filter** (S8): als Feature nachrüstbar, bewusst nicht enthalten.
- **`cap-matrix.sh` ist umgebaut** (Stand nach den Root-Läufen): Teil 1 prüft die
  Mengen je Startart (Fälle a–e, c jetzt mit `CapabilityBoundingSet` +
  `AmbientCapabilities` wirklich eingeschränkt, der frühere Vollstart als d2
  ehrlich benannt), Teil 2 die **Verhaltensmatrix** Menge × Fall (a: Hash,
  b: 0711-Datei, c: setuid/dumpable, d: Ringüberlauf per `kill -STOP`). Die
  „Cap\*=0x0"-Fehlmeldungen der ersten Läufe waren ein Harness-Bug
  (Schlüssel mit/ohne Doppelpunkt in `caps_of`); die Rohbelege zeigten korrekte
  Reduktion. Der Bit-35-Unterschied (`vorhanden=0xc800080004` gegen Bounding
  `0xc000080004`) ist die execve-Regel: das Inheritable-Set des Aufrufers geht
  bei root in Permitted über (Sitzung hat `CAP_WAKE_ALARM`) — behoben mit
  `setpriv --inh-caps=-all`, nachgewiesen in einer User-Namespace.
- **`PR_CAPBSET_DROP` ohne `CAP_SETPCAP`** (im Root-Lauf von `cap-matrix.sh`
  Fall b/e sichtbar): `PR_CAPBSET_DROP` verlangt `CAP_SETPCAP` im *effektiven*
  Satz. Ein Daemon, der minimal gestartet wird (genau `bpf`+`perfmon`+
  `sys_ptrace`+`dac_read_search`), hat sie nicht – das Kernel verbietet das
  Leeren des Bounding-Sets dann mit `EPERM`. Deshalb ist dieser eine Fehler
  **kein** Abbruch, sondern eine Warnung: die Macht des Prozesses kommt aus
  Effektiv/Permitted (die `capset` reduziert, fatal), nie aus dem Bounding-Set,
  und neue Caps könnte nur ein `execve` geben – das tut der Daemon nie.
  Umgesetzt als „Drop-Lauf nur, wenn `CAP_SETPCAP` vorhanden; sonst eine
  Warnung". Ein Lauf mit fataler Behandlung endete in Fall b/e mit
  `PR_CAPBSET_DROP(0): Operation not permitted`, obwohl die Zielmenge korrekt
  war – also genau in der Startform, für die der Daemon gedacht ist.
- **`wall`-Drift**: Abweichung des errechneten `realtime − boottime` bei
  Zeitsprüngen (NTP-Stellschritt/manuell) während des Laufs – dokumentiert.
  Reines **Suspend** driftet nicht: `CLOCK_BOOTTIME` und `CLOCK_REALTIME` laufen
  beide über den Suspend hinweg weiter, der einmal gemessene Offset bleibt gültig.
- **In-Place-Binary-Modifikation** (K13): Datei kann nach dem Hash verändert werden;
  Hash-Cache erkennt Änderungen über `(size, mtime, ctime)`, nicht über den Inhalt.
- **Exec-Ketten derselben PID (Befund A, behoben)**: Sensorereignis und
  Daemon-Verarbeitung liegen auseinander; `start_boottime` bleibt bei Exec im
  selben Prozess gleich (auch mit `de_thread`), sodass eine Helfer-Zeile den
  Hash des Ziels trug. Jetzt erfasst der Sensor `(i_ino, i_size)` aus
  `mm->exe_file` zum Ereigniszeitpunkt; der Daemon vergleicht vor Cache/Hash
  mit `fstat` des geöffneten FDs: Abweichung → `superseded` (sha256 null),
  fehlende Sensor-Identität → `unreadable` (+ `ident_missing`). Auf btrfs wird
  bewusst `(ino, size)` statt `(dev, ino)` verglichen (`st_dev` ≠ `s_dev`,
  gemessen). Restlücke: gleicher Inode + gleiche Größe bei geändertem Inhalt.
  Anatomie der BTF-Auflösung: `mm_struct` ist auf dem Zielkernel eine
  Randstruct-Hülle (benannter Typ mit anonymem Rumpf); der Walker durchsucht
  anonyme Member rekursiv. Belegt in `tests/integration.sh` Phase H
  (K23/K24, Root-Lauf steht aus).
- **Relative Pfade**: Tracepoint liefert den Rohpfad (kann relativ sein) – nicht absolutisiert.
- **Kurzlebige Ziele** (im Root-Lauf aufgefallen): `/bin/echo` (uid 1000) und
  ein memfd-Start erschienen mit `hash_state:"gone"`, `sha256:null`, `flags:[]`.
  Ursache ist der Zeitabstand Exec → Verarbeitung: der Prozess ist fort, bevor
  der Daemon `/proc/<pid>/exe` liest. Kein Fehler, aber messrelevant: alle
  Prüfungen auf Hash/`fileless`/`deleted` laufen jetzt mit Zielen, die leben
  (`/bin/sleep 3`, Kopie im memfd bzw. gelöschte Kopie). Ein eigener Info-Fall
  (200 × `/bin/true`) berichtet nur die Mischung ok/gone, ohne Bewertung.
  Dokumentiert in `SCHEMA.md` §3.
- **`argc` bei usermodehelper**: `execveat`/`execve`-Deckung vorhanden; Kernel-Helferprozesse
  (`modprobe`) durchlaufen kein `sys_enter` → `argc:null` (korrekt).
- **`argc`-Abweichung bei leerem `argv`**: Beobachter zählt am Syscall-Eintritt `0`;
  der Kernel fügt danach ein leeres Argument ein, das Programm sieht `1`
  (dokumentiert in `SCHEMA.md` §3, nachgemessen mit `argc_exec 0`).
- **Stale `ARGS`-Eintrag nach fehlgeschlagenem `execve`** (Kriterium 10, umgesetzt als
  „Mittelweg A–B“):
  `sys_enter_execve`/`sys_enter_execveat` legen `argc` unter der TGID in der
  `ARGS`-Map ab; entfernt wird der Eintrag nur von `sched_process_exec` (erfolgreicher
  Exec). Ein **fehlgeschlagenes** `execve` lässt den Eintrag stehen, weil kein
  `sys_exit_execve`/`sys_exit_execveat`-Programm existiert. Zwei design-technische
  Extreme – **tatsächlich umgesetzt ist die Mitte**:
  - **Option A (Code, verworfen)**: zwei zusätzliche Tracepoints, die
    `ARGS.remove(&args_key())` aufrufen. Aufwand gering, aber zwei weitere
    Attach-Punkte und ein Remove-Race-Kandidat auf dem Exit-Pfad.
  - **Option B (Doku, verworfen)**: als Limitation dokumentieren, kein Code –
    hinterlässt stilles Fehldatum bei PID-Wiederverwendung.
  - **Mittelweg (umgesetzt)**: `ARGS` trägt statt `u64` einen `ArgsEntry`
    (`start_boottime`, `argc`, `argc_min`). Als Identitäts-Cookie wird an
    **beiden** Enden die `start_boottime` des `group_leader` verwendet (nicht die
    des bloßen Threads): `sys_enter_*` speichert sie, `sched_process_exec` liest
    sie (neuer BTF-Offset `task_struct.group_leader`, uapi `OFF_GROUP_LEADER`).
    Begründung: Führt ein **Nicht-Hauptthread** `execve` aus, macht `de_thread`
    (in `begin_new_exec`) ihn zum Leader und setzt
    `tsk->start_boottime = leader->start_boottime`; der
    `sched_process_exec`-Tracepoint feuert **danach**. Mit der eigenen
    Thread-Startzeit am `sys_enter` hätte das Cookie nicht gematcht → K5
    (Nicht-Hauptthread-Exec) hätte `argc:null` geliefert. Der
    `group_leader`-Wert ist an beiden Enden gleich (vor `de_thread`: alter
    Leader; danach: der Ausführende selbst).
    Bei Abweichung – PID-Wiederverwendung durch einen Start ohne `sys_enter`
    (z. B. `modprobe`) – gilt der Eintrag als veraltet und die Zeile erhält
    `argc:null` (nie ein falsches `argc`). Der Eintrag bleibt LRU-gebunden
    (Obergrenze, keine neue Lösch-Race). Geänderter Pfad:
    `count_and_store` (+`group_leader_start_boottime`) und die `ARGS.get`-Seite in
    `try_sched_process_exec` (`exec-observer-ebpf/src/main.rs`). Die
    Entscheidungslogik liegt als reine Funktion `resolve_argc` in `exec-observer-uapi`
    (einzige Quelle, eBPF ruft sie auf) und ist host-unit-getestet
    (`cargo test -p exec-observer-uapi`: gültig/veraltet/fehlend/Null-Edge).

    **Herkunft der `de_thread`-Aussage** (kein Gedächtnis, beides belegt):
    - **Quelltext:** `fs/exec.c`, Linux-Tag **`v7.2`** (Mirror
      `torvalds/linux`, per `raw.githubusercontent.com` gelesen, lokal
      heruntergeladen und gegreppt): `de_thread()` Zeilen 988–993 setzen
      `tsk->start_time = leader->start_time;` / `tsk->start_boottime =
      leader->start_boottime;` – mit dem Kommentar „When we take on its
      identity by switching to its PID, we also take its birthdate“. Die
      Leader-Quelle ist `struct task_struct *leader = tsk->group_leader;`
      (Zeile 962). `exec_binprm()` ruft `trace_sched_process_exec(current,
      old_pid, bprm)` in **Zeile 1748**, erst nach dem
      `search_binary_handler()`-Loop ab **Zeile 1720** (und damit nach
      `begin_new_exec()` → `de_thread()`). Dasselbe Bild in `master`
      (Zeilen 997 / 1837).
      **Einschränkung:** gelesen wurde der Tag `v7.2`, nicht der exakte
      Patchstand `7.2.9` – der Stable-Zweig `linux-7.2.y` war über
      raw.githubusercontent nicht erreichbar und der lokale Quellbaum
      (`/usr/src/kernels/7.2.9-200.nobara.fc44.x86_64`) enthält kein `fs/`.
      Der Code ist über die 7.2er-Reihe stabil; der Patchstand wurde **nicht**
      zeichengenau gegen 7.2.9 verglichen.
    - **Empirisch auf dem laufenden Kernel** (`7.2.9-200.nobara.fc44.x86_64`,
      nur `/proc`, kein Root): `/tmp/opencode/de_thread_probe.c` –
      Leader-Startzeit 40738643, eigene Worker-Startzeit 40738663, nach dem
      Exec im Worker trägt die PID weiterhin **40738643** (Ausgabe: „Fall A –
      Worker übernimmt Leader-Startzeit (de_thread-Transfer)“), mehrfach
      reproduzierbar.
    - **Noch offen (Annahme, nicht Fakt):** dass der eBPF-Pfad diese Werte
      auch tatsächlich so sieht – `start_boot_time` wird im Tracepoint über
      `group_leader` gelesen und gegen den am `sys_enter` gespeicherten Wert
      verglichen. Der **Ende-zu-Ende-Beweis** (argc korrekt, nicht `null`)
      bleibt K5 im Root-Lauf.
- **bpftool** nicht installiert – UNION-Wirksamkeit stattdessen durch `btf.rs`-Unit-Test abgesichert.

---

## 7. Kriterienmatrix

Zuordnung der Auftragsnummern zu den Prüfungen in `tests/integration.sh`
(interne K-Nummern) und `tests/cap-matrix.sh`. Legende **Beleg**:
`Host` = `cargo test` (ohne Root), `Integration` = eines der Skripte
(benötigt Root für den eBPF-Load), `ungeprüft` = es gibt dafür keinen Beleg.

Stand über alle Zeilen: **cap-matrix.sh mehrfach mit sudo gelaufen und grün**
(Masken a/b/e/f, Verhaltensmatrix s1–s4; Details unten);
`tests/integration.sh` lief beim Nutzer (Befund A stammt aus einer
Phase-D-Senke), seine Matrix wurde hier nicht protokolliert —
Integrations-Zeilen gelten daher als geschrieben + teilweise gelaufen,
nicht als grün belegt. Host-Belege: uapi 8, common 28, Daemon 86–87 Tests,
`bash -n` sauber, Auswerte-Logik per synthetischen Senken geprüft.

Zur Nummerierung: die internen K-Nummern stammen aus dem ersten Auftrag
(K1–K8 = Kriterien 1–8) und wurden im zweiten Auftrag für die schärferen
Nachprüfungen derselben und neuer Kriterien weiterverwendet (9–14). Deshalb
tauchen K5/K6/K7 in beiden Tabellen auf: einmal als Erstbeleg, einmal als
Nachprüfung mit zusätzlichen Bedingungen (`pid == TGID`, zwei Threads,
fehlgeschlagenes Exec).

### 7.1 Auftrag 1 – Kriterien 1 bis 8

| Auftrag | Kriterium | interner K | Beleg | Stand |
|---|---|---|---|---|
| 1 | `start` v=2, `seq=0`, mit `mid`+`kernel`; `stop` mit gleicher `mid` | K1 | Integration | geschrieben; Root-Lauf nicht protokolliert |
| 2 | `seq` lückenlos ab 0 (Kopf-Reihenfolge) | K2 | Integration | geschrieben; Root-Lauf nicht protokolliert |
| 3 | Ereignis-Zeilen tragen `pid`…`flags`, mit geschlossenen Vokabularen (`hash_state` inkl. `superseded`, `sha256` null-oder-64-hex, `flags` inkl. `fd_exec`) | K3 | Integration | Prüfung bewusst zustandsunabhängig (gilt für lebende wie kurzlebige Ziele) |
| 4 | `execve`-Zeilen: `uid`≠0, `argc` korrekt (private Kopie) | K4 | Integration | geschrieben; Root-Lauf nicht protokolliert |
| 5 | Nicht-Hauptthread ruft `execve`: genau eine Zeile, `pid == TGID`, `argc` korrekt | K5 | Integration | geschrieben; Root-Lauf nicht protokolliert; `group_leader`-Identität (§6) |
| 6 | Zwei Threads gleichzeitig: je Zeile `argc=2`, `pid == TGID`, keine falsche Zeile | K6 | Integration | geschrieben; Root-Lauf nicht protokolliert |
| 7 | Fehlgeschlagenes `execve`: kein Ereignis, Daemon lebt weiter | K7 | Integration | geschrieben; Root-Lauf nicht protokolliert |
| 8 | `sha256` = Kopie-Hash (64 hex), `hash_state: ok` für private Zielkopie fremder uid, genau 2 Zeilen | K8 | Integration | Private Kopie (B1/B2), exakter Pfad + uid; benötigt `CAP_SYS_PTRACE` (cap-matrix b/e) |

### 7.2 Auftrag 2 (mit den Entscheidungen) – Kriterien 9 bis 14

| Auftrag | Kriterium | interner K | Beleg | Stand |
|---|---|---|---|---|
| 9 | Nicht-Hauptthread ruft `execve`; genau eine Zeile; `argc`; `pid == TGID`; Zusatz: zwei Threads gleichzeitig | K5, K6 | Integration | geschrieben; Root-Lauf nicht protokolliert; `argc` hängt an der `group_leader`-Identität (§6) |
| 10 | Fehlgeschlagenes `execve` ohne Zeile; nächstes Exec mit richtigem `argc`; Zusatz: Stale-`ARGS`/PID-Reuse darf nie falsches `argc` liefern | K7 + `resolve_argc` | Host (uapi, grün) + Integration | `resolve_argc` host-geprüft (gültig/veraltet/fehlend/Null-Edge); K7 geschrieben, Root-Lauf nicht protokolliert; `HashState::Reused` **ungeprüft** (siehe 7.3) |
| 11 | `argc`-Randfälle: `n=0`; `Limit-1`/`Limit`/`Limit+1`; `n=100000` | K15, K16, K17 | Integration | geschrieben, Root-Lauf nicht protokolliert; Helfer verifiziert |
| 12a | `execveat` auf memfd → `fileless` (ohne `deleted`), `hash_state: ok`, `sha256` = Nutzlast-Hash | K12 | Integration | Private Nutzlast (`PAY_C`, lebt 3 s), sonst nicht beobachtbar (§6) |
| 12b | Gelöschte Datei → `deleted`, nicht `fileless`, Hash = Kopie-Hash | K18 | Integration | Private Kopie via `EXEC_CASES_TMPDIR` (lebt); Helfer verifiziert |
| 13 | Ringpuffer-Überlauf → Erhaltung `geschrieben + lost == kernel_seen` (B4), `lost ≥ 1` | K13 | Integration + cap-matrix Fall d | cap-matrix: s1/s3 PASS (Verhältnis 1.000); s2/s4 exakt −1 (sechs Läufe) — offen, KEEP=1-Experiment ausstehend; Integration: geschrieben, Laufstand nicht protokolliert |
| 14 | `kill -9`: letzte Zeile valides JSON, kein `stop`; zusätzlich K14b: der getroffene Prozess ist wirklich fort | K14, K14b | Integration | geschrieben; Nutzer-Befund A stammt aus einer Phase-D-Senke (kill -9-Fall lief); Matrix nicht protokolliert; K14b prüft `kill -0` auf die Daemon-PID (kein Waisenprozess mehr) |

### 7.3 Weitere Prüfungen (nicht Auftrags-Kriterium) – und die offenen Zeilen

| Prüfung | interner K | Beleg | Stand |
|---|---|---|---|
| Capabilities: Mindestmenge nach dem Load, fail-closed beim Load, fremde exe lesbar / nicht lesbar | cap-a … cap-e | `tests/cap-matrix.sh` (Root-Läufe, mehrfach grün) | Masken a/b/e/f PASS; Verhalten s1–s4 grün (a1000/aroot/b0711/setuid/dump); `over` s1/s3 PASS, s2/s4 −1 (offen); Fall c/d2 deaktiviert; Host-Tests für Parser/Zielmenge grün |
| `HashState::Reused` (PID wiederverwendet nach dem Hashen) | K10 | **ungeprüft** | `SKIP`; nur manuell reproduzierbar (host-seitig ist nur `resolve_argc` geprüft) |
| `HashState::Superseded` (spätere Exec-Stufe derselben PID) + Kette setpriv→Helfer→Ziel | K23, K24 | Integration Phase H (STOP-deterministisch) | geschrieben; Root-Lauf ausstehend (beweist zugleich das `mm->exe_file`-Timing) |
| Dateisystem-Matrix: btrfs-Kopie, `/usr/bin/sleep`, tmpfs-Kopie → je `ok` | K25, K26, K27 | Integration Phase I | geschrieben; Root-Lauf ausstehend |
| Root-Gegenprobe (`linger`, genau 1 Zeile, uid 0, argc 3) | K19 | Integration Phase A2 | geschrieben; Root-Lauf ausstehend |
| `HashState::Reused` (PID wiederverwendet nach dem Hashen) | K10 | **ungeprüft** | `SKIP`; nur manuell reproduzierbar (host-seitig ist nur `resolve_argc` geprüft) |
| Tiefer Pfad → `path_trunc` (≤ 256 B) | K11 | Integration | geschrieben; Root-Lauf nicht protokolliert |
| Hash-Cache → 1. Start ohne, 2. mit `cached`, identischer `sha256` (private Kopie) | K9 | Integration | geschrieben; Root-Lauf nicht protokolliert |
| Kurzlebige Ziele (je 200 × zwei private Kopien): Zustandsmischung, **ohne Bewertung** | K20 | Integration | reine Info-Zeile, zählt nicht in pass/fail/skip |
| Nach dem Lauf bleibt kein `exec-observer`-Prozess übrig; Temps (mktemp + `.it-btrfs.*`, außer `KEEP=1`) sind abgeräumt | (Schlusspunkt) | Integration + `tests/temp-selftest.sh` (ohne root) | Selbsttest grün; Schlussprüfung in beiden Skripten geschrieben |
| Auswertung selbst: scheitert der Auswerte-Block, darf der Lauf nicht grün aussehen | (Wächter) | beides | rc!=0 oder leere Matrix → UNVOLLSTÄNDIG (Exit 2); bewertete Fehler → Exit 1 |
| `ts`/`seq` nicht zueinander monoton; Import ordnet nach `seq` | – | Host (`cargo test` in `exec-observer-common`, 28 Tests) | grün |

Offene Zeilen bewusst benannt: **cap-matrix Fall c/d2** (deaktiviert),
**PID-Wiederverwendung** (K10 bleibt `SKIP`, nur `resolve_argc` host-geprüft),
**Überlauf s2/s4** (exakt −1, KEEP=1-Experiment ausstehend),
**Integration-Matrix** (lief beim Nutzer, aber nicht protokolliert).

Host-Testzahlen (laufend): `exec-observer-uapi` 8, `exec-observer-common` 28,
`exec-observer` (Daemon) 86 (87 mit Feature `cap-matrix`) – davon
`resolve_argc` als der einzige Host-Beleg für Kriterium 10.
`ARGC_LIMIT`: **1024** (`exec-observer-ebpf/src/main.rs`).