# TODO – Sitzungsanker exec-observer

Stand: 12. Oktober 2026 (aktualisiert nach Läufe-Auswertung: Locale,
Überlauf-`.err`, `--caps`-Feature, DESIGN-Belege).
Prüfung: lesend als normaler Nutzer, keine Ausführung, kein `sudo`.

Statusbegriffe:

- `erledigt`: geforderte Änderung ist im Code vorhanden und statisch geprüft.
- `offen`: geforderte Änderung fehlt oder ist nachweislich falsch/unvollständig.
- `ungeprüft`: Änderung ist geschrieben, aber der Root-/Laufzeitbeleg fehlt.
- Nach der Sitzungsregel wird ein bloß statisch geprüfter Laufzeitbeleg nicht als
  abgeschlossener Testnachweis gemeldet.

## Sitzungsregeln

- Ich führe nichts mit `sudo` aus; Root-Befehle werden nur genannt.
- Jedes `rm -rf` lautet `rm -rf -- "${var:?}"` und betrifft nur mktemp-Verzeichnisse.
- `kill` trifft nur die eigene, verifizierte Daemon-PID; kein `pkill`.
- Testergebnisse werden als `erwartet / gemessen` berichtet.
- Belegtes und Annahmen werden getrennt genannt.
- Nichts hinzufügen, was nicht verlangt ist.

## a) CapInh-Befund

- Ursache `CAP_WAKE_ALARM`/Bit 35 dokumentiert: `erledigt`.
  - `DESIGN.md:91-120`, `DESIGN.md:122-136`.
  - `tests/cap-matrix.sh:22-30`.
- Host-Test für Wortzusammensetzung Bits 31, 32, 35, 38, 39, 40: `erledigt`.
  - `exec-observer/src/main.rs:2246-2279`.
- Matrix startet mit `--inh-caps=-all`: `erledigt`.
  - Direkte Starts in `tests/cap-matrix.sh:252-255`, `tests/cap-matrix.sh:511-512`.
  - `tests/integration.sh:205-206`.
  - Ausnahme nach Auftrag: Fall `f` mit `--inh-caps=+wake_alarm`.
- Kein fester Sollwert für `vorhanden`: `erledigt`.
  - `tests/cap-matrix.sh:645-658`, `tests/cap-matrix.sh:690-714`.
- Verbleibend: Root-/Laufzeitbeleg ist `ungeprüft`.

## b) cap-matrix.sh

- Fall `c` mit `CapabilityBoundingSet`: `offen`.
  - Abweichung: `tests/cap-matrix.sh:294-306` ist auskommentiert.
  - Auswertung `c`/`d2` ebenfalls: `tests/cap-matrix.sh:660-688`.
  - Begründung im Code: flaky/systemd-Units.
- Fall `0711`: geschrieben, `ungeprüft`.
  - `tests/cap-matrix.sh:384-395`, Auswertung `tests/cap-matrix.sh:787-788`.
- Fall `setuid`: geschrieben, `ungeprüft`.
  - `tests/cap-matrix.sh:396-405`, Auswertung `tests/cap-matrix.sh:789-790`.
- Fall `dumpable`: geschrieben, `ungeprüft`.
  - `tests/cap-matrix.sh:406-417`, Auswertung `tests/cap-matrix.sh:791-796`.
- Überlauf mit `kill -STOP`: `teilweise erledigt`.
  - Erfolgreiche Starts werden gezählt; Auswertung nach dem Stopp aus Senke
    plus `--stats` (geschrieben+lost==kernel_seen).
  - Der alte Extraktionsfehler (`case "$out"` auf Dateinamen) ist behoben.
  - Root-Lauf weiterhin `ungeprüft`.
- Tabelle Menge × Fall: geschrieben, `ungeprüft`.
  - `tests/cap-matrix.sh:822-840`, Logik `tests/cap-matrix.sh:744-801`.
- Empfehlung der Minimalmenge, getrennt nach belegt/Annahme: `erledigt`.
  - `DESIGN.md:9-26`, `DESIGN.md:28-89`, `DESIGN.md:170-184`.
  - Einschränkung: einige als belegt bezeichnete Root-Aussagen können im
    derzeitigen Stand wegen deaktiviertem Fall `c` nicht erneut belegt werden.

## c) integration.sh

- `krit`-Fehler, angeblich Zeile 427: statisch geprüft, kein Fehler gefunden.
  - Abweichung: aktuelle `krit()` steht in `tests/integration.sh:134-142`.
  - Zeile 427 ist Python-Hilfscode, keine `krit`-Funktion.
  - Die Auswertung ist gegen leere/fehlgeschlagene Python-Ausgabe gehärtet:
    `tests/integration.sh:700-703`.
- Exit-Codes `UNVOLLSTÄNDIG=2`, Fehler=`1`: `erledigt`.
  - `tests/integration.sh:63-67`, Vorbedingungen `tests/integration.sh:118-124`,
    Auswerteabbruch `tests/integration.sh:700-703`,
    Endergebnis `tests/integration.sh:734-738`.
- Selbsttest des Berichtspfads: `erledigt`.
  - `tests/temp-selftest.sh:1-94`.
  - Abweichung: Kommentar sagt acht Pfade, geprüft werden neun:
    `tests/temp-selftest.sh:12`, `tests/temp-selftest.sh:44-54`.
- `trunc_exec` mit Verzeichnisrechten: `erledigt`.
  - Separates Deep-Verzeichnis: `tests/integration.sh:175-188`.
  - Eigentum für den Helfer: `tests/integration.sh:322-327`.
- Temp-Liste ohne Unterschale: `erledigt`.
  - `tests/lib-temp.sh:1-34`.
  - Verwendung ohne `$()`: `tests/integration.sh:175-178`.
- `KEEP=1`: `erledigt`.
  - Dokumentation: `tests/integration.sh:15`.
  - Erhalt im Cleanup: `tests/integration.sh:89-95`.
- Bei `FAIL` Senkenzeilen und stderr ausgeben: `erledigt` (B6 neu gefasst).
  - Strukturierter CTX-Kontext aus der Auswertung (höchstens 8 Trefferzeilen
    + Zeilenzahl je PID), keine Kopf/Ende-Auszüge mehr; CTX-Zeilen füttern
    weder pass noch fail noch skip.
  - Die frühere `dump_failure_context`-Funktion (head/tail) ist entfallen.
- Verbleibend: Root-/Laufzeitbeleg ist `ungeprüft`.
- Hinweis: Zeilenangaben in diesem Abschnitt stammen aus einer früheren
  Revision; Inhalte wurden per `grep`/`bash -n` gegen den aktuellen Stand
  verifiziert.

## d) Hash-Tests

- Lebende Ziele für Urteile: geschrieben, `ungeprüft`.
  - `/bin/sleep 3` für Hash/Cache: `tests/integration.sh:268-278`.
  - memfd mit lebendem `/bin/sleep`: `tests/integration.sh:280-288`.
  - `deleted_exec /bin/sleep 3`: `tests/integration.sh:340-345`.
- Kurzlebige Fälle als Messzeilen: geschrieben, `ungeprüft`.
  - 200 Starts je Ziel: `tests/integration.sh:382-402`.
  - Zustandszähler ohne Bewertung: `tests/integration.sh:635-653`.
- Quote `2 bis 3 %, enge Schleife` in `SCHEMA.md`: `offen`.
  - Abweichung: `SCHEMA.md:109-118` verlangt ausdrücklich erst den Root-Lauf
    und nennt keine belastbare Prozentzahl.

## e) fd_exec-Flag

- Erkennung für `/dev/fd/` und `/proc/self/fd/`: `erledigt`.
  - `exec-observer/src/main.rs:317-331`.
- `SCHEMA.md`: `erledigt`.
  - `SCHEMA.md:129-130`, `SCHEMA.md:162-167`.
- Host-Tests: `erledigt`.
  - `exec-observer/src/main.rs:1731-1812`.
  - `exec-observer-common/src/lib.rs:715-753`.
- Verbleibend: Root-/Laufzeitbeleg ist `ungeprüft`.

## f) --stats

- Verzögerung `ts_boot` bis Öffnen von `/proc/<pid>/exe`: `erledigt`.
  - Messpunkt und Berechnung: `exec-observer/src/main.rs:688-701`.
- Min/Median/P99/Max in Mikrosekunden, getrennt nach Zustand: `erledigt`.
  - `exec-observer/src/main.rs:799-841`.
- Nur stderr, Strom unverändert: `erledigt`.
  - `exec-observer/src/main.rs:757`, `exec-observer/src/main.rs:1589-1592`.
- Öffnen als Erstes in der Verarbeitung: `erledigt`.
  - Reihenfolge: `exec-observer/src/main.rs:657-663`,
    `exec-observer/src/main.rs:703-712`.
- Host-Tests für Zählung, Deaktivierung, Perzentile und Renderformat: `erledigt`.
  - `exec-observer/src/main.rs:2309-2387`.
- Verbleibend: Root-/Strombeleg ist `ungeprüft`.

## Empfohlene Reihenfolge 1–5

1. `run_case`-Überlaufextraktion, `memfd`-Argument, SHORT-Argumente und
   Überlauf-Erhaltung: `teilweise erledigt`.
   - `run_case`-Extraktionsfehler (Dateiname statt Inhalt) behoben:
     Auswertung nach dem Stopp aus Senke + `--stats`.
   - `case_doverflow` zählt erfolgreiche Starts, Gleichung
     geschrieben+lost==kernel_seen (B4).
   - `cap-matrix.sh` nutzt `set -o pipefail`.
   - `memfd_exec` bereits auf `argv[3]` korrigiert.
   - SHORT-Aufrufe statisch unauffällig.
   - Offen: PID-Identitätsprüfung in `cap-matrix.sh`, B5-Builtin-Waits dort.
2. PID-Identitätsprüfung in `cap-matrix.sh` und `set -o pipefail`: `teilweise`.
   - `pipefail` erledigt; PID-Identität offen.
3. Tracepoint-ABI, `ARGS`-Alter/Sequenz und Ringkapazität als Obergrenze: `offen`.
4. Senken-Allowlist beziehungsweise Instanzsperre, Hash-Arbeitspfad und
   Shutdown-Drain: `teilweise`.
   - Shutdown-Drain erledigt (B4/Entscheidung 7); Rest offen.
5. Build-Toolchain pinnen, Testartefakte entfernen, Doku-/Zählerstellen
   konsolidieren: `offen`.

## Läufe-Auswertung (Punkte 1–4) – umgesetzt, Läufe durch Nutzer offen
1. Locale: Hypothese bestätigt (`${EPOCHREALTIME%%.*}` scheitert am Komma).
   `LC_ALL=C` in beiden Skripten; `tests/lib-time.sh` neu (now_s schneidet `.`
   und `,` ab); Abbruchpfad mit Zeit + Daemon-stderr + Daemon-Exit;
   rootloser `tests/locale-selftest.sh` (skip ohne de_DE.UTF-8).
2. Überlauf-`.err`: `--stats` gibt `kernel_seen/geschrieben/lost` aus (B4
   umgesetzt, Format `kernel_seen=N geschrieben=N lost=N`). Fund:
   `eval_overflow` las `$CUR_SINK.err` (existiert nie), Daemon-stderr liegt in
   `$TMPROOT/<set>-<fall>.err` → jetzt `CUR_ERR`. Danach Überlauffall je Menge
   durch Nutzer neu fahren (`ONLY_CASE=over`, Filter neu).
3. `--caps=`-Testoption (Feature `cap-matrix`, nicht im normalen Build):
   Override der Zielmenge nach dem Laden; Host-Test für Parser geschrieben;
   Menge unverändert bis zum Ergebnis. Erwartung: Map-Lesen ohne `CAP_BPF`
   scheitert. Nutzer baut mit `--features cap-matrix` und fährt
   Zielmenge `--caps=ptrace,dac` + Überlauftest.
4. DESIGN.md: SYS_PTRACE/DAC_READ_SEARCH/PERFMON als belegt; root-ohne-ptrace
   als beobachtet+Annahme; BPF-Laufzeit offen; Kernel/ptrace_scope-Hinweis.

## Identitäts-Planänderung (ino/size) – umgesetzt, Root-Lauf ungeprüft

- Messung übernommen: btrfs-Mount `0:35`, Datei-`st_dev` `0:37` → `(dev,ino)`
  verworfen, `(ino,size)` umgesetzt.
- BTF-Felder live aufgelöst (alle 6): `task_struct.mm` @2744,
  `mm_struct.exe_file` @1528 (Randstruct-Hülle, anonyme Rekursion im Walker),
  `file.f_inode` @32, `inode.i_ino` @64, `inode.i_size` @80.
  OFFSETS-Map 7 → 12, fail-closed.
- ABI: `exe_ino`/`exe_size`/`has_exe_ident`, 328 B → 352 B, 744 Plätze.
- Daemon: `resolve_exe_identity` (rein, host-getestet) vor Cache/Hash;
  `superseded` (sha null), `unreadable` + `ident_missing` ohne Sensor-Identität.
- SEEN-Map, `geschrieben`-Zähler, Shutdown-Drain, `--stats`-Erhaltung.
- SCHEMA.md: `reused` korrigiert, `superseded` + Kettenhinweis + Changelog
  (FORMAT 2) + Limitationen.
- Entscheidungen 1–8 alle umgesetzt (BASH_VERSINFO-Check, K13-Kettenlänge,
  target-Kommentar, setpriv Systemstufe, Pfad+uid-Filter).
- TESTS a–d und B1–B6 in `tests/integration.sh` geschrieben (K23–K27, Phasen
  H/I, private Kopien, Builtin-Waits, CTX-Fehlerkontext).
- Host-Belege grün: Daemon 82, Common 28, uapi 8 Tests; `bash -n` sauber;
  Python-Auswertung per synthetischen Senken geprüft (K8/K9/K13/K23–K27 PASS).
- Offen: kompletter Root-Lauf (`sudo tests/integration.sh`,
  `sudo tests/cap-matrix.sh`).

## Überlauf-Erhaltung: Befund-Ledger (geordnet, ohne Spekulation)

Methode: Jede Zeile braucht einen Beleg oder das Etikett Annahme. Die
Interleave-Hypothese aus dem vorigen Stand wird hiermit auf Annahme
zurückgestuft — sie erklärt alles und beweist nichts.

### Gemessen (over-Fall, `geschrieben+lost` vs. `kernel_seen`)

| Lauf | s1 | s2 | s3 | s4 |
|---|---|---|---|---|
| 1 (Matrix) | 0 | −1 | 0 | −1 |
| 2 (Matrix) | 0 | −1 | 0 | −1 |
| 3 (ONLY_CASE) | 0 | −1 | 0 | −1* |
| 4 (ONLY_CASE) | 0 | −1 | 0 | −1 |
| 5 (ONLY_CASE) | 0 | −1 | 0 | −1 |
| 6 (ONLY_CASE) | 0 | 0 | 0 | 0 |

(* Lauf 3, s4: Anzeige-Zahlendreher; `ok`+Verhältnis stimmen für −1.)
0 = Gleichung exakt (Verhältnis 1.000); −1 = genau eins fehlt.

### Bewiesen (Codebeleg)

- Doppelzählung behoben und bestätigt (s1/s3-Verhältnis 1.000 statt 2.000).
- Submit-Seite kann die Gleichung nicht brechen: jedes gesendete Ereignis
  wird genau einmal geschrieben (Pfad-Enumeration im Code).
- Daemon-Differenzen und Per-CPU-Summen je genau einmal (kein Faktor 2).
- Jeder `process()`-Fehler hinterlässt „übersprungen“ in stderr.
- BPF-Laufzeit widerlegt (`over_nobpf`: null Caps, volle Funktion, exakt).

### Bewiesen falsch (durch Lauf 6)

- „Deterministischer Zählfehler“ (wäre immer da).
- „Reiner µs-Zufalls-Race mit kleiner Trefferquote“ (träfe nicht 5× nur s2/s4).

### Offen (genau eine Frage, keine Theorie)

Wo bleibt in s2/s4-Läufen 1–5 je ein Versuch? Kandidaten unbewertet
nebeneinander: Post-Converge-Ankunft, Senken-Schreibfehler, Consumer-Seite.
Diskriminierend ist ausschließlich das KEEP=1-Experiment (Strom-Zeilen vs.
`geschrieben`, Strom-`lost` vs. `lost`, `.err`-Grep) — alles andere ist
derzeit Meinung, inklusive meiner eigenen Interleave-Überlegung.

### Stärkste Hypothese (falsifizierbar durch Rerun, kein Code-Raten mehr)

Beim Gegenlesen gefunden und sofort behoben (Hauptschleife, ererbter
Flüchtigkeitsfehler): `while let Some(item) = next()` + Abbruch *nach* dem
Holen verwarf ein bereits geholtes, unverarbeitetes Ereignis still (in SEEN,
nie geschrieben, nie in DROPS). Kausalkette zum −1: Vor `stop_daemon_now`s
TERM spawnt `run_case` deterministisch ~4 Harness-Prozesse (tr/cut/head);
mit ptrace drainen diese langsam (Hash-Versuche an lebenden Zielen), ohne
schnell. Trifft TERM mitten im Drain mit ≥2 Items Rest, geht exakt EINS
verloren — der Rest wird vom Konvergenz-Drain gerettet. Das erklärt Menge
(ptrace-Korrelation über Drain-Geschwindigkeit), Ausmaß (genau 1) und
Lautlosigkeit — und Lauf 6 als Scheduling-Jitter. Fix: Stopp *vor* dem Holen
prüfen (`while !STOP` + `let-else`); danach kann ein −1 nicht mehr von hier
kommen. Falsifikation: `ONLY_CASE=over`-Rerun — s2/s4 grün ⇒ bestätigt;
−1 bleibt ⇒ Hypothese tot, zurück zum KEEP=1-Experiment.

### Nachgereicht: aya-RingBuf-Audit (vorbestehende Schicht, kein eigener Code)

Anlass: Der Fehler könnte vor dem eigenen Einsatzzeitpunkt in
nicht-verifizierten Grundlagen sitzen. Geprüft: `aya 0.14`
`maps/ring_buf.rs` (`ProducerData::next`, `read_item`, `consume`).

- `Item::Discard` wird still übersprungen — korrekt, denn das sind NUR
  unsere eigenen `entry.discard(0)`-Reservierungen, und jede davon zählt der
  Wrapper in DROPS (Erhaltung intakt).
- `Item::Busy` liefert `None` („sieht leer aus“), verbraucht aber nichts;
  der Konvergenz-Drain holt solche Einträge in der nächsten Runde. Einzige
  Lücke: busy-zum-Abbruchzeitpunkt (nachgewiesen nur als Möglichkeit, kein
  Beleg).
- Stilles Überspringen gültiger Einträge gibt es im Consumer nicht;
  Producer-Seite (`reserve`/`submit`/`discard`) kennt nur Zählbares.
- Damit ist die Bibliothek als stille Verlustquelle entlastet; Kernel-Seite
  (`ringbuf.c`) bleibt Annahme (keine Quellen installiert).
- Dabei nebenbei belegt: dumpable/setuid brauchen `SYS_PTRACE` (DESIGN
  nachgetragen); Fall-a-Fehlermeldung nennt jetzt die `SEEN`-Map.
- Wichtig: `ONLY_CASE=`/`MATRIX_BPF_TEST=` via `sudo` fallen weg (env_reset);
  Aufruf mit `sudo env ...`.
