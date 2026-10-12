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

## Überlauftest-Doppelzählung (lost == 2×) – Ursache behoben, Lauf offen

- Befund (8 Messungen, alle Mengen): `lost` ≈ 2 × (`kernel_seen` − geschrieben).
- Ursache belegt: Sensor zählte Reservierungs-Drops doppelt (innen in
  `try_sched_process_exec` UND im Wrapper bei `Err`). Andere Fehlerpfade
  (discard) einfach; Daemon-Differenz und Per-CPU-Summen je einmal
  (Hypothesen widerlegt, Codebeleg im Bericht).
- Fix: inneres `count_drop()` entfernt (Wrapper einzige Zählstelle).
- Härtung: `CounterDelta` (eine Summe je Lesung, 4 Host-Tests), Shutdown-Drain
  mit Konvergenz (9 Runden Deckel), Erhaltung exakt ohne Toleranz.
- Tests melden `lost/(seen−geschrieben)` (gesund 1.000).
- SEEN: keine Doppelzählung (ein `count_seen()` im Wrapper); Rauschen
  (System-Execs) fließt konsistent in alle drei Zähler ein.
- Lauf 12.10. (Matrix, `--features cap-matrix` baut sauber):
  s1/s3 `over` PASS mit Verhältnis 1.000 (Fix bestätigt);
  s2/s4 `over` FAIL mit exakt −1 (1381 vs 1382, Verhältnis 0.998).
  Resthypothesen: In-Flight-Race beim Endauslesen, Senken-Schreibfehler
  („übersprungen“), oder systematisch — Unterscheidungsexperimente offen
  (Wiederholung: wandert das −1 oder klebt es an ptrace-Mengen? KEEP=1 +
  `.err` auf „übersprungen“ prüfen; Strom-Zeilen vs. `geschrieben`).
- Dabei nebenbei belegt: dumpable/setuid brauchen `SYS_PTRACE` (DESIGN
  nachgetragen); Fall-a-Fehlermeldung nennt jetzt die `SEEN`-Map.
- Wichtig: `ONLY_CASE=`/`MATRIX_BPF_TEST=` via `sudo` fallen weg (env_reset);
  Aufruf mit `sudo env ...`.
