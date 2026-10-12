# Audit-Stand exec-observer — 12. Oktober 2026

Stand: Commit `6c44fa0` (Ledger-Prüfskript). Alle Aussagen wurden am Repo und
an den Testläufen dieses Tages geprüft. Was nur aus Protokollen oder Erinnerung
stammt, ist als solches markiert.

## 1. Kurzfassung

- **Host-Tests grün:** Daemon 86 (87 mit Feature `cap-matrix`), Common 28,
  Uapi 8. `cargo fmt --check` sauber. Alle Shell-Skripte bestehen `bash -n`.
- **Root-Belege vorhanden:** Capability-Matrix (Masken a/b/e/f, Verhalten
  s1–s4) und Überlauf-Erhaltung `geschrieben + lost == kernel_seen` sind in
  den letzten Läufen exakt (Verhältnis 1.000 in allen Mengen).
- **Nicht belegt:** Die Integrationsmatrix (`tests/integration.sh`, K1–K27)
  ist seit der Identitätsänderung (`exe_ino`/`exe_size`) nach Protokoll nicht
  vollständig gelaufen. Damit ist die Laufzeitfrage „Befüllt der Sensor die
  Identität und greift der Daemon-Vergleich?“ offen.
- **Größtes Risiko:** Die letzten Änderungen am Daemon (Hauptschleife,
  `CounterDelta`, Shutdown-Drain) sind belegt durch Host-Tests und die
  Matrix, nicht durch einen vollständigen Integrationslauf.

## 2. Belegt (mit Quelle)

| Aussage | Beleg |
|---|---|
| Erhaltung `geschrieben + lost == kernel_seen` | Matrix over-Fall, Läufe 6–8 exakt in allen Mengen |
| Doppelzählung behoben | Sensor: inneres `count_drop` entfernt; Verhältnis 2.000 → 1.000 |
| Consume-then-break behoben | Hauptschleife prüft Stopp vor dem Holen; Lauf 7 grün nach Fix |
| BPF zur Laufzeit nicht nötig | `over_nobpf`: Schnittmenge leer, Erhaltung exakt (zweimal) |
| SYS_PTRACE für fremde/Root-Hashes nötig | Matrix a1000/aroot: s2/s4 ok, s1/s3 unreadable |
| DAC_READ_SEARCH für 0711-Dateien nötig | Matrix b0711: s4 ok, s2 unreadable |
| dumpable/setuid brauchen SYS_PTRACE | Matrix setuid/dump: s2/s4 ok, s1/s3 unreadable |
| PERFMON nur zum Laden | Masken f: EPERM ohne, Start mit |
| BTF-Felder live auflösbar (alle 6) | Host-Test `parses_sysfs_and_finds_offsets` gegen die echte BTF |
| Locale-Härtung der Warte-Helfer | `locale-selftest.sh` 8/8 unter C und de_DE |
| Temp-Verwaltung ohne Leichen | `temp-selftest.sh` 7/7 |
| Ledger-Invarianten | `ledger/test_ledger.py` 6/6 (inkl. Waisen-Negativtest) |

## 3. Nicht belegt oder offen

| Punkt | Status | Was fehlt |
|---|---|---|
| Integrationsmatrix K1–K27 nach Identitätsänderung | offen | `sudo tests/integration.sh` |
| Sensorfüllung `exe_ino`/`exe_size` zur Laufzeit | offen | K23/K24 (Phase H) |
| Daemon-Vergleich `superseded` im Feld | offen | K23 (gleicher Lauf) |
| K10 `reused` (echte PID-Wiederverwendung) | offen, manuell | kein automatischer Test |
| Matrix Fall c (systemd) und d2 | deaktiviert | flaky, gewollt aus |
| Capability-Verengung (`CAP_BPF` raus?) | Entscheidung ausstehend | deine Entscheidung |
| PID-Identitätsprüfung in `cap-matrix.sh` | offen | aus der Empfehlungsliste |
| Tracepoint-ABI gegen Live-Format validieren | offen | Format-Datei war nicht lesbar |
| Senken-Allowlist / Instanzsperre | offen | Empfehlungsliste Punkt 4 |
| Build-Toolchain pinnen | offen | kein `rust-toolchain`-File, `Toolchain::Nightly` unversioniert |
| Kernel-Seite Ringbuf (`ringbuf.c`) | Annahme | keine Quellen installiert |
| Smoke-Test der Integrations-Auswertung | nur in `/tmp` | `/tmp/opencode/eval_smoke.py` ist nicht versioniert |

## 4. Risiken (nach Gewicht)

1. **Integration ungelaufen nach der größten Änderung.** Die Identitätsbefüllung
   im Sensor ist kompiliert und die Matrix läuft, aber die Phase, die sie
   beweisen würde, nicht. Ein Fehler dort bliebe unbemerkt, weil die übrigen
   Läufe ihn nicht auslösen.
2. **Auswertung der Integration nur gegen synthetische Daten geprüft.**
   Der Smoke-Test liegt außerhalb des Repos. Ein Fehler im echten Lauf wäre
   in der Auswertung nicht reproduzierbar.
3. **Lizenz CC BY-NC 4.0 für Software.** Lizenzrechtlich möglich, aber nicht
   der übliche Weg; Patent- und Kompatibilitätsklauseln fehlen. Das ist eine
   bewusste Entscheidung, sollte aber nochmal bestätigt werden.
4. **Ledger ist eine eingefrorene Kopie.** Änderungen am Kern in `collect2`
   fließen nicht zurück. Stand heute identisch (`diff` leer).
5. **Build nicht reproduzierbar gepinnt.** Der eBPF-Build hängt an der
   jeweils installierten Nightly.

## 5. Doku-Hygiene

- `TODO.md` ist aktuell (Kopf, Host-Zahlen, Ledger-Abschnitt).
- Veraltete Zeilenangaben in `TODO.md` (z. B. `main.rs:799-841`) verweisen auf
  frühere Revisionen. Inhalte stimmen, Zeilen nicht mehr.
- `SCHEMA.md` nennt 328 → 352 B und 799 → 744 Plätze. Das ist Changelog, kein
  Fehler.
- `AUDIT.md` ist ein historisches Kriterienprotokoll. Es ist in Teilen überholt
  (z. B. Integrationszeilen „geschrieben, nicht gelaufen“). Dieses Dokument
  ersetzt es nicht, sondern ergänzt es.
- Keine offenen TODO/FIXME-Marker im Rust-Code.

## 6. Empfehlungen (priorisiert)

1. **`sudo tests/integration.sh` laufen lassen** und das Ergebnis mit K23/K24
   zurückmelden. Das ist der einzige Schritt, der die größte offene
   Annahme entscheidet.
2. **Smoke-Test ins Repo** (`tests/eval_smoke.py` oder ähnlich), damit die
   Integrations-Auswertung versioniert und wiederholbar ist.
3. **Entscheidung `CAP_BPF`**: dokumentiert widerlegt, die Menge bleibt
   unverändert. Ohne deine Freigabe passiert nichts.
4. **Toolchain pinnen** (`rust-toolchain.toml`), sobald die Matrix stabil ist.
5. **Ledger** bei Bedarf synchronisieren oder bewusst eingefroren lassen. Ein
   Hinweis steht bereits in `TODO.md`.

## 7. Methodik und Grenzen

- Geprüft: Git-Historie, Testläufe, Skript-Syntax, Doku-Quervergleich,
  Ledger-`diff`.
- Nicht geprüft: Root-Läufe in diesem Audit (kein `sudo`), echte Kernel-Quellen,
  Verhalten auf anderen Kerneln oder mit anderem `ptrace_scope`.
- Die Aussagen zur Integration stützen sich auf das Protokoll dieser Sitzung.
  Ein Lauf außerhalb dieser Sitzung wäre dem nicht bekannt.
