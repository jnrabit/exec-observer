# Testreihe: vom billigen Beweis zum teuren

Prinzip: aufsteigende Kosten. Jede Stufe hat eine Vorhersage — scheitert sie,
stoppt die Reihe (kein teurer Lauf auf fauligem Fundament). Zugehörigkeit zum
Stern: Stufe 1 ist der Stern-Test, Stufe 3 rotiert die Nabe.

## Stufe 0 — ohne Root (jederzeit, ~3 min)

| Nr | Befehl | Vorhersage | Bei FAIL |
|---|---|---|---|
| 0.1 | `cargo test -p exec-observer -p exec-observer-uapi -p exec-observer-common` | 86 + 28 + 8 grün | Baum faulig — kein Root-Lauf |
| 0.2 | `cargo test -p exec-observer --features cap-matrix` | 87 grün | dito |
| 0.3 | `bash tests/locale-selftest.sh` | grün oder SKIP mit Grund | Locale-Härtung kaputt |
| 0.4 | `bash tests/temp-selftest.sh` | 7 pass | Temp-Verwaltung kaputt |

## Stufe 1 — Integration, vollständig (der Stern-Test)

```bash
cargo build -p exec-observer
gcc -O2 -Wall -Wextra -pthread tests/exec-cases.c -o tests/exec-cases.bin
sudo tests/integration.sh
```

| Vorhersage | Bedeutung |
|---|---|
| K13 PASS (Gleichung exakt) | Erhaltungs-Speichen halten auch in Integration |
| K23/K24 PASS | **IDENT-Speiche kippt auf belegt** (Sensor füllt zur Laufzeit) |
| Keine andere Speiche bricht | Stern-Form bestätigt |

Zu posten: Matrix + Auffälligkeiten. K23/K24 FAIL ⇒ IDENT-Speiche falsch
(Sensor füllt nicht wie angenommen). K13 FAIL ⇒ Gleichung neu aufmachen.

## Stufe 2 — Matrix-Regression (Fix-Nachweis wiederholen)

```bash
sudo env ONLY_CASE=over tests/cap-matrix.sh
```

Vorhersage: alle vier Mengen exakt (zweite Bestätigung nach Lauf 7, dass das
−1 nicht zurück ist). Bei erneutem −1: Ledger-Zeile, kein Code-Raten.

## Stufe 3 — Rotation Capability (nur nach Freigabe)

Voraussetzung: Entscheidung, `CAP_BPF` aus der Laufzeitmenge zu streichen.
Dann durch mich: `KEEP_WANTED` verengen, Masken/Tests/Doku anpassen, danach:

```bash
sudo tests/cap-matrix.sh   # voll, alle Fälle
```

Vorhersage: gleiche Belege bei kleinerer Menge (neue Nabe:
Minimale Capability-Menge).

## Entfallen (mit Grund, nicht vergessen)

- KEEP=1-Dreifachvergleich: Fall geschlossen (consume-then-break belegt).
- `over_nobpf`-Wiederholung: zweimal exakt, Hypothese widerlegt.

## Offene Ränder (manuell, keine Reihe)

- K10 (`reused`, nur manuell reproduzierbar, bleibt SKIP).
- Matrix-Fall c/d2 (systemd, deaktiviert/flaky).
