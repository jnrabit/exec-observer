# Stern statt Liste: Erhaltungsgleichung in der Mitte

**Stand: Entwurf, ungetestet.** Diese Darstellung ist selbst eine Hypothese
und gilt erst, wenn sie den Test unten besteht.

Nicht linear abgearbeitet, sondern als Abhängigkeitsstern: Die Mitte gilt
nur, wenn alle Speichen tragen. Status je Speiche: **belegt** (mit Quelle)
oder **offen** (mit dem einen Experiment, das sie entscheiden würde).

```mermaid
graph TD
    C["Erhaltung: geschrieben + lost == kernel_seen<br/>(exakt, keine Toleranz)"]
    C --- SEEN["SEEN zählt jeden Versuch genau einmal"]
    C --- DROPS["DROPS zählt jeden Verlust genau einmal"]
    C --- RING["Ring verliert nichts still"]
    C --- DRAIN["Drain holt alles"]
    C --- WR["geschrieben zählt jede Zeile"]
    C --- STATS["--stats meldet alle drei Stände"]
    C --- K13["K13 prüft die Gleichung"]
    C --- OVER["Matrix-over prüft je Menge"]
    C --- NOBPF["Funktion ohne CAP_BPF zur Laufzeit"]
    C --- IDENT["exe_ino/exe_size wird befüllt"]
```

## Speichen

| Speiche | Status | Beleg / offenes Experiment |
|---|---|---|
| SEEN zählt 1× | **belegt** | Pfad-Review (ein `count_seen` im Wrapper); `over_nobpf`-Gleichung exakt |
| DROPS zählt 1× | **belegt** | Doppelzähl-Fix; Verhältnis 1.000 in allen Läufen seitdem |
| Ring still verlustfrei | **belegt** + Annahme | aya-Audit: Discard = gezählt, Busy = transient; Kernel-Seite Annahme |
| Drain holt alles | **belegt** | Kein consume-then-drop mehr (Fix); Konvergenz; Lauf 7 grün |
| geschrieben zählt | **belegt** | Code + Host-Tests; Zähler nur nach erfolgreichem Emit |
| --stats meldet | **belegt** | K13-Parse + Läufe zeigen alle drei Zahlen |
| K13 prüft | **belegt** | Smoke-Test + Root-Läufe |
| Matrix-over | **belegt** | 7 Läufe, alle Mengen |
| ohne CAP_BPF | **belegt** | `over_nobpf`: null Caps, volle Funktion, exakt |
| exe_ino/exe_size | **offen (Laufzeit)** | Code-Seite belegt; Sensorfüllung erst durch Phase H (K23/K24) |

## Regel zum Stern

Falsifizierbarkeit vor Vollständigkeit gilt pro Speiche: Jede Speiche braucht
ihren eigenen Diskriminator (nicht: „passt zum Gesamtbild“). Eine neue
Beobachtung bricht genau die Speiche, die sie betrifft — der Rest des Sterns
bleibt stehen.

## Test des Sterns (ausstehend)

Der Stern beweist sich, indem er eine Vorhersage über neue Daten macht:

```bash
cargo build -p exec-observer
gcc -O2 -Wall -Wextra -pthread tests/exec-cases.c -o tests/exec-cases.bin
sudo tests/integration.sh
```

Vorhersage: K13 (Phase F) PASS, K23/K24 (Phase H) PASS — und genau dadurch
kippt ausschließlich die Speiche `exe_ino/exe_size` auf belegt; keine andere
Speiche darf brechen.

- K23/K24 FAIL ⇒ Speiche `exe_ino/exe_size` falsch (Sensor füllt nicht wie
  angenommen), Rest des Sterns unberührt.
- K13 FAIL in Integration ⇒ Speiche Erhaltung/Drain/Stats neu aufmachen.
- Brechen mehrere unbeteiligte Speichen ⇒ die Stern-Form selbst ist ungeeignet
  (zurück zur Liste).
