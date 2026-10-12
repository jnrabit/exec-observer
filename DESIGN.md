# DESIGN – Capability-Mindestmenge des Exec-Beobachters

Stand: 11. Oktober 2026 · Fassung zu `tests/cap-matrix.sh`
Dieses Dokument sagt, **welche Capabilities der Daemon braucht, warum, und
welche Regeln für das Starten gelten**. Getrennt nach *durch Test belegt* und
*Annahme*. Geprüft wird es in `tests/cap-matrix.sh`; was dort noch aussteht,
ist unten ausdrücklich markiert.

## 1. Empfehlung

**Zwei Mengen, auseinanderhalten:**

| Phase | Menge | Maske |
|---|---|---|
| **Start/Laden** | `CAP_BPF` + `CAP_PERFMON` (+ was der Betrieb will) | `0x000000c000000000` |
| **danach (Laufzeit)** | `CAP_SYS_PTRACE` + `CAP_DAC_READ_SEARCH` + `CAP_BPF` | `0x0000008000080004` |

Der Daemon lädt eBPF-Objekte erst und reduziert sich **danach** selbst
(`restrict_capabilities`, noch vor der `start`-Zeile). Was zum **Laden** nötig
ist, kann er daher hinterher abgeben — es muss nur beim Start da sein.

Der Daemon startet mit **mehr**, wenn er mehr bekommt, und reduziert sich
selbst auf `Mindestmenge ∩ vorhanden` (`capability_target` in
`exec-observer/src/main.rs`). Abbruch, wenn `capset` fehlschlägt oder die
erreichte Menge von der Zielmenge abweicht — nie ein Weiterlaufen mit mehr
Rechten als vorgesehen.

## 2. Begründung je Capability

### `CAP_BPF` — **belegt zum Laden; zur Laufzeit widerlegt (nicht nötig)**

| Beleg | Quelle |
|---|---|
| Ohne `CAP_BPF` startet der Daemon **nicht**: `Ebpf::load` scheitert schon beim Anlegen der Maps (`Error: "eBPF laden: map error: failed to create map `ARGS`"`), Exit ≠ 0, keine `start`-Zeile. | Root-Lauf, `cap-matrix.sh` Fall a |
| **Laufzeit NICHT nötig (Experiment Punkt 3):** Zielmenge `--caps=ptrace,dac` bei Startmenge s1 (`bpf+perfmon`) ⇒ Schnittmenge **leer** — der Daemon lief mit **null Capabilities** voll funktionsfähig: start-Zeile, komplette Verarbeitung, `--stats` mit exakter Erhaltung (759+622=1381). Das Lesen bestehender `DROPS`/`SEEN`-Maps über `bpf()` braucht auf diesem System **kein** `CAP_BPF`. | Root-Lauf, `over_nobpf` (Feature-Build) |

Konsequenz (noch nicht umgesetzt, Entscheidung ausstehend): `CAP_BPF` könnte
aus der Laufzeitmenge fallen (`KEEP_WANTED` → `ptrace+dac`). Das ändert Masken,
Matrix-Erwartungen und Host-Tests — erst nach expliziter Freigabe.

### `CAP_SYS_PTRACE` — **belegt**

| Beleg | Quelle |
|---|---|
| Ohne `CAP_SYS_PTRACE` ist `/proc/<pid>/exe` eines Prozesses **anderer uid** nicht lesbar → `hash_state: "unreadable"`, `sha256: null`. | Root-Lauf, Fall e (Menge `bpf, perfmon, dac_read_search`) |
| Gegenprobe bestanden: **mit** `SYS_PTRACE` (s2/s4) → lesbar/`ok`, **ohne** (s1/s3) → `unreadable`. | Root-Lauf, `cap-matrix.sh` Teil 2, Fälle `a1000`/`aroot` |
| Grund: `ptrace_may_access` verlangt bei uid-Abweichung `CAP_SYS_PTRACE`. | Kernel-Regel |
| Die dumpable-Regel greift **unabhängig von der uid**: setuid-Prozesse, `PR_SET_DUMPABLE=0`, und vom Kernel bei nur-ausführbaren Dateien (Modus 0711) gesetztes `dumpable=0`. | Verhaltensmatrix-Fälle c und b, **belegt** (s2/s4 ok, s1/s3 unreadable) |

### Beobachtet, Ursache ungeklärt: root-Prozess ohne `SYS_PTRACE` unlesbar

Auch bei **gleicher uid (root→root)** ist ohne `CAP_SYS_PTRACE`
`hash_state: "unreadable"` beobachtet (Fall `aroot`, s1/s3). Hypothese
(Annahme, nicht belegt): Die `ptrace`-Prüfung (`PTRACE_MODE_READ_FSCREDS`)
verlangt, dass der Beobachter die Rechte des Ziels **besitzt** – nicht nur,
dass die UIDs übereinstimmen. Ohne `SYS_PTRACE` besitzt ein (reduzierter)
Root-Prozess sie nicht.

### `CAP_DAC_READ_SEARCH` — **belegt**

*Begründung:* Der Hash entsteht über `open("/proc/<pid>/exe")`, das am
Ziel-Inode die Leserechte prüft. Weltlesbare Binärdateien (Modus 0755) lassen
sich als uid 0 ohne jede Capability lesen; eine **nur ausführbare** Datei
(0711: Eigentümer `rwx`, Gruppe/Andere `--x`) dagegen nicht — Dafür braucht es
`CAP_DAC_READ_SEARCH`, weil `CAP_DAC_OVERRIDE` (das sonst als uid 0 griffe)
abgegeben wird.

*Beleg:* Verhaltensmatrix-Fall b (Kopie von `/bin/sleep`, uid 1000, Modus 0711,
Prozess läuft): s2 (ohne `DAC_READ_SEARCH`) → `unreadable`; s4 (mit) → `ok`.
Fällt die Anforderung „Hash auch für nicht-weltlesbare Ziele" weg, kann die
Capability entfallen — `hash_state: "unreadable"` für solche Ziele wäre dann
das ehrliche Ergebnis.

### `CAP_PERFMON` — **belegt: nur zum Laden nötig, danach entbehrlich**

| Beleg | Quelle |
|---|---|
| Startmenge `{bpf, sys_ptrace, dac_read_search}` **ohne** `PERFMON` → der Ladevorgang scheitert: `LoadError { io_error: Os { code: 1, kind: PermissionDenied … } }`, keine `start`-Zeile. | Root-Lauf, `cap-matrix.sh` Fall f (vor der Korrektur) |
| Dieselbe Menge **mit** `PERFMON` startet (Fälle b/c/e, jeweils `{bpf, perfmon, …}`). | Root-Lauf |
| Nach dem Laden wird es nicht behalten (`Eff/Prm = 0x8000080004` ohne `PERFMON`), der Daemon arbeitet weiter („lauscht"). | Root-Lauf |

Konsequenz: `PERFMON` gehört in die **Start**menge, nicht in die Laufzeitmenge.
In der Verhaltensmatrix (`cap-matrix.sh` Teil 2) haben deshalb **alle** Mengen
`bpf + perfmon`; unterschieden wird über `sys_ptrace` und `dac_read_search`.

### `CAP_SETPCAP` — **belegt nicht nötig**

Fehlt in der Mindestmenge. Dann kann der Daemon das Bounding-Set nicht
beschneiden (`PR_CAPBSET_DROP` → `EPERM`, das ist ein Kernel-Verbot, kein
Fehler). Ohne Kindprozesse ohne Belang: die Macht des Prozesses kommt aus
Effektiv/Permitted, die `capset` reduziert hat; neue Capabilities könnte nur
ein `execve` geben — das tut der Daemon nie (siehe 4.).

### Ausdrücklich **nicht** benötigt

`CAP_DAC_OVERRIDE` (kein Schreiben auf fremde Dateien; das Lesen deckt
`DAC_READ_SEARCH`), `CAP_SYS_ADMIN`.

Nicht benötigt **zur Laufzeit**, aber benötigt **zum Laden**: `CAP_PERFMON`
(siehe oben).

## 2a. „vorhanden" umfasst auch die geerbte Menge

Die Diagnosezeile des Daemons (`Capabilities: vorhanden=0x… → Ziel=0x…`)
nennt das **Permitted-Set des laufenden Prozesses** – und das entsteht bei
`execve` neu, nicht durch einfaches Vererben:

> Bei `execve` einer Datei **ohne** Datei-Capabilities durch einen
> **Root**-Prozess gilt `F(inheritable) = alle Caps`. Das *Inheritable-Set des
> Aufrufers* geht also in das *Permitted-Set des Kindes* über; das
> Bounding-Set kürzt nur, was NEU hinzukommen könnte, nicht das Geerbte.

**Gemessen:** Die systemd-Benutzersitzung hinterlässt `CAP_WAKE_ALARM` (Bit 35)
im Inheritable-Set (`CapInh: 0000000800000000`; `setpriv --dump` zeigt
`Inheritable wake_alarm`). Deshalb meldete der Daemon unter
`--bounding-set=-all,+bpf,+perfmon,+sys_ptrace,+dac_read_search`
`vorhanden=0xc800080004`, während das Bounding-Set `0xc000080004` war — der
Unterschied ist exakt Bit 35. In einer User-Namespace nachgestellt; mit
`setpriv --inh-caps=-all` wird `Permitted == Bounding` exakt
(`0x000000c000080004`).

Konsequenzen:

* **Keine Sollwerte für „vorhanden" eintragen.** Der Wert hängt von der
  aufrufenden Umgebung ab und wird nur **gemessen**; geprüft wird allein die
  Konsistenz: `Eff == Prm == (Wunschmenge ∩ vorhanden)`, `CapInh = 0`,
  `CapAmb = 0`. Genau das tut `restrict_capabilities` zusätzlich, indem es
  `Inheritable` auf 0 setzt — das Erbe verschwindet damit aus dem Daemon.
* Tests starten den Daemon deshalb mit `setpriv --inh-caps=-all`, außer im
  Fall „Sitzung mit geerbtem Recht" (`--inh-caps=+wake_alarm`), der genau
  diesen Pfad prüft: erwartet `CapInh = 0` und die Zielmenge unverändert.

## 3. Regeln für die Bounding-Menge

1. **Bounding-Set = genau die Mindestmenge** (nicht mehr). Dann ist das
   Ergebnis exakt: `Permitted` nach dem Start entspricht dem Bounding-Set, und
   es gibt nichts, was der Daemon „wegwerfen" müsste.
2. **Inheritable-Set des Aufrufers leeren.** Bei `execve` einer Datei ohne
   Datei-Capabilities durch einen Root-Prozess gilt `F(inheritable) = alle
   Caps`; das Inheritable-Set des Aufrufers geht also in das Permitted-Set des
   Kindes über. Die systemd-Benutzersitzung hinterlässt dort `CAP_WAKE_ALARM`
   (Bit 35) — der Daemon meldete deshalb einmal `vorhanden=0xc800080004` bei
   einer Bounding-Menge von `0xc000080004`. In `tests/cap-matrix.sh` erledigt
   das `setpriv --inh-caps=-all` (Reihenfolge: erst `--inh-caps`, dann
   `--bounding-set` — umgekehrt entfernt das Bounding-Set `CAP_SETPCAP` und das
   Hinzufügen scheitert). In einer User-Namespace nachgestellt: mit
   `--inh-caps=-all` ist `Permitted == Bounding` exakt (`0x000000c000080004`).
3. **Unter systemd `CapabilityBoundingSet=` *und* `AmbientCapabilities=` gemeinsam
   setzen.** Nur `AmbientCapabilities` lässt das Bounding-Setz voll — der Start
   ist dann nicht eingeschränkt (cap-matrix Fall d2 beschreibt genau das,
   absichtlich als „voller Start" gekennzeichnet).
4. **Regel Kindprozesse:** Der Daemon erzeugt zur Laufzeit **keine
   Kindprozesse und ruft kein `execve`** (kein `fork`/`Command`/`exec` im
   Runtime-Pfad; der einzige `fork` steht in einem Host-Test für den
   Zombie-Fall). Deshalb
   - kann das Bounding-Set keine zusätzlichen Rechte eröffnen,
   - **und** muss es nicht größer sein als die Mindestmenge.
   **Ändert sich das** — braucht der Daemon Kindprozesse oder ein `execve` —
   muss das Bounding-Set deren Rechte enthalten, sonst schlägt deren
   Rechtgebrauch fehl. Dann ist dieses Dokument und die Mindestmenge neu
   aufzustellen.

## 4. Startkontrakt (für Skript, systemd-Unit, Operator)

```
Start (werden nach dem Laden abgegeben, soweit entbehrlich):
  CAP_BPF             Anlegen der Maps
  CAP_PERFMON         Laden der Programme        (belegt: ohne ihn EPERM)
Laufzeit (behält der Daemon selbst):
  CAP_BPF             Lesen von DROPS/SEEN (widerlegt unnötig, aber bis zur
                      Mengen-Entscheidung behalten – s. §2)
  CAP_SYS_PTRACE      /proc/<pid>/exe fremder UID und gleicher UID (root→root), dumpable-Regel
  CAP_DAC_READ_SEARCH Inhalt nicht-weltlesbarer Binärdateien (belegt, s. o.)
Bounding-Set         = genau die Startmenge, nicht mehr
Inheritable/Ambient  = leer
```

Der Daemon reduziert sich nach dem Laden selbst auf `Mindestmenge ∩ vorhanden`
und meldet auf stderr, was er tat:
`exec-observer: Capabilities: vorhanden=0x… → Ziel=0x…`.

## 5. Was noch zu belegen ist

| Punkt | Zustand | wo |
|---|---|---|
| `SYS_PTRACE` → Hash uid-1000 lesbar (Gegenprobe) | **belegt** (s2/s4 Fall a1000 ok) | Teil 2, s2/s4, Fall a |
| `SYS_PTRACE` → Hash root→root lesbar (aroot) | **belegt** (s2/s4 ok, s1/s3 unreadable) | Teil 2, s2/s4, Fall aroot |
| root→root ohne `SYS_PTRACE` unlesbar: Ursache ungeklärt | **beobachtet** (Hypothese: ptrace-Prüfung verlangt Besitz der Zielrechte) | Fall aroot, s1/s3 |
| `DAC_READ_SEARCH` → Hash 0711-Datei lesbar | **belegt** (s2 unreadable, s4 ok) | Teil 2, s2/s4, Fall b |
| dumpable/setuid brauchen `SYS_PTRACE` | **belegt** (s2/s4 ok, s1/s3 unreadable) | Teil 2, Fall c |
| Überlauf/DROPS/SEEN brauchen `CAP_BPF` zur Laufzeit | **widerlegt** (`over_nobpf`: null Caps, volle Funktion, Erhaltung exakt) | Teil 2, Fall d |
| `PERFMON` **mit** `BPF` reicht zum Laden | **belegt** (Fälle b/c/e laufen) | Teil 1 b/c/e |
| `PERFMON` **ohne** `BPF` reicht zum Laden nicht (Maps) | **belegt** (Fall a: Map-Fehler) | Teil 1 a |
| `BPF` **ohne** `PERFMON` reicht zum Laden nicht (Programme) | **belegt** (Fall f: LoadError EPERM) | Teil 1 f |

Hinweis: Auf einem anderen Kernel oder mit anderem `ptrace_scope` können die
Ergebnisse abweichen – die Belege gelten für den Zielkernel und die dort
gemessene Konfiguration. Jede Zeile wird im nächsten `sudo tests/cap-matrix.sh`
entschieden; das Ergebnis gehört dann hier als *belegt* bzw. *widerlegt*
nachgetragen.
