# Schema v2 des Exec-Beobachters (JSON-Strom)

Version `0.1.0` · Format-Version `v = 2` (`exec-observer-common`).
Dieses Dokument ist die verbindliche Beschreibung des ausgegebenen JSON-Stroms
(eine Ereignis-Zeile pro Zeile, `\n`-terminiert) und der Abweichungen vom
ursprünglichen v1-Entwurf.

---

## 1. Ereignisarten (`ev`)

Geschlossenes Vokabular, feste Strings:

| `ev` | Bedeutung |
|---|---|
| `start` | Daemon gestartet (einmalig als erste Zeile); trägt `mid` + `kernel` |
| `exec` | Ein `execve`/`execveat` wurde beobachtet und erfolgreich am Ringpuffer abgelegt |
| `lost` | Mindestens ein Ereignis ging im Ringpuffer-Überlauf verloren (`count`) |
| `stop` | Daemon sauber beendet (letzte Zeile); trägt `mid` |

Für `lost`/`start`/`stop` fehlt das `exec`-Beispiel; alle Zeilen haben denselben
gemeinsamen Kopf.

## 2. Gemeinsamer Kopf (alle Ereignisse)

| Feld | Typ | Bedeutung |
|---|---|---|
| `v` | int | Schema-Version (fix `2`) |
| `seq` | int (≥ 0) | Lückenloser Zähler pro Lauf, erste Zeile `seq: 0` |
| `ts` | int | Zeitstempel in ns (siehe §5 Zeitbasen) |
| `wall` | int | Unix-Kalenderzeit in ns (Korrelation mit journalctl/SIEM) |
| `ev` | string | Ereignisart aus §1 |

## 3. Ereignis-spezifische Felder

### `start`
```json
{"v":2,"seq":0,"ts":…,"wall":…,"ev":"start","mid":"…","kernel":"…"}
```
- `mid` – Maschinen-/Boot-ID (Inhalt von `/proc/sys/kernel/random/boot_id`).
- `kernel` – Kerneltreiber-Version aus `/proc/sys/kernel/osrelease`.

### `exec`
```json
{"v":2,"seq":12,"ts":…,"wall":…,"ev":"exec","pid":123,"ppid":1,"uid":1000,"euid":1000,"comm":"bash","path":"/usr/bin/bash","argc":3,"sha256":"…64 hex…","hash_state":"ok","flags":["cached"]}
```
| Feld | Typ | Bedeutung |
|---|---|---|
| `pid` | int | Prozess-ID (TGID), aus `task_struct.tgid` |
| `ppid` | int | Parent-TGID, aus `task_struct.real_parent` |
| `uid` | int | Reale Benutzer-ID, aus `cred.uid` |
| `euid` | int | Effektive Benutzer-ID, aus `cred.euid` (z. B. `0` bei `sudo`) |
| `comm` | string | Task-Name (`TASK_COMM_LEN=16`, lossy zu UTF-8) |
| `path` | string | Vom Syscall übergebener Dateiname (lossy zu UTF-8, kann relativ sein) |
| `argc` | int \| `null` | Anzahl der Argumente; `null`, wenn unbekannt (z. B. usermodehelper) |
| `sha256` | `null` \| string | 64 Hex-Zeichen des ausgeführten Abbilds; `null`, wenn `hash_state ≠ ok` |
| `hash_state` | string | §4.1 |
| `flags` | string[] | §4.2, feste Reihenfolge |

#### `argc`-Semantik (Kriterium 11)

`argc` wird im eBPF-Sensor am Syscall-Eintritt durch Zählen der `argv`-Zeiger
ermittelt. Die Obergrenze ist `ARGC_LIMIT = 1024` (eBPF-Seite,
`exec-observer-ebpf/src/main.rs`).

| Fall | `argc` im Strom | Flag | Anmerkung |
|---|---|---|---|
| `n` Argumente, `n < ARGC_LIMIT` | `n` | – | exakter Wert |
| `n = ARGC_LIMIT` | `1024` | – | Terminator an Position `ARGC_LIMIT` geprüft (K1) |
| `n > ARGC_LIMIT` (z. B. 100.000) | `1024` | `argc_min` | Untergrenze, kein Verifier-Abbruch |
| leeres `argv` (`n = 0`) | `0` | – | Zählung am Eintritt |

**Bekannte Abweichung bei leerem `argv`:** Der Beobachter zählt am
Syscall-Eintritt `0` (die Zeile trägt `"argc":0`). Der Kernel fügt danach ein
leeres Argument ein; das ausgeführte Programm sieht `argc = 1`
(nachgemessen mit `tests/exec-cases.c argc_exec 0 …`). Der Strom zeigt damit
den *übergebenen* Wert, nicht den *im Zielprozess wirksamen*.

#### `deleted`-Zeitabhängigkeit (Kriterium 12b)

`deleted` wird **beim Verarbeiten** des Ereignisses aus `/proc/<pid>/exe`
bestimmt (`fs::read_link`), nicht beim Exec. Daraus folgt:

- Ein Update, das eine **bereits laufende** Binary ersetzt, erzeugt **kein**
  `deleted`: Die Exec-Zeile ist längst geschrieben, wenn das Ersetzen geschieht.
- `deleted` erscheint nur, wenn die Datei zum Verarbeitungszeitpunkt schon
  gelöscht/ersetzt ist – etwa wenn ein Programm seine eigene Datei direkt nach
  dem Start löscht oder über einen offenen Deskriptor auf eine bereits
  gelöschte Datei gestartet wird (`execveat(AT_EMPTY_PATH)`).
- **Wettlauf:** Ist der Verarbeiter schneller als das Löschen, fehlt das Flag.
  Der Testfall ist deshalb deterministisch gebaut
  (`exec-cases deleted_exec`): Die Kopie wird vor dem `execveat` gelöscht.
- Der `sha256` stammt aus dem offenen Deskriptor und ist vom Löschen
  unberührt; eine geänderte Datei wird (bis zur nächsten Änderung) korrekt als
  Original erfasst. `fileless` (memfd) und `deleted` schließen sich aus.

#### Hash und Flags hängen am Prozesszustand (kurzlebige Ziele)

`sha256`, `hash_state` und die Flags `fileless`/`deleted` werden beim
**Verarbeiten** des Ereignisses ermittelt, also Millisekunden nach dem Exec.
Für Ziele, die in dieser Zeit bereits beendet sind (`/bin/true`, `/bin/echo`),
gilt deshalb:

| Beobachtung beim Ziel | `hash_state` | `sha256` | `flags` |
|---|---|---|---|
| Ziel lebt beim Verarbeiten | `ok` | 64 hex | `fileless`/`deleted` möglich |
| Ziel ist bereits beendet | `gone` | `null` | `[]` (kein `fileless`, kein `deleted`) |

**Gemessene Quote** (Offline-Logik, Root-Lauf stand zum Zeitpunkt dieser
Fassung noch aus; `tests/integration.sh` Phase G liefert sie bei jedem Lauf):
200 Starts von `/bin/echo` und `/bin/true` je Ziel, als unprivilegierter
Nutzer, ergeben ein Mischbild aus `ok` und `gone` – für Ziele, die in
Millisekunden enden, überwiegt `gone`. Die Zahlen hängen an **Last** und
**Programmdauer** ab und sind als MESSZEILEN (kein Pass/Fail) in den Strom
eingebettet; `--stats` am Daemon ergänzt die Verzögerung
`ts_boot → erster /proc-Zugriff` (min/median/p99/max in µs, getrennt nach
`ok` und `gone`). Belastbare Prozentsätze werden mit dem ersten Root-Lauf
hier nachgetragen.

Ein `gone` ist also **kein Fehler**, sondern die ehrliche Antwort auf „der
Prozess existiert nicht mehr, `/proc/<pid>/exe` ist nicht lesbar". Damit sind
`fileless` und `deleted` für kurzlebige Ziele grundsätzlich nicht beobachtbar;
Prüfungen darauf müssen mit einem Ziel laufen, das noch lebt (z. B. `sleep 3`
oder ein Helfer, der auf ein Signal wartet). Entsprechend sind die Tests
gebaut: `tests/integration.sh` verwendet dafür lang-lebige Ziele und bringt
einen eigenen Info-Fall mit 200 kurzlebigen Execs (nur Zahlen ok/gone, keine
Bewertung).

Nicht betroffen ist `fd_exec`: es wird aus dem Kernel-Pfad des **Ereignisses**
bestimmt und steht unabhängig vom Prozesszustand.

### `lost`
```json
{"v":2,"seq":5,"ts":…,"wall":…,"ev":"lost","count":7}
```
- `count` – Anzahl verlorener Ereignisse seit der letzten Prüfung (Ringpuffer-Überlauf).

### `stop`
```json
{"v":2,"seq":…,"ts":…,"wall":…,"ev":"stop","mid":"…"}
```

## 4. Geschlossene Vokabulare

### 4.1 `hash_state`
`ok` | `gone` | `unreadable` | `reused` | `superseded`

| Wert | Bedeutung |
|---|---|
| `ok` | Inhalt der exe-Datei erfolgreich gehasht, Startzeit- und Identitätskontrolle bestanden |
| `gone` | Prozess war vor/nach dem Hashen verschwunden, oder beim Öffnen von `/proc/<pid>/exe` existierte er nicht mehr; bei kurzlebigen Zielen der Normalfall (§3) |
| `unreadable` | Öffnen von `/proc/<pid>/exe` scheiterte, obwohl der Prozess **noch lebt** (Permissions/race-bedingter Fehler), oder die Sensor-Identität fehlt (`ident_missing`-Zähler in `--stats`) |
| `reused` | **Echte PID-Wiederverwendung:** Der Prozess lebte nach dem Hashen weiter, aber mit **anderer** Startzeit (alter Prozess beendet, PID neu vergeben); der gelesene Hash gehörte zur vorherigen Prozess-Instanz. Bedeutet ausdrücklich **nicht** “derselbe Prozess hat erneut exec’t” – das erkennt `superseded`. |
| `superseded` | **Gleiche PID, gleiche Startzeit**, aber zwischen Sensorereignis und Daemon-Verarbeitung hat derselbe Prozess erneut exec’t: Der geöffnete FD gehört zu einer **späteren Exec-Stufe** derselben Prozess-Instanz. Der gelesene Hash gehört nicht zur Ereigniszeile und wird verworfen. |

Invariante: `sha256 ≠ null` ⟺ `hash_state == ok`; bei den vier anderen Zuständen
ist `sha256` immer `null`.

#### Exec-Ketten: eindeutig ist die Zeile, nicht die PID

Ein Helferstart erzeugt mehrere Exec-Zeilen **derselben PID** (z. B.
`setpriv → exec-cases → Ziel`, mit `bash` dazwischen vier Stufen). Jede Stufe
ist eine eigene Zeile mit eigenem `path`, eigener Sensor-Identität und eigenem
`hash_state`. Konsumenten dürfen daher **nie von der PID allein** auf “die”
ausgeführte Datei schließen; die eindeutige Zeilenidentität ist `seq` (pro
Lauf lückenlos), die Kettenzuordnung erfolgt über `seq`-Reihenfolge plus
exakten Pfad.

### 4.2 `flags`
Geschlossenes Vokabular, **feste kanonische Reihenfolge** (unabhängig von der
Einfügereihenfolge im Daemon):

`fileless`, `fd_exec`, `deleted`, `argc_min`, `lossy`, `path_trunc`, `cached`

| Flag | Bedeutung |
|---|---|
| `fileless` | Abbild stammt aus `/memfd:` (anonymes Speicherobjekt) |
| `fd_exec` | Exec über einen übergebenen Deskriptor: Kernel-Pfad beginnt mit `/dev/fd/` oder `/proc/self/fd/`; wird aus dem **Ereignis** bestimmt und ist damit unabhängig vom Prozesszustand. **Beweist weder memfd noch gelöscht** – deshalb eigenes Flag und keine Ableitung aus `fileless`/`deleted` |
| `deleted` | Abbild ist zum **Verarbeitungszeitpunkt** unter `/proc/<pid>/exe` gelöscht/ersetzt (`(deleted)`) – zeitabhängig, setzt ein lebendes Ziel voraus (siehe §3), **nicht** fileless |
| `argc_min` | `argc` ist eine Untergrenze (`argv`-Scan am Limit abgebrochen) |
| `lossy` | `comm`/`path` enthielten ungültiges UTF-8; Bytes durch U+FFFD ersetzt (automatisch) |
| `path_trunc` | Erkannte Kernel-Pfadlänge > `MAX_FILENAME`; `path` ist ein gekürzter Anfang |
| `cached` | `sha256` stammt aus dem Datei-Hash-Cache (dev/ino+size+mtime+ctime unverändert), nicht aus erneutem Lesen |

## 5. Zeitbasen

- `seq` – lückenlos, vom Daemon vergeben (deterministische Reihenfolge).
- **`seq` und `ts` sind nicht zueinander monoton.** `seq` zählt in
  Daemon-*Verarbeitungs*reihenfolge; `ts` trägt die (potenziell verfrühte)
  Kernel-*Ereignis*zeit. Insbesondere kann eine später verarbeitete Zeile ein
  kleineres `ts` tragen (z. B. wenn der Sensor das Event früher abschickte, der
  Daemon es aber nach einem anderen las). Konsumenten **ordnen daher nach `seq`**
  und behandeln `ts` als Attribut (Ereigniszeit), nicht als Ordnungsschlüssel.
  `start`/`lost`/`stop` tragen `ts` aus der Daemon-Uhr; nur `exec` trägt die
  Kernel-Zeit.
- `ts` – **Kernel-Bootzeit `CLOCK_BOOTTIME`** (ns) **zum Ereigniszeitpunkt**:
  für `exec`-Ereignisse aus dem eBPF-Sensor (`bpf_ktime_get_boot_ns`, Feld
  `ts_boot` – kein Daemon-Verarbeitungsverzug), für `start`/`lost`/`stop` aus
  `clock_gettime(CLOCK_BOOTTIME)` des Daemons. Damit steht `ts` auf derselben
  Uhr wie die Prozess-Startzeit `start_boot_time`/`starttime` – der
  Mischbasis-Fehler (zuvor `CLOCK_MONOTONIC` vs. BOOTTIME) ist beseitigt.
- `wall` – Unix-Zeit (ns) = `ts` verschoben um den einmalig beim Start gemessenen
  Offset `CLOCK_REALTIME − CLOCK_BOOTTIME` (`wall_offset`). Bei Zeitsprüngen
  während des Laufs (NTP-Stellschritt/manuell) kann `wall` driften
  (dokumentierte Grenze). Reines **Suspend** driftet nicht: `CLOCK_BOOTTIME` und
  `CLOCK_REALTIME` laufen beide über den Suspend hinweg weiter, der einmal
  gemessene Offset bleibt gültig.
- **Basiswerte**: Die `start`-Zeile trägt mit `ts` (Bootzeit zum Daemon-Start)
  und `wall` (zugehörige Unix-Zeit) genau die beiden Bezugspunkte, aus denen
  `wall` im gesamten Lauf rekonstruiert wird (`wall ≈ ts + (start.wall − start.ts)`).

## 6. ABI (`ExecEvent`) im Überblick

`#[repr(C)]`-bytemuck-`Pod` (Quelle: `exec-observer-uapi`):

`pid, ppid, uid, euid, tid` (u32), `argc` (u32), `argc_min, has_argc, path_trunc`
(u8), `start_boot_time` (u64), `ts_boot` (u64), `comm[16]`, `filename_len` (u16),
`filename[256]`, `exe_ino` (u64), `exe_size` (u64), `has_exe_ident` (u8).

- `tid` – Thread-ID des ausführenden Tasks (Kernel-`old_pid`); `pid` ist die TGID.
- `filename_len` – erkannte Kernel-Pfadlänge, begrenzt durch die Per-CPU-
  Zwischenablage `PATH_BUF_SIZE = 4096`; `filename` hält davon `MAX_FILENAME = 256`
  Bytes, `path_trunc` markiert Kürzung.
- `exe_ino`/`exe_size` – Datei-Identität zum Ereigniszeitpunkt
  (`mm->exe_file->f_inode->{i_ino, i_size}`); `has_exe_ident != 0` bedeutet
  gültig gelesen. Der Daemon vergleicht sie mit `fstat` (`st_ino`, `st_size`)
  des geöffneten `/proc/<pid>/exe`-FDs **vor** Cache und Hash. Abweichung →
  `superseded`; fehlende Sensor-Identität → `unreadable` (+ `ident_missing`).
- Eventgröße aktuell **352 B** → **744 Plätze** im 256-KiB-Ringpuffer.

### Warum `(ino, size)` statt `(dev, ino)`

Auf btrfs weicht die Superblock-Nummer (`s_dev`) von `st_dev` ab (gemessen:
Mount `0:35`, Datei-`st_dev` `0:37`). Ein Vergleich `s_dev ↔ st_dev` wäre dort
falsch. Gewählt wurde deshalb `(i_ino, i_size)`.

Limitationen der Wahl:

- Gleicher Inode und gleiche Größe bei **geändertem Inhalt** wird nicht
  erkannt (In-Place-Überschreibung ohne Größenänderung).
- Gleiche Nummer und gleiche Größe über Subvolume-/Dateisystemgrenzen ist
  nicht ausgeschlossen, aber unwahrscheinlich; der Vergleich schützt den
  Regelfall (Exec-Ketten derselben PID), nicht jede theoretische Kollision.

## 7. Abweichungen vom v1-Entwurf — und Gründe

| # | Feld/Aspekt | v1 (Entwurf) | v2 | Grund |
|---|---|---|---|---|
| A | `euid` | fehlte | eigenes Feld | Sicherheit/Detektion: nur mit `euid` sind setuid-Execs (z. B. `sudo`) als solche zu erkennen; `uid` allein zeigt den Aufrufer |
| B | `hash_state` | bool `hash_ok` | enum `ok\|gone\|unreadable\|reused` | Bool verlor drei real existierende Zustände (Prozess weg → `gone`, nicht lesbar → `unreadable`, PID-Reuse → `reused`); sonst wäre ein falscher Hash nicht von „kein Hash“ unterscheidbar |
| C | `flags` | Freitext-Array | geschlossenes Vokabular in fester Reihenfolge | Konsumenten müssen Flags deterministisch parsen; Reihenfolge und Wortschatz sind vertraglich fix |
| D | `argc` | int | int \| `null` + `argc_min` | `argv`-Zählung kann das Limit erreichen (Untergrenze) oder ganz fehlen (usermodehelper); beides böte nur int eine Lüge |
| E | `tid` | fehlte | eigenes u32-Feld | macht Nicht-Hauptthread-Execs nachvollziehbar (`pid` = TGID bleibt der Prozess) |
| F | `path`/`path_trunc` | unbegrenzter Pfad | `path` auf 256 B gekürzt + Flag | Ringpuffer-Leitung: kompakter Event-Rahmen; Kanonischer Pfad steht über `/proc/<pid>/exe` bereit; Kürzung wird ehrlich signalisiert |
| G | `ts` | `CLOCK_MONOTONIC` (Daemon) | `CLOCK_BOOTTIME`, Kernel-Seite (`ts_boot`) | Die v1-Basis war eine Daemon-Seiten-Mischrechnung (`realtime − monotonic`); Schritt 6 stellt `ts` auf die Kernel-Bootzeit zum Ereigniszeitpunkt um: direkt mit `start_boot_time` vergleichbar, kein Verarbeitungsverzug, `wall` über den einmalig gemessenen BOOTTIME-Offset |

## 8. Vererbung der Härtungs-/Schema-Schritte

- Schritt 1 (Hash-Cache): `(dev,ino)` + `size` + `mtime` (`sek`+`nsec`) +
  `ctime` (`sek`+`nsec`); **kein** Cache-Treffer bei `fileless`/`deleted`;
  `cached`-Flag bei jedem Cache-Treffer; LRU-Obergrenze `65536`.
- Schritt 5 (dieses Dokument): `unreadable`-Semantik, `path_trunc`, Per-CPU-
  Zwischenablage `PATH_BUF_SIZE = 4096`.
- Schritt 6: `ts` = Kernel-Bootzeit `bpf_ktime_get_boot_ns` zum Ereigniszeitpunkt;
  `wall` über einmaligen Offset `realtime − boottime`; `start`-Zeile liefert die
  Basiswerte (siehe §5). Daher ist `ts` direkt mit `start_boot_time`/`starttime`
  vergleichbar (kein Mischbasis-Fehler mehr).
- Schritt 7 (Ereignis-Identität): `(i_ino, i_size)` aus `mm->exe_file` zum
  Ereigniszeitpunkt; Vergleich mit `fstat` vor Cache/Hash; `superseded` bei
  späterer Exec-Stufe, `unreadable` + `ident_missing` ohne Sensor-Identität.

## 9. Änderungsliste (Format bleibt `v = 2`)

Solange kein Konsument (Import X4) existiert, bleibt `FORMAT_VERSION = 2`
eingefroren; additive Änderungen werden hier nachgetragen. Mit dem ersten
Import wird das Format eingefroren; danach erhöht jede Vokabularänderung die
Version.

- `hash_state: superseded` neu: gleiche PID/Startzeit, aber geöffneter FD
  gehört zu einer späteren Exec-Stufe (vorher fälschlich `ok` mit fremdem
  Hash möglich).
- `reused` neu definiert: nur echte PID-Wiederverwendung (andere Startzeit),
  nicht erneutes Exec.
- ABI: `exe_ino`, `exe_size`, `has_exe_ident` neu; Eventgröße 328 B → 352 B,
  Ringplätze 799 → 744.
- `--stats`: Zähler `ident_missing` neu (Ereignisse ohne Sensor-Identität).
- Kettenhinweis neu: eine PID trägt mehrere Exec-Zeilen; eindeutig ist die
  Zeile (`seq`), nicht die PID.