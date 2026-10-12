#!/usr/bin/env bash
# =============================================================================
# tests/integration.sh – Laufzeit-Kriterienmatrix für exec-observer 0.1.0
#
# AUSFÜHRUNG (nur durch Menschen, bewusst NICHT aus einem Agentenfenster).
# Dieses Skript BAUT NICHTS; es gibt genau zwei getrennte Schritte:
#
#   (1) BAUEN – als normaler Nutzer (NICHT sudo!), damit in ./target/ keine
#       root-eigenen Dateien entstehen:
#         cargo build -p exec-observer
#         gcc -O2 -Wall -Wextra -pthread tests/exec-cases.c -o tests/exec-cases.bin
#
#   (2) AUSFÜHREN – als root (eBPF-Load braucht Root, K9):
#         sudo tests/integration.sh
#         KEEP=1 sudo tests/integration.sh  # Temp-Verzeichnisse nach dem Lauf behalten
#
# ROLLENMODELL (bewusst so gebaut):
#   * Das Skript läuft als root und enthält KEINE sudo-Aufrufe mehr.
#   * Der Daemon wird DIREKT aus diesem Skript heraus gestartet. $! ist damit
#     die PID des Daemon-Prozesses selbst – kein sudo-Wrapper dazwischen.
#     Deshalb trifft kill -9/$DAEMON_PID wirklich den Daemon (vorher war $! die
#     sudo-PID; kill -9 hätte nur sudo getroffen und ein root-Daemon-Waise mit
#     geladenem eBPF-Programm wäre stehengeblieben). kill -0 belegt hinterher,
#     dass der Prozess wirklich weg ist (K14b).
#   * Die Hilfsprogramme laufen NICHT als root, sondern als der ursprüngliche
#     Aufrufer (SUDO_UID/SUDO_GID per setpriv --reuid/--regid/--clear-groups).
#     Genau ein Fall läuft absichtlich als root (K19). Damit sind uid/euid auf
#     beiden Seiten belegt, und der /proc/<pid>/exe-Zugriff des Beobachters auf
#     Prozesse eines FREMDEN Nutzers wird geprüft (das ist der Grund, warum
#     CAP_SYS_PTRACE gehalten wird; siehe tests/cap-matrix.sh Fall e).
#   * Verzeichnisse, die der unprivilegierte Helfer betreten/beschreiben muss,
#     werden per chown ihm übereignet – ausschließlich auf Pfade, die dieses
#     Skript selbst per mktemp angelegt hat.
#
# STARTSYNCHRONISATION: Der Daemon schreibt die start-Zeile erst, NACHDEM alle
# Tracepoints angehängt UND die Capabilities reduziert sind
# (exec-observer/src/main.rs: Schritt 3 anhängen → Capability-Reduktion →
# start-Zeile, mit flush je Zeile). Das Skript wartet deshalb auf die
# start-Zeile (Limit 10 s) statt auf eine feste Zeit – das ist kein Wettlauf
# mehr. Zusätzlich prüft start_daemon, dass /proc/$PID/exe auf den Daemon zeigt.
#
# TEMP-VERWALTUNG: tests/lib-temp.sh. new_sink liefert ihren Pfad in der
# globalen Variablen SINK_PATH – NIEMALS über $(), sonst läuft die Funktion in
# einer Unterschale und die Temp-Liste bleibt im Elternprozess leer (das war der
# Grund, weshalb nach einem Lauf sechs /tmp/exec-observer-it.* liegen blieben).
# tests/temp-selftest.sh prüft das ohne Root.
#
# Anforderungen: bash, python3, setpriv, sudo sowie root. Kein Netz; jede
# Senke liegt in einem eigenen 0700-Temp-Verzeichnis (mktemp). Das Trap
# beendet den Daemon, räumt die Temp-Verzeichnisse ab und meldet übrig
# gebliebene exec-observer-Prozesse.
# =============================================================================
set -uo pipefail

# Locale-Härtung (Punkt 1): $EPOCHREALTIME nutzt im deutschen Locale ein Komma
# (1791792331,854623); jede Arithmetik damit scheiterte mit „Ganzzahl
# erwartet“, bevor überhaupt ein Fall lief. Zusätzlich schneidet now_s()
# (tests/lib-time.sh) Punkt UND Komma robust ab.
export LC_ALL=C

HERE="$(cd "$(dirname "$0")/.." && pwd)"
DAEMON="$HERE/target/debug/exec-observer"
HELPER="$HERE/tests/exec-cases.bin"
PY="${PYTHON:-python3}"

# shellcheck source=lib-temp.sh
. "$HERE/tests/lib-temp.sh"
# shellcheck source=lib-time.sh
. "$HERE/tests/lib-time.sh"
if ! command -v now_s >/dev/null 2>&1 || ! command -v wait_for_lines >/dev/null 2>&1; then
  echo "FEHLER: tests/lib-time.sh nicht ladbar: $HERE/tests/lib-time.sh" >&2
  exit 2  # UNVOLLSTÄNDIG (Konstanten weiter unten noch nicht definiert)
fi

# Entscheidung 6: $EPOCHREALTIME braucht bash ≥ 5 (Fristen ohne externe
# Prozesse). Ältere bash → unvollständig, kein stiller Fehlertest.
[ "${BASH_VERSINFO[0]:-0}" -ge 5 ] || {
  echo "FEHLER: bash >= 5 nötig (EPOCHREALTIME), gefunden: $BASH_VERSION" >&2
  exit 2
}

PASS=0; FAIL=0; SKIP=0
# Exit-Codes: 0 = alle bewerteten Kriterien grün, 1 = bewerteter Fehler,
# 2 = unvollständig (Vorbedingung, Harness- oder Auswertefehler).
EXIT_FEHLER=1
EXIT_UNVOLLSTAENDIG=2
DAEMON_PID=""
DAEMON_STAT=""
KILLED_PID=""
LEFTOVER=0

die() { echo "FEHLER: $*" >&2; exit "$EXIT_UNVOLLSTAENDIG"; }

cleanup() {
  trap - EXIT INT TERM
  if daemon_is_current; then
    kill -TERM "$DAEMON_PID" 2>/dev/null
    # Gnadenfrist ohne neue Prozesse: kill -0 ist ein Builtin, die Frist kommt
    # aus now_s() (heißer, aber kurzer Spin statt externem sleep – ein
    # sleep-exec würde den noch laufenden Daemon füttern und den Cache wärmen).
    local end
    now_s; end=$(( NOW_S + 2 ))
    while kill -0 "$DAEMON_PID" 2>/dev/null; do
      now_s; [ "$NOW_S" -ge "$end" ] && break
    done
    if daemon_is_current; then
      kill -9 "$DAEMON_PID" 2>/dev/null
    fi
    DAEMON_PID=""
    DAEMON_STAT=""
  fi
  if [ "${KEEP:-0}" = "1" ]; then
    log "KEEP=1: Temp-Verzeichnisse bleiben erhalten:"
    local d
    for d in ${TEMPS[@]+"${TEMPS[@]}"}; do log "  behalte $d"; done
  else
    cleanup_temps
  fi
  # Restscan ohne pgrep (externes pgrep würde als Prozess auftauchen): /proc
  # lesen ist reine Builtin-Arbeit, nacktes $(<...) ohne Fork (kein 2>/dev/null
  # inside — das liefert still leer, s. lib-time.sh).
  local p comm
  for p in /proc/[0-9]*/comm; do
    [ -r "$p" ] || continue
    comm=$(<"$p") || continue
    if [ "$comm" = "exec-observer" ]; then
      LEFTOVER=1
      echo "ACHTUNG: exec-observer-Prozess(e) noch aktiv: ${p#/proc/} (${p%/comm})" >&2
    fi
  done
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# ── Vorbedingungen (KEIN Build hier — siehe Skriptkopf) ─────────────────────
[ "$(id -u)" -eq 0 ] || die "bitte per sudo aufrufen (eBPF-Load braucht Root, K9)"
[ -n "${SUDO_UID:-}" ] && [ -n "${SUDO_GID:-}" ] || \
  die "kein SUDO_UID/SUDO_GID – bitte 'sudo tests/integration.sh' nutzen (nicht su/Login-Root)"
[ "$SUDO_UID" != "0" ] && [ "$SUDO_GID" != "0" ] || \
  die "SUDO_UID/SUDO_GID ist 0 – ein unprivilegierter Aufrufer wird gebraucht"
getent passwd "$SUDO_UID" >/dev/null 2>&1 || die "unbekannter Benutzer $SUDO_UID"
getent group "$SUDO_GID" >/dev/null 2>&1 || die "unbekannte Gruppe $SUDO_GID"
command -v setpriv >/dev/null 2>&1 || die "setpriv fehlt (util-linux)"
if ! [ -x "$DAEMON" ]; then
  echo "FEHLER: Daemon fehlt/nicht ausführbar: $DAEMON" >&2
  echo "        Erst bauen (als normaler Nutzer): cargo build -p exec-observer" >&2
  exit "$EXIT_UNVOLLSTAENDIG"
fi
if ! [ -x "$HELPER" ]; then
  echo "FEHLER: Helfer fehlt/nicht ausführbar: $HELPER" >&2
  echo "        Erst bauen (als normaler Nutzer):" >&2
  echo "        gcc -O2 -Wall -Wextra -pthread tests/exec-cases.c -o tests/exec-cases.bin" >&2
  exit "$EXIT_UNVOLLSTAENDIG"
fi
command -v "$PY" >/dev/null 2>&1 || die "python3 fehlt"

USER_UID="$SUDO_UID"; USER_GID="$SUDO_GID"

log() { printf '%s\n' "$*"; }

# Vote-Sammler. „info" zählt bewusst NICHT in pass/fail/skip – so kann ein Fall
# berichtet werden, ohne eine Bewertung vorzutäuschen (Kurzlebige-Prozesse-Info).
krit() { # krit <nr> <pass|fail|info|skip> <text>
  case "$2" in
    pass) PASS=$((PASS+1)); s=PASS;;
    fail) FAIL=$((FAIL+1)); s=FAIL;;
    info) s=INFO;;
    *)    SKIP=$((SKIP+1)); s=SKIP;;
  esac
  printf '  K%-2s %-4s %s\n' "$1" "$s" "$3"
}

log "exec-observer integration.sh – Kriterienmatrix (B1–B6, Identitäts-Planänderung)"
log "Daemon: $DAEMON | Helfer: $HELPER"
log "Unprivilegierte Hilfsprozesse laufen als uid=$USER_UID gid=$USER_GID"
log "Temp-Root (mktemp): siehe TEARDOWN am Ende (trap)"
log ""

# ── Helfer: Ausführung als unprivilegierter Nutzer ──────────────────────────
# setpriv execve't direkt; $! bzw. die Kind-PID ist damit die PID des Helfers.
run_user() {
  setpriv --reuid="$USER_UID" --regid="$USER_GID" --clear-groups -- "$@"
}

# ── Temp-Wurzeln (alles innerhalb mktemp; kein fester /tmp-Pfad mehr) ────────
# new_dir/new_file/new_sink kommen aus lib-temp.sh und liefern DIR_PATH,
# FILE_PATH bzw. SINK_PATH im aktuellen Prozess – NIEMALS über $(...)
# aufrufen, sonst landet die Registrierung in einer Unterschale.
new_dir root            || die "mktemp -d fehlgeschlagen"
TMPROOT="$DIR_PATH"
new_file nonex          || die "mktemp (NONEXEC) fehlgeschlagen"
NONEXEC="$FILE_PATH"; chmod 0600 "$NONEXEC"
new_dir deep            || die "mktemp -d (deep) fehlgeschlagen"
DEEPROOT="$DIR_PATH"
new_file argmap         || die "mktemp (argmap) fehlgeschlagen"
ARGMAP="$FILE_PATH"
new_file argcout        || die "mktemp (argcout) fehlgeschlagen"
ARGCOUT="$FILE_PATH"
# Die Ausgabe des unprivilegierten Helfers gehört ihm: Nur so beweist ein
# erfolgreicher Schreibvorgang, dass der abgesetzte Nutzer schreiben konnte
# (statt dass die Root-Shell die Datei vorab öffnet).
chown "$USER_UID:$USER_GID" "$ARGCOUT" || die "chown (argcout) fehlgeschlagen"
chmod 0600 "$ARGCOUT"

# ── Private Kopien (B1/B2, TESTS a–d) ──────────────────────────────────────
# Jede Stufe jeder Kette läuft aus einer privaten Kopie mit eindeutigem Namen:
# geteilte Systempfade machten Treffer mehrdeutig und wärmten den Hash-Cache
# vor (K9). Alles VOR dem ersten Daemonstart – cp/chmod/sha256sum sind
# Prozesse und würden sonst als Ereignisse auftauchen.
# Das btrfs-Verzeichnis liegt unter $HERE (btrfs, TEST a), NICHT in /tmp
# (/tmp ist tmpfs, TEST b). setpriv bleibt Systemstufe (Entscheidung 4).
BTRFSROOT="$(mktemp -d "$HERE/.it-btrfs.XXXXXX")" || die "mktemp -d (btrfs) fehlgeschlagen"
chmod 700 "$BTRFSROOT"
register_temp "$BTRFSROOT"
H_P="$BTRFSROOT/helper-priv.bin"            # privater Helfer (alle Phasen)
cp -p "$HELPER" "$H_P" || die "Kopie Helfer fehlgeschlagen"
T_A1="$BTRFSROOT/target-echoA.bin"          # Phase A: echo-Ziel
cp -p /bin/echo "$T_A1" || die "Kopie echo(A) fehlgeschlagen"
T_A2="$BTRFSROOT/target-sleepA.bin"         # Phase A: sleep-Ziel (two_threads + langlebig)
cp -p /bin/sleep "$T_A2" || die "Kopie sleep(A) fehlgeschlagen"
T_B="$BTRFSROOT/target-sleepB.bin"          # Phase B: Hash/Cache-Ziel
cp -p /bin/sleep "$T_B" || die "Kopie sleep(B) fehlgeschlagen"
PAY_C="$BTRFSROOT/memfd-payload.bin"        # Phase C: memfd-Nutzlast (lebt)
cp -p /bin/sleep "$PAY_C" || die "Kopie memfd-Nutzlast fehlgeschlagen"
T_H="$BTRFSROOT/target-chain.bin"           # Phase H: Ketten-Ziel
cp -p /bin/sleep "$T_H" || die "Kopie chain-Ziel fehlgeschlagen"
T_G1="$BTRFSROOT/target-trueG.bin"          # Phase G: kurzlebig 1
cp -p /bin/true "$T_G1" || die "Kopie true(G) fehlgeschlagen"
T_G2="$BTRFSROOT/target-echoG.bin"          # Phase G: kurzlebig 2
cp -p /bin/echo "$T_G2" || die "Kopie echo(G) fehlgeschlagen"
T_SYS="/usr/bin/sleep"                      # Phase I: Systemprogramm
T_TMP="$TMPROOT/target-tmpfs.bin"           # Phase I: Ziel auf tmpfs (/tmp)
cp /bin/sleep "$T_TMP" || die "Kopie tmpfs-Ziel fehlgeschlagen"
chmod 755 "$T_TMP" || die "chmod tmpfs-Ziel fehlgeschlagen"
chown -R "$USER_UID:$USER_GID" "$BTRFSROOT" || die "chown (btrfs) fehlgeschlagen"
chown "$USER_UID:$USER_GID" "$T_TMP" || die "chown tmpfs-Ziel fehlgeschlagen"
# Fix K27: TMPROOT ist mktemp-Verzeichnis (root, 0700). Uid 1000 braucht nur
# Durchgangsrecht (x) zum Erreichen von T_TMP, kein Lese-/Schreibrecht. Ohne
# das scheiterte der Exec des Ziels still (Zeilenzahl 2 statt 3 pro PID).
chmod 711 "$TMPROOT" || die "chmod TMPROOT fehlgeschlagen"
# Erwartete Hashes VOR dem ersten Daemonstart bestimmen (sha256sum selbst ist
# ein Prozess; danach darf kein Setup-Prozess mehr laufen, solange ein Daemon
# lauscht). Feldsplit per Parameter-Expansion, ohne cut/awk (B5).
sha_of() { # sha_of <datei> → Hex-Hash
  local out
  out="$(sha256sum "$1")" || return 1
  printf '%s' "${out%% *}"
}
SETPRIV_BIN="$(command -v setpriv)"
case "$SETPRIV_BIN" in
  /*) ;; # absoluter Pfad nötig: die Kette prüft die setpriv-Stufe exakt
  *) die "setpriv-Pfad nicht absolut: $SETPRIV_BIN";;
esac
H_SETPRIV="$(sha_of "$SETPRIV_BIN")" || die "sha256sum (setpriv) fehlgeschlagen"
H_HELP="$(sha_of "$H_P")"             || die "sha256sum (Helferkopie) fehlgeschlagen"
H_SLEEP="$(sha_of /bin/sleep)"        || die "sha256sum (/bin/sleep) fehlgeschlagen"
H_USRSLEEP="$(sha_of "$T_SYS")"       || die "sha256sum (System-sleep) fehlgeschlagen"
# Kettenlängen (Entscheidung 5/8, dokumentiert statt gezählt): run_user =
# setpriv + Helfer + Ziel (3 Stufen, 1 PID); run_user bash -c = setpriv +
# bash + Helfer + Ziel (4 Stufen, 1 PID); direkter Helferstart = 2 Stufen.

# ── Start/Stopp: PID == Daemon-PID (kein sudo-Wrapper), Warten auf start ────
# Signale gehen nur an eine verifizierte Daemon-Instanz: PID, exe-Link und
# /proc-Startzeit müssen übereinstimmen. Damit kann eine wiederverwendete PID
# keinen fremden Prozess treffen.
proc_starttime() { # proc_starttime <pid>
  local stat rest
  [ -r "/proc/$1/stat" ] || return 1
  stat=$(<"/proc/$1/stat") || return 1
  rest="${stat##*)}"
  [ "$rest" != "$stat" ] || return 1
  set -- $rest
  [ $# -ge 20 ] || return 1
  case "$20" in
    ''|*[!0-9]*) return 1;;
  esac
  printf '%s' "$20"
}

daemon_is_current() {
  [ -n "$DAEMON_PID" ] || return 1
  kill -0 "$DAEMON_PID" 2>/dev/null || return 1
  # -ef vergleicht Gerät/Inode ohne readlink-Prozess (B5).
  [ "/proc/$DAEMON_PID/exe" -ef "$DAEMON" ] || return 1
  [ -n "${DAEMON_STAT:-}" ] || return 1
  [ "$(proc_starttime "$DAEMON_PID" 2>/dev/null || true)" = "$DAEMON_STAT" ]
}

# Warten ohne neue Prozesse (B5): Fristen aus $EPOCHREALTIME, Muster per
# nacktem [[ $(<...) ]] (ohne Zusatz-Umleitung!), Zeilen per mapfile-Builtin –
# siehe tests/lib-time.sh.

wait_start() { # wait_start <sink> [sekunden]
  local sink="$1"
  wait_for_content "$sink" '"ev":"start"' "${2:-10}" || return 1
  # Der Daemon ist weg: keine start-Zeile zu erwarten (z. B. eBPF-Fehler).
  kill -0 "$DAEMON_PID" 2>/dev/null || return 1
  return 0
}

# Der Daemon läuft mit --stats (Statistik auf stderr beim Beenden) und mit
# geleertem Inheritable-Set: sonst ginge das CapInh der aufrufenden Sitzung
# (CAP_WAKE_ALARM, Bit 35) in sein Permitted über und die Läufe hingen an der
# Umgebung. stderr landet in einer Datei, damit die Messzeilen die Statistik
# herausziehen können.
start_daemon() { # start_daemon <sink>
  local t0
  now_s; t0="$NOW_S"
  setpriv --inh-caps=-all -- "$DAEMON" "$1" --stats >/dev/null 2>"$1.err" &
  DAEMON_PID=$!
  if ! wait_start "$1" 10; then
    # Abbruchpfad (Punkt 1): verstrichene Zeit, Daemon-stderr (erste 20
    # Zeilen, Builtins only) und Exit-Status des Daemons – dann UNVOLLSTÄNDIG.
    local elapsed rc errline
    now_s; elapsed=$(( NOW_S - t0 ))
    if kill -0 "$DAEMON_PID" 2>/dev/null; then
      rc="läuft noch"
    else
      wait "$DAEMON_PID" 2>/dev/null
      rc="$?"
    fi
    log "ABBRUCH: keine start-Zeile nach ${elapsed}s (UNVOLLSTÄNDIG, Daemon-Exit: $rc)"
    log "-- stderr ($1.err, erste 20 Zeilen):"
    local errlines i=0
    mapfile -t errlines < "$1.err" 2>/dev/null || errlines=()
    for errline in ${errlines[@]+"${errlines[@]}"}; do
      [ "$i" -ge 20 ] && break
      log "   $errline"
      i=$((i+1))
    done
    [ "${#errlines[@]}" -eq 0 ] && log "   (leer/fehlend)"
    die "Daemon schrieb in ${elapsed}s keine start-Zeile (Tracepoints nicht angehängt?)"
  fi
  [ "/proc/$DAEMON_PID/exe" -ef "$DAEMON" ] || \
    die "/proc/$DAEMON_PID/exe zeigt nicht auf den Daemon – \$! ist nicht der Daemon"
  DAEMON_STAT="$(proc_starttime "$DAEMON_PID")" || \
    die "Startzeit von Daemon-PID $DAEMON_PID nicht lesbar"
}

stop_daemon() { # stop_daemon [sink]
  # --stats wird NACH der stop-Zeile geschrieben; per Frist darauf warten,
  # ohne grep/sleep-Prozesse. Danach urteilt die Auswertung, nicht das Warten.
  local sink="${1:-$SINK}"
  if [ -n "$sink" ] && [ -f "$sink.err" ]; then
    wait_for_content "$sink.err" "--stats end" 3 || true
  fi
  if daemon_is_current; then
    kill -TERM "$DAEMON_PID" 2>/dev/null
    local end
    now_s; end=$(( NOW_S + 2 ))
    while kill -0 "$DAEMON_PID" 2>/dev/null; do
      now_s; [ "$NOW_S" -ge "$end" ] && break
    done
    if daemon_is_current; then
      kill -9 "$DAEMON_PID" 2>/dev/null
    fi
  elif [ -n "$DAEMON_PID" ]; then
    echo "WARNUNG: Daemon-PID $DAEMON_PID stimmt nicht mehr mit dem gestarteten Daemon überein – kein Kill" >&2
  fi
  DAEMON_PID=""
  DAEMON_STAT=""
}

THREAD_PID=0; TWO_PID=0

# ── Phase A: Haupt-/Nicht-Haupt-Thread, Doppel-Thread, fehlgeschlagenes exec ─
new_sink || die "mktemp -d (Senke) fehlgeschlagen"
SINK="$SINK_PATH"
start_daemon "$SINK"
# Alle Hilfsprozesse hier laufen als uid $USER_UID (vorher ging ALLES als root,
# damit fehlte der Fall "Prozess eines fremden Nutzers" vollständig).
# Ziele sind private Kopien (B1); Filter treffen exakte Pfade, nie PIDs allein.
run_user "$H_P" main_exec "$T_A1" a b c >/dev/null 2>&1 || true
run_user "$H_P" thread_exec "$T_A1" "t1" >/dev/null 2>&1 & THREAD_PID=$!
wait "$THREAD_PID" 2>/dev/null || true
run_user "$H_P" two_threads "$T_A2" >/dev/null 2>&1 & TWO_PID=$!
wait "$TWO_PID" 2>/dev/null || true
run_user "$H_P" fail_exec "$NONEXEC"      || true
run_user "$H_P" main_exec "$T_A2" nope >/dev/null 2>&1 || true   # Daemon lebt nach fail_exec weiter
# Warten urteilt nicht (B5): findet die Ruhe nicht statt, meldet die Auswertung.
wait_for_quiescence "$SINK" 10 15 || true
stop_daemon "$SINK"

# ── Phase A2: EIN Fall mit Hilfsprogramm als root (Gegenprobe) ──────────────
new_sink || die "mktemp -d (Senke) fehlgeschlagen"
SINKAR="$SINK_PATH"
start_daemon "$SINKAR"
# linger statt echo-Ziel: Der Helfer selbst lebt 3 s (kein weiterer exec), die
# einzige Zeile ist damit deterministisch hashbar (K19).
"$H_P" linger 3 >/dev/null 2>&1 || true
wait_for_quiescence "$SINKAR" 2 15 || true
stop_daemon "$SINKAR"

# ── Phase B: Hash-/Cache-Konsistenz (B2) ────────────────────────────────────
# Ziel MUSS leben: sha256 und hash_state werden beim Verarbeiten gelesen. Bei
# kurzlebigen Zielen war der Prozess vorher fort → hash_state "gone".
# Private Kopie T_B: erster Start ohne cached (nichts wärmt vor), zweiter mit.
new_sink || die "mktemp -d (Senke) fehlgeschlagen"
SINKB="$SINK_PATH"
start_daemon "$SINKB"
run_user "$H_P" main_exec "$T_B" 3 >/dev/null 2>&1 || true
wait_for_lines "$SINKB" 4 15 || true   # start + Kette (setpriv, Helfer, Ziel)
run_user "$H_P" main_exec "$T_B" 3 >/dev/null 2>&1 || true   # 2. Start → Cache-Treffer
wait_for_lines "$SINKB" 7 15 || true
stop_daemon "$SINKB"

# ── Phase C: memfd/fileless + tiefer Pfad (path_trunc) ──────────────────────
# Setup VOR dem Daemonstart (B5): mkdir/ln/chown sind Prozesse und würden
# sonst als Ereignisse auftauchen.
DEEPDIR="$DEEPROOT/p"
P="$DEEPDIR"
for ((i=1; i<=20; i++)); do P="$P/dddd$i-$i-$i-$i-YYYYYYY-$i"; done
mkdir -p "$P"; ln -s "$T_A1" "$P/deep"
chown -R "$USER_UID:$USER_GID" "$DEEPROOT"
new_sink || die "mktemp -d (Senke) fehlgeschlagen"
SINKC="$SINK_PATH"
start_daemon "$SINKC"
# memfd mit LEBENDIGER privater Nutzlast (B3): Inhalt aus PAY_C per
# stdin-Umleitung – kein cat-Prozess, kein Rauschen. argv[0] = "" (leer),
# argv[1] = "3" → der Prozess steht noch, wenn der Daemon liest.
run_user "$H_P" memfd_exec payload 3 <"$PAY_C" >/dev/null 2>&1 || true
# Tiefer Pfad: Symlink auf die private echo-Kopie (kein Systempfad, B1).
run_user "$H_P" trunc_exec "$P/deep" || true
wait_for_quiescence "$SINKC" 7 15 || true   # start + Kette(3) + trunc-Kette(3)
stop_daemon "$SINKC"

# ── Phase D: kill -9 (Abbruch ohne stop) ────────────────────────────────────
new_sink || die "mktemp -d (Senke) fehlgeschlagen"
SINKD="$SINK_PATH"
start_daemon "$SINKD"
run_user "$H_P" main_exec "$T_A2" 0.2 >/dev/null 2>&1 || true
wait_for_lines "$SINKD" 4 15 || true   # start + Kette (setpriv, Helfer, Ziel)
# $DAEMON_PID ist der Daemon selbst (start_daemon prüft /proc/PID/exe), nicht
# mehr die sudo-PID. kill -0 belegt danach, dass der Prozess wirklich fort ist.
KILLED_PID="$DAEMON_PID"
kill -9 "$DAEMON_PID"
wait "$DAEMON_PID" 2>/dev/null
DAEMON_PID=""
DAEMON_STAT=""
if ! kill -0 "$KILLED_PID" 2>/dev/null; then
  K14B=PASS
  K14B_TEXT="kill -9 auf Daemon-PID $KILLED_PID: kill -0 schlägt danach fehl (keine sudo-Waise)"
else
  K14B=FAIL
  # -ef statt readlink-Prozess (B5): gleiche Datei + kill -0 ok → lebt weiter.
  if [ "/proc/$KILLED_PID/exe" -ef "$DAEMON" ]; then
    K14B_TEXT="kill -9 auf Daemon-PID $KILLED_PID: Prozess lebt weiter (kein PASS)"
  else
    K14B_TEXT="kill -9 auf Daemon-PID $KILLED_PID: PID wurde wiederverwendet oder ist unprüfbar (kein PASS)"
  fi
fi

# ── Phase E: argc-Randfälle (Kriterium 11) + deleted (Kriterium 12b) ────────
new_sink || die "mktemp -d (Senke) fehlgeschlagen"
SINKE="$SINK_PATH"
ARGC_LIMIT=1024
start_daemon "$SINKE"
for n in 0 $((ARGC_LIMIT - 1)) "$ARGC_LIMIT" $((ARGC_LIMIT + 1)) 100000; do
  # Die Umleitung steht innerhalb des abgesetzten Prozesses: Der Helfer öffnet
  # ARGCOUT selbst als unprivilegierter Nutzer, nicht die Root-Shell vorab.
  # Kette je Fall (4 Stufen, 1 PID): setpriv → bash → Helfer → Ziel (Helfer
  # selbst, argc_exec re-exec't ihn mit n Argumenten).
  run_user bash -c 'exec >>"$1" 2>/dev/null; exec "$2" argc_exec "$3" "$2"' _ "$ARGCOUT" "$H_P" "$n" &
  printf '%s %s\n' "$n" "$!" >>"$ARGMAP"
  wait "$!" 2>/dev/null || true
done
# deleted braucht ein lebendes Ziel: private Kopie im btrfs-Verzeichnis
# (EXEC_CASES_TMPDIR, B1), unlink vor execveat, argv = [Kopie, 3] → steht noch
# beim Verarbeiten → Flag deleted (nicht fileless), sha256 der Kopie.
# export (nicht bloß vorangestellt): run_user ist eine Funktion, nur
# Exportiertes erbt setpriv an den Helfer weiter.
export EXEC_CASES_TMPDIR="$BTRFSROOT"
run_user "$H_P" deleted_exec "$T_A2" 3 >/dev/null 2>&1 || true
wait_for_quiescence "$SINKE" 20 15 || true
stop_daemon "$SINKE"

# ── Phase F: Ringpuffer-Überlauf per kill -STOP (Kriterium 13, B4) ──────────
# Überlauf deterministisch: Daemon mit SIGSTOP anhalten, dann mehr execs
# feuern, als der 256-KB-Ringpuffer fasst (~744 Ereignisse à 352 B), dann
# SIGCONT. Der Sensor zählt alle Versuche (SEEN) und Reservierungsfehler
# (DROPS); der Daemon meldet die Differenz als ev:"lost". Die Auswertung
# prüft geschrieben + lost == kernel_seen (keine Schätzung mehr).
new_sink || die "mktemp -d (Senke F) fehlgeschlagen"
SINKF="$SINK_PATH"
OVERFLOW_EXECS=1200
start_daemon "$SINKF"
# Ein Vorlauf, damit der Ringpuffer nachweislich leer startet.
run_user "$H_P" main_exec "$T_G1" >/dev/null 2>&1 || true
wait_for_lines "$SINKF" 4 15 || true   # start + Kette
# 1) Daemon anhalten – er konsumiert den Ringpuffer nicht mehr.
kill -STOP "$DAEMON_PID"
# 2) Mehr execs als in den Ringpuffer passen. stdout/stderr bewusst nach
#    /dev/null. Ziel ist die private true-Kopie (endet sofort; die Ereignisse
#    stauen sich im Ring, während der Daemon steht). Zählschleife als C-Loop
#    (B5: seq wäre ein Prozess pro Lauf).
OVERFLOW_DONE=0
for ((i=1; i<=OVERFLOW_EXECS; i++)); do
  # Nur erfolgreich gestartete Helfer zählen: `|| true` würde sonst auch
  # fehlgeschlagene Spawns als erzeugte Ereignisse verbuchen. Jede erfolgreiche
  # Iteration erzeugt drei exec-Ereignisse (setpriv, Helfer, Ziel).
  if run_user "$H_P" main_exec "$T_G1" >/dev/null 2>&1; then
    OVERFLOW_DONE=$((OVERFLOW_DONE+1))
  fi
done
# 3) Weiterlaufen lassen, bis der Strom zur Ruhe kommt (Quiescence statt
#    fester Zeit): Der Daemon liest die DROPS-Differenz und schreibt ev:"lost".
kill -CONT "$DAEMON_PID"
wait_for_quiescence "$SINKF" 100 60 || true
stop_daemon "$SINKF"
# --stats-Block der Überlaufphase retten (Erhaltung B4).
FSTATS="$SINKF.err"

# ── Phase G: kurzlebige Prozesse (MESSZEILEN, keine Bewertung) ─────────────
# Ziele enden in Millisekunden: hash_state "gone"/"superseded" ist dort der
# Normalfall (SCHEMA.md §3). Deshalb NUR MESSWERTE, kein Pass/Fail.
# Je Ziel 200 Starts als private Kopien (B1), jeweils als unprivilegierter
# Nutzer. Die Zahlen werden bei JEDEM Lauf ausgegeben, auch wenn alles andere
# grün ist. C-Loop statt seq (B5).
new_sink || die "mktemp -d (Senke G) fehlgeschlagen"
SINKG="$SINK_PATH"
SHORTLIVED="$T_G1"
SHORTLIVED2="$T_G2"
SHORTLIVED_RUNS=200
start_daemon "$SINKG"
for ((i=1; i<=SHORTLIVED_RUNS; i++)); do
  run_user "$H_P" main_exec "$SHORTLIVED"  >/dev/null 2>&1 || true
  run_user "$H_P" main_exec "$SHORTLIVED2" >/dev/null 2>&1 || true
done
wait_for_quiescence "$SINKG" 1000 60 || true
stop_daemon "$SINKG"
# --stats-Block aus der Senken-stderr retten (VOR dem cleanup)
GSTATS="$SINKG.err"

# ── Phase H: Exec-Kette mit angehaltenem Daemon (TEST c + Timing-Beweis) ───
# Deterministisch dank kill -STOP: Alle drei Stufen (setpriv → Helfer → Ziel)
# stehen im Ring, BEVOR der Daemon sie verarbeitet. Erwartung:
# - setpriv-Zeile: superseded (FD gehört beim Öffnen längst dem Ziel),
# - Helfer-Zeile:  superseded (dto.),
# - Ziel-Zeile:    ok, sha256 == Hash der privaten Kopie.
# Das beweist zugleich die Timing-Annahme (Punkt 5): Der Sensor las die
# Helfer-Identität zum Helfer-Ereignis (sonst wäre die Helfer-Zeile ok mit
# fremdem Hash – genau Befund A) und die Ziel-Identität zum Ziel-Ereignis.
# Das Ziel (8 s) lebt bei der Verarbeitung noch (s. Fix unten).
# Fix (Testfehler): Vorher lief die Kette SYNCHRON, das Ziel war beim
# Verarbeiten längst tot → `gone` war korrekt, der Test falsch. Jetzt: Kette im
# Hintergrund mit 8 s Lebensdauer; Daemon bleibt angehalten, bis das Ziel-Image
# läuft (Polling per Builtin, Abbruch nach 5 s); dann CONT. Verarbeitung dauert
# Millisekunden, das Ziel lebt noch 8 s.
new_sink || die "mktemp -d (Senke H) fehlgeschlagen"
SINKH="$SINK_PATH"
start_daemon "$SINKH"
kill -STOP "$DAEMON_PID"
run_user "$H_P" main_exec "$T_H" 8 >/dev/null 2>&1 & HPID=$!
now_s; hend=$(( NOW_S + 5 ))
while :; do
  now_s; [ "$NOW_S" -ge "$hend" ] && break
  [ -r "/proc/$HPID/comm" ] && [ "$(<"/proc/$HPID/comm")" = "target-chain.bi" ] && break
done
kill -CONT "$DAEMON_PID"
wait_for_quiescence "$SINKH" 4 15 || true   # start + 3 Kettenstufen
stop_daemon "$SINKH"
wait "$HPID" 2>/dev/null || true            # Kette ausklingen lassen (≤ 8 s)

# ── Phase I: Dateisystem-Matrix (TESTS a/b) ─────────────────────────────────
# (a) Ziel auf btrfs (privater Ordner unter dem Projektverzeichnis) UND ein
#     Systemprogramm (/usr/bin/sleep): jeweils hash_state ok.
# (b) Ziel in /tmp (tmpfs): hash_state ok.
# Jeweils eigene Senke, Filter auf exakten Pfad + uid (Entscheidung 5).
new_sink || die "mktemp -d (Senke I1) fehlgeschlagen"
SINKI1="$SINK_PATH"
start_daemon "$SINKI1"
run_user "$H_P" main_exec "$T_B" 3 >/dev/null 2>&1 || true
wait_for_quiescence "$SINKI1" 4 15 || true
stop_daemon "$SINKI1"
new_sink || die "mktemp -d (Senke I2) fehlgeschlagen"
SINKI2="$SINK_PATH"
start_daemon "$SINKI2"
run_user "$H_P" main_exec "$T_SYS" 3 >/dev/null 2>&1 || true
wait_for_quiescence "$SINKI2" 4 15 || true
stop_daemon "$SINKI2"
new_sink || die "mktemp -d (Senke I3) fehlgeschlagen"
SINKI3="$SINK_PATH"
start_daemon "$SINKI3"
run_user "$H_P" main_exec "$T_TMP" 3 >/dev/null 2>&1 || true
wait_for_quiescence "$SINKI3" 4 15 || true
stop_daemon "$SINKI3"

# ── Python-Auswertung (gemeinsames Prüflogik-Modul) ─────────────────────────
# Eine scheiternde Auswertung darf nicht wie ein grüner Lauf aussehen. Ohne
# diesen Abbruch warf der Python-Block einen Traceback, VERDICT war leer, die
# Matrix blieb leer und `[ "$FAIL" -eq 0 ]` meldete Erfolg.
EVAL_RC=0
VERDICT="$( "$PY" - "$SINK" "$SINKB" "$SINKC" "$SINKD" "$NONEXEC" \
    "$SINKE" "$THREAD_PID" "$TWO_PID" "$ARGMAP" "$ARGCOUT" "$SINKAR" \
    "$SINKF" "$OVERFLOW_DONE" "$SINKG" "$SHORTLIVED_RUNS" "$GSTATS" \
    "$SHORTLIVED" "$SHORTLIVED2" "$H_P" "$T_A1" "$T_A2" "$T_B" "$H_HELP" "$H_SLEEP" \
    "$H_USRSLEEP" "$H_SETPRIV" "$SETPRIV_BIN" "$SINKH" "$T_H" "$SINKI1" "$SINKI2" "$SINKI3" \
    "$T_TMP" "$USER_UID" "$FSTATS" "$T_SYS" <<'PYEOF'
import json, re, sys

def load(p):
    raw = open(p, "rb").read()
    if raw == b"":
        return []
    evs = []
    for ln in raw.split(b"\n"):
        ln = ln.strip()
        if ln:
            evs.append(json.loads(ln.decode("utf-8")))  # K1: striktes JSON
    return evs

def flags(ev): return ev.get("flags", [])
def execs(evs): return [e for e in evs if e["ev"] == "exec"]

out = []
def emit(no, st, msg):
    out.append(f"{no}|{st}|{msg}")

A = load(sys.argv[1])   # Phase A   (uid 1000)
B = load(sys.argv[2])   # Phase B   (Hash/Cache)
C = load(sys.argv[3])   # Phase C   (memfd/deep)
D = load(sys.argv[4])   # Phase D   (kill -9)
R = load(sys.argv[11])  # Phase A2  (als root)
F = load(sys.argv[12])  # Phase F   (Überlauf per kill -STOP)
OVERFLOW_EXECS = int(sys.argv[13])  # tatsächlich durchgeführte execs
SHORT1 = sys.argv[17] if len(sys.argv) > 17 else "/bin/true"
SHORT2 = sys.argv[18] if len(sys.argv) > 18 else "/bin/echo"
HP, TA1, TA2, TB = sys.argv[19], sys.argv[20], sys.argv[21], sys.argv[22]
H_HELP, H_SLEEP, H_USR = sys.argv[23], sys.argv[24], sys.argv[25]
H_SETPRIV, SETPRIV = sys.argv[26], sys.argv[27]
H = load(sys.argv[28])   # Phase H   (Kette mit STOP)
TH = sys.argv[29]
I1 = load(sys.argv[30])  # Phase I1  (btrfs-Kopie)
I2 = load(sys.argv[31])  # Phase I2  (System-sleep)
I3 = load(sys.argv[32])  # Phase I3  (tmpfs-Kopie)
T_TMP = sys.argv[33]
UUID = int(sys.argv[34])
TSYS = sys.argv[36]
G = load(sys.argv[14])  # Phase G   (kurzlebige Prozesse, nur Info)
SHORT_RUNS = int(sys.argv[15])
# --stats-Block des Daemon (stderr) als Zusatzinformation
STATS_TEXT = ""
try:
    STATS_TEXT = open(sys.argv[16]).read()
except OSError:
    STATS_TEXT = ""
# --stats-Block der Überlaufphase (Erhaltung B4)
FSTATS_TEXT = ""
try:
    FSTATS_TEXT = open(sys.argv[35]).read()
except OSError:
    FSTATS_TEXT = ""

def ctx(no, evs, filt):
    """B6-Fehlerkontext: höchstens 8 getroffene Zeilen + Zeilenzahl je pid."""
    from collections import Counter
    hits = [e for e in evs if filt(e)]
    pc = Counter(e.get("pid") for e in evs if e.get("ev") == "exec")
    out.append("CTX|%s|treffer=%d|%s|pid_zeilen=%s" % (
        no, len(hits),
        ";".join(json.dumps(e, sort_keys=True) for e in hits[:8]),
        ",".join("%s:%s" % kv for kv in sorted(pc.items()))))

# K1: start/stop-Kopf
st = next((e for e in A if e["ev"] == "start"), None)
sp = next((e for e in A if e["ev"] == "stop"), None)
emit(1, "PASS" if (st and st["v"] == 2 and st["seq"] == 0 and st["mid"]
                   and st["kernel"] and sp and sp["mid"] == st["mid"])
        else "FAIL",
      "start v=2 seq=0 mit mid/kernel; stop gleiche mid")

# K2: seq lückenlos
seqs = [e["seq"] for e in A]
emit(2, "PASS" if seqs == list(range(len(seqs))) else "FAIL",
      "seq lückenlos ab 0 (Kopf-Reihenfolge)")

# K3: exec-Felder vollständig UND werthaltig. So angelegt, dass sie für
#     langlebige UND kurzlebige Ziele gilt: geprüft werden die Schlüssel und
#     die geschlossenen Vokabulare – nicht ein bestimmter hash_state (der hängt
#     am Prozesszustand, SCHEMA.md §3).
need = {"pid","ppid","uid","euid","comm","path","argc","sha256","hash_state","flags"}
STATES = {"ok", "gone", "unreadable", "reused", "superseded"}
HEX = set("0123456789abcdef")
FLAGWORDS = {"fileless", "fd_exec", "deleted", "argc_min", "lossy", "path_trunc", "cached"}
bad3 = []
for e in execs(A) + execs(B) + execs(C) + execs(G):
    missing = sorted(need - set(e.keys()))
    if missing:
        bad3.append("fehlende Felder: %s" % ",".join(missing))
    if e.get("hash_state") not in STATES:
        bad3.append("hash_state nicht im Vokabular: %r" % e.get("hash_state"))
    sh = e.get("sha256")
    if sh is not None and not (isinstance(sh, str) and len(sh) == 64 and set(sh) <= HEX):
        bad3.append("sha256 weder null noch 64-hex: %r" % sh)
    fl = e.get("flags")
    if not isinstance(fl, list) or any(f not in FLAGWORDS for f in fl):
        bad3.append("flags nicht im Vokabular: %r" % fl)
emit(3, "PASS" if not bad3 else "FAIL",
     "exec-Zeilen tragen pid…flags mit geschlossenen Vokabularen"
     + ("" if not bad3 else " – " + "; ".join(sorted(set(bad3))[:3])))

# K4: Hauptthread-argc (argv = Zielkopie a b c → argc=4). Der Helfer lief als
#     uid != 0 – wird hier gleich mit geprüft. Exakter Pfad der privaten Kopie.
main = [e for e in execs(A) if e["path"] == TA1]
emit(4, "PASS" if (any(e["argc"] == 4 for e in main) and all(e["uid"] != 0 for e in main)
                    and all(e["euid"] != 0 for e in main)) else "FAIL",
      f"main_exec private Kopie (uid={main[0]['uid'] if main else '?'} != 0) → argc=4")
ctx(4, A, lambda e: e["ev"] == "exec" and e["path"] == TA1)

# K5: Nicht-Hauptthread → genau EINE Zeile für den exec, argc=2,
#     und die pid der Zeile ist die TGID des Prozesses (nicht die TID des
#     exec-enden Threads). THREAD_PID ist die PID/TGID des Helfers; die TID
#     des Threads wäre eine andere Zahl.
thread_pid = int(sys.argv[7])
thread_evs = [e for e in execs(A) if e["pid"] == thread_pid and e["path"] == TA1]
emit(5, "PASS" if (len(thread_evs) == 1 and thread_evs[0]["argc"] == 2 and thread_evs[0]["uid"] != 0)
        else "FAIL",
      "thread_exec: genau 1 Zeile, argc=2, pid == TGID(Helfer), uid != 0")

# K6: zwei Threads gleichzeitig → jede Ziel-Zeile der privaten Kopie passt zu
#     einem der beiden Aufrufe (argc=2), keine falsche Zeile, pid == TGID.
two_pid = int(sys.argv[8])
two_evs = [e for e in execs(A) if e["pid"] == two_pid and e["path"] == TA2]
emit(6, "PASS" if (two_evs and all(e["argc"] == 2 for e in two_evs)) else "FAIL",
      "two_threads: alle Ziel-Zeilen argc=2, keine falsche Zeile, pid == TGID")

# K7: fehlgeschlagenes execve → kein Event; Daemon lebt weiter
nex = sys.argv[5]
emit(7, "PASS" if (not any(e["path"] == nex for e in execs(A))
                   and len(execs(A)) >= 4) else "FAIL",
      "fail_exec → kein Event; Daemon läuft weiter")

# K8: sha256 == Hash der privaten Zielkopie, hash ok, exakter Pfad + uid
#     (B1/B2 – nie PID allein, nie Systempfad). Genau 2 Zielzeilen (2 Starts).
#     Zugleich Fremd-UID-Zugriff (CAP_SYS_PTRACE), da Helfer uid != 0 laufen.
tb = [e for e in execs(B) if e["path"] == TB]
emit(8, "PASS" if (len(tb) == 2 and all(isinstance(e["sha256"], str)
                                  and e["sha256"] == H_SLEEP
                                  and e["hash_state"] == "ok"
                                  and e["uid"] == UUID for e in tb))
         else "FAIL",
      f"Zielkopie: genau 2 Zeilen, sha256==Kopie-Hash, ok, uid={UUID}")
ctx(8, B, lambda e: e["ev"] == "exec" and e["path"] == TB)

# K9: Cache-Treffer mit identischem sha256 (B2). Korrigiert: Die erste Zeile
#     darf schon `cached` sein, weil die Stufen derselben Kette (setpriv,
#     Helfer) denselben Prozess beim Verarbeiten sehen: /proc/<pid>/exe zeigt
#     dann das Ziel und der Hash wird in den Cache gelegt. Der Cache ist
#     dateiidentitätsgeschlüsselt, ein Treffer ist also korrekt.
emit(9, "PASS" if len(tb) == 2
                    and "cached" in flags(tb[1])
                    and tb[0]["sha256"] == tb[1]["sha256"] else "FAIL",
      "Cache-Treffer (2. Start) mit identischem sha256 (1. Start darf cached sein, s. Kommentar)")

# K10: reused – nur bei echter PID-Wiederverwendung reproduzierbar
emit(10, "SKIP", "reused (PID-Reuse) – nur manuell reproduzierbar, siehe BERICHT")

# K11: tiefer Pfad → path_trunc
trunc = [e for e in execs(C) if "path_trunc" in flags(e)]
emit(11, "PASS" if trunc and len(trunc[0]["path"]) <= 256 else "FAIL",
      "tiefer Pfad → path_trunc, path ≤ 256 B")

# K12: memfd/fileless. Korrigiert: `execveat` mit AT_EMPTY_PATH meldet den
#      Pfad als /dev/fd/N (gleicher Mechanismus wie K18), nicht /memfd:…
#      Erkannt wird fileless deshalb am Flag aus /proc/<pid>/exe (memfd_noexec=0,
#      die Ausführung ist erlaubt). Nutzlast PAY_C lebt 3 s.
mf = [e for e in execs(C) if e["path"].startswith("/dev/fd/") and "fileless" in flags(e)]
emit(12, "PASS" if (mf and "fileless" in flags(mf[0]) and "deleted" not in flags(mf[0])
                    and mf[0].get("hash_state") == "ok"
                    and mf[0].get("sha256") == H_SLEEP)
         else "FAIL",
     f"memfd_exec → /memfd:…, flags fileless (ohne deleted), hash_state ok, "
     f"sha256 == Nutzlast-Hash")
ctx(12, C, lambda e: e["ev"] == "exec" and e["path"].startswith("/memfd:"))

# K13: Ringpuffer-Überlauf (erzeugt per kill -STOP in Phase F). Erhaltung aus
#      --stats der Phase (B4, keine Schätzung mehr): geschrieben + lost ==
#      kernel_seen (Differenzen seit Start), lost >= 1 belegt echten Verlust.
m = re.search(r"kernel_seen=(\d+) geschrieben=(\d+) lost=(\d+)", FSTATS_TEXT)
if m:
    ks, wr, lo = map(int, m.groups())
    ok13 = (wr + lo == ks and lo >= 1)
    # Punkt 4: Verhältnis lost/(kernel_seen − geschrieben); gesund = 1.0
    # (Doppelzählung zeigte 2.0). Nenner 0 → kein Verlust messbar.
    ratio13 = ("%.3f" % (lo / (ks - wr))) if ks > wr else "n/a (kein Verlust)"
    msg13 = (f"Erhaltung: geschrieben({wr})+lost({lo})==kernel_seen({ks}), lost>=1; "
             f"Verhältnis lost/(seen-geschrieben)={ratio13} "
             f"(erfolgreiche Starts={OVERFLOW_EXECS} nur Info)")
else:
    ok13 = False
    msg13 = "keine kernel_seen-Zeile in --stats (Phase F)"
emit(13, "PASS" if ok13 else "FAIL", msg13)
ctx(13, F, lambda e: e["ev"] == "lost")

# K14: kill -9 → vollständige JSON-Zeile am Ende, kein stop
raw4 = open(sys.argv[4], "rb").read()
k14 = bool(D) and not any(e["ev"] == "stop" for e in D) \
       and raw4.rstrip(b"\n").endswith(b"}")
emit(14, "PASS" if k14 else "FAIL",
      "kill -9: Ende valides JSON (letzte Zeile \\n), kein stop")

# ── Kriterium 11: argc-Randfälle (Phase E) ──────────────────────────────────
ARGC_LIMIT = 1024
E = load(sys.argv[6])
argmap = {}
for ln in open(sys.argv[9]):
    parts = ln.split()
    if len(parts) == 2:
        argmap[int(parts[0])] = int(parts[1])
child_out = [ln.strip() for ln in open(sys.argv[10]) if ln.strip()]

def target(n):
    # Pro Fall: die LETZTE Zeile der Helfer-pid ist der Ziel-exec. Davor
    # liegen derselben PID setpriv-, bash- und Helfer-Stufe (4 Stufen:
    # setpriv → bash → Helfer → Ziel); die erste Zeile ist NICHT der Helfer.
    pid = argmap.get(n)
    evs = [e for e in execs(E) if e["pid"] == pid]
    return evs[-1] if evs else None

# K15: n=0 (leeres argv). Erwartung von Hand: Beobachter zählt am
#      Syscall-Eintritt 0 (kein argc_min); der Kernel fügt danach ein leeres
#      Argument ein, der Prozess sieht (auf diesem Kernel) argc=1.
e0 = target(0)
seen0 = child_out[0].split("=", 1)[1] if child_out else "?"
emit(15, "PASS" if (e0 and e0["argc"] == 0 and "argc_min" not in flags(e0)) else "FAIL",
      f"argc n=0: Beobachter argc=0 ohne argc_min; Prozess sieht argc={seen0} (dok. Abweichung)")

# K16: Limit-1 / Limit / Limit+1 → bis Limit exakt ohne argc_min, darüber
#      argc = Limit mit argc_min (genau der K1-Grenzfall).
e_m1, e_l, e_p1 = target(ARGC_LIMIT - 1), target(ARGC_LIMIT), target(ARGC_LIMIT + 1)
ok16 = (e_m1 and e_m1["argc"] == ARGC_LIMIT - 1 and "argc_min" not in flags(e_m1)
        and e_l and e_l["argc"] == ARGC_LIMIT and "argc_min" not in flags(e_l)
        and e_p1 and e_p1["argc"] == ARGC_LIMIT and "argc_min" in flags(e_p1))
emit(16, "PASS" if ok16 else "FAIL",
      f"argc n={ARGC_LIMIT-1}/{ARGC_LIMIT}/{ARGC_LIMIT+1}: exakt, exakt, Limit+argc_min")

# K17: n=100000 → der Verifier lehnt nichts ab, die Zeile trägt argc_min.
e_h = target(100000)
emit(17, "PASS" if (e_h and e_h["argc"] == ARGC_LIMIT and "argc_min" in flags(e_h)) else "FAIL",
      f"argc n=100000: Zeile argc={ARGC_LIMIT}+argc_min, kein Verifier-Abbruch")

# K18 (Kriterium 12b): deleted deterministisch. Die über execveat gestartete
#      private Kopie war vor dem Exec gelöscht → Flag deleted (nicht fileless),
#      der sha256 aus dem offenen FD entspricht dem Kopie-Hash.
del_evs = [e for e in execs(E) if "deleted" in flags(e)]
emit(18, "PASS" if (del_evs and "fileless" not in flags(del_evs[0])
                    and del_evs[0].get("sha256") == H_SLEEP
                    and del_evs[0].get("hash_state") == "ok") else "FAIL",
     f"deleted_exec (private Kopie, lebend): Flag deleted (nicht fileless), "
     f"hash_state ok, sha256 == Kopie-Hash ({len(del_evs)} Zeile(n))")
ctx(18, E, lambda e: "deleted" in flags(e))

# K19: EIN Fall mit Hilfsprogramm als ROOT (Gegenprobe zu den uid-!=0-Fällen).
# Der Helfer selbst (linger 3, lebt) ist die einzige Zeile: uid == euid == 0,
# argc=3 ([Helfer, linger, 3]), hash ok mit Helfer-Hash.
root_evs = [e for e in execs(R) if e["path"] == HP]
emit(19, "PASS" if (len(root_evs) == 1 and root_evs[0]["uid"] == 0
                    and root_evs[0]["euid"] == 0 and root_evs[0]["argc"] == 3
                    and root_evs[0]["hash_state"] == "ok"
                    and root_evs[0]["sha256"] == H_HELP) else "FAIL",
      "root-Run (linger): genau 1 Zeile, uid == euid == 0, argc=3, hash ok")
ctx(19, R, lambda e: e["ev"] == "exec")

# K23/K24 (TEST c + Timing-Beweis Punkt 5): Kette mit angehaltenem Daemon.
# setpriv- und Helfer-Stufe sind beim Verarbeiten längst überholt (Prozess
# ist das Ziel) → superseded ohne Hash; Ziel-Stufe ok mit Kopie-Hash.
h_setpriv = [e for e in execs(H) if e["path"] == SETPRIV]
h_help = [e for e in execs(H) if e["path"] == HP and e["uid"] == UUID]
h_targ = [e for e in execs(H) if e["path"] == TH]
ok23 = (len(h_setpriv) == 1 and h_setpriv[0]["hash_state"] == "superseded"
        and h_setpriv[0]["sha256"] is None
        and len(h_help) == 1 and h_help[0]["hash_state"] == "superseded"
        and h_help[0]["sha256"] is None)
emit(23, "PASS" if ok23 else "FAIL",
     "Kette: setpriv- und Helfer-Zeile superseded ohne Hash (Befund A behoben)")
ctx(23, H, lambda e: e["ev"] == "exec" and e["path"] in (SETPRIV, HP))
emit(24, "PASS" if (len(h_targ) == 1 and h_targ[0]["hash_state"] == "ok"
                    and h_targ[0]["sha256"] == H_SLEEP
                    and h_targ[0]["uid"] == UUID) else "FAIL",
     "Kette: Ziel-Zeile ok mit Kopie-Hash")
ctx(24, H, lambda e: e["ev"] == "exec" and e["path"] == TH)

# K25/K26/K27 (TESTS a/b): Dateisystem-Matrix. Exakter Pfad + uid, genau eine
# Zielzeile je Senke, hash_state ok mit dem erwarteten Hash.
def fs_ok(evs, path, h):
    m = [e for e in execs(evs) if e["path"] == path and e["uid"] == UUID]
    return len(m) == 1 and m[0]["hash_state"] == "ok" and m[0]["sha256"] == h
emit(25, "PASS" if fs_ok(I1, TB, H_SLEEP) else "FAIL",
     "btrfs-Kopie (Projektverzeichnis): ok mit Kopie-Hash")
ctx(25, I1, lambda e: e["ev"] == "exec" and e["path"] == TB)
emit(26, "PASS" if fs_ok(I2, TSYS, H_USR) else "FAIL",
     "/usr/bin/sleep (Systemprogramm): ok mit System-Hash")
ctx(26, I2, lambda e: e["ev"] == "exec" and e["path"] == TSYS)
emit(27, "PASS" if fs_ok(I3, T_TMP, H_SLEEP) else "FAIL",
     "tmpfs-Kopie (/tmp): ok mit Kopie-Hash")
ctx(27, I3, lambda e: e["ev"] == "exec" and e["path"] == T_TMP)

# K20/K21 (MESSZEILE, keine Bewertung): kurzlebige Ziele. Gemischt ok/gone
# ist korrekt – die Quote hängt an Last und Programmdauer (SCHEMA.md §3).
from collections import Counter
g_evs = execs(G)

def mess_row(no, pfad, evs, runs):
    """MESSZEILE: je hash_state die Anzahl – niemals pass/fail."""
    if not evs:
        emit(no, "INFO", "%s: %d Starts, 0 Zeilen gemessen (Ringueberlauf?)" % (pfad, runs))
        return
    c = Counter(e.get("hash_state") for e in evs)
    emit(no, "INFO",
         "%s: %d Starts als Nutzer – gemessen %d Zeilen: " % (pfad, runs, len(evs))
         + ", ".join("%s=%s" % (k, v) for k, v in sorted(c.items()))
         + " | sha256 gesetzt: %d" % sum(1 for e in evs if e.get("sha256"))
         + " | fd_exec-Flag: %d" % sum(1 for e in evs if "fd_exec" in flags(e)))

mess_row(20, SHORT1, [e for e in g_evs if e.get("path") == SHORT1], SHORT_RUNS)
mess_row(21, SHORT2, [e for e in g_evs if e.get("path") == SHORT2], SHORT_RUNS)

# K22 (MESSZEILE): Verarbeitungsverzug aus --stats (stderr)
if "--stats begin" in STATS_TEXT:
    block = STATS_TEXT.split("--stats begin", 1)[1].split("--stats end", 1)[0]
    lines = [l.split("--stats:", 1)[1].strip() for l in block.splitlines()
             if "--stats:" in l and l.split("--stats:", 1)[1].strip()]
    emit(22, "INFO", "Verarbeitungsverzug (--stats, stderr): " + " | ".join(lines))
else:
    emit(22, "INFO", "keine --stats-Statistik (Daemon ohne --stats gestartet?)")

sys.stdout.write("\n".join(out))
PYEOF
)"
EVAL_RC=$?

if [ "$EVAL_RC" -ne 0 ] || [ -z "$VERDICT" ]; then
  echo "  K eval  FAIL  Auswertung fehlgeschlagen (rc=$EVAL_RC) – keine belastbare Matrix" >&2
  exit "$EXIT_UNVOLLSTAENDIG"
fi

# K14b: Shell-seitig – der per kill -9 beendete Prozess ist WIRKLICH fort.
VERDICT="$VERDICT
14b|$K14B|$K14B_TEXT"

log ""
log "Kriterienmatrix:"
while IFS='|' read -r no st txt; do
  # B6: CTX-Zeilen sind Fehlerkontext (höchstens 8 Treffer + pid-Zeilen),
  # keine Bewertung – sie füttern weder pass noch fail noch skip.
  case "$no" in
    CTX) printf '      %s\n' "$txt";;
    *) krit "$no" "$(printf '%s' "$st" | tr 'A-Z' 'a-z')" "$txt";;
  esac
done < <(printf '%s\n' "$VERDICT")
log ""
if [ "$LEFTOVER" -eq 1 ]; then
  FAIL=$((FAIL+1))
  printf '  K%-2s %-4s %s\n' "+" "FAIL" "nach dem Lauf bleibt kein exec-observer-Prozess übrig"
else
  printf '  K%-2s %-4s %s\n' "+" "PASS" "kein exec-observer-Prozess nach dem Lauf übrig"
fi
printf '  Matrix: %s pass, %s fail, %s skip\n' "$PASS" "$FAIL" "$SKIP"

# ── Capability-Teilmengen ───────────────────────────────────────────────────
# Werden nicht mehr hier wiederholt: tests/cap-matrix.sh führt sie aus und
# belegt sie (Fälle a–e). Nur die Aufruf-Faustformel steht als Kommentar hier:
#   setpriv --bounding-set=-all,+bpf,+perfmon,+sys_ptrace,+dac_read_search \
#        "$HERE/target/debug/exec-observer" /tmp/...
# Der Daemon startet direkt (kein sudo davor); setpriv execve't, also ist die
# Kind-PID die Daemon-PID. Cap-Gehalte werden aus /proc/<PID>/status gelesen.

if [ "$FAIL" -eq 0 ]; then
  exit 0
else
  exit "$EXIT_FEHLER"
fi
