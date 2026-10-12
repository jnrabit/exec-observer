#!/usr/bin/env bash
# tests/lib-temp.sh – gemeinsame Temp-Verwaltung für tests/integration.sh,
# tests/cap-matrix.sh und tests/temp-selftest.sh.
#
# Regel, die hier erzwungen wird: Funktionen, die ein Temp-Verzeichnis anlegen,
# müssen im AUFRUFENDEN Shell-Prozess laufen. Wird ihr Ergebnis über $(...)
# geholt, läuft die Funktion in einer Unterschale – jede Zuweisung an TEMPS
# landet dort und ist im Elternprozess verloren. Genau daran lag es, dass nach
# einem Lauf sechs /tmp/exec-observer-it.*-Verzeichnisse stehen blieben:
# new_sink wurde als SINK="$(new_sink)" aufgerufen, die Temps standen also nur
# in der Unterschale.
#
# Konsequenz: new_sink schreibt ihren Pfad in die globale Variable SINK_PATH
# und meldet Erfolg über den Rückgabewert – nicht über stdout.

TEMPPREFIX="${TEMPPREFIX:-/tmp/exec-observer}"
TEMPS=()
SINK_PATH=""

# register_temp <pfad> – nur im Elternprozess aufrufen (nicht aus $(...)).
register_temp() {
    [ -n "$1" ] || return 1
    TEMPS+=("$1")
}

# new_sink – legt ein 0700-Verzeichnis mit einer Senke an, setzt SINK_PATH.
# Aufruf:  new_sink || die "...";  start_daemon "$SINK_PATH"
new_sink() {
    local d
    d="$(mktemp -d "${TEMPPREFIX}-it.XXXXXX")" || return 1
    chmod 700 "$d"
    register_temp "$d"
    SINK_PATH="$d/exec.log"
}

# new_dir <suffix> – legt ein weiteres 0700-Verzeichnis im Temp-Bereich an,
# setzt DIR_PATH. Für NONEXEC/ARGMAP/ARGCOUT/DEEPROOT.
new_dir() {
    local d
    d="$(mktemp -d "${TEMPPREFIX}-${1:-dir}.XXXXXX")" || return 1
    chmod 700 "$d"
    register_temp "$d"
    DIR_PATH="$d"
}

# new_file <suffix> – legt eine Datei (0600) im Temp-Bereich an, setzt
# FILE_PATH.
new_file() {
    local d
    d="$(mktemp "${TEMPPREFIX}-${1:-file}.XXXXXX")" || return 1
    chmod 0600 "$d"
    register_temp "$d"
    FILE_PATH="$d"
}

# cleanup_temps – räumt alles aus TEMPS ab. ${d:?} bricht bei leerem Pfad ab,
# damit ein Bug im Buchführen nicht nach /tmp/ oder / löscht.
cleanup_temps() {
    if [ "${#TEMPS[@]}" -gt 0 ]; then
        local d
        for d in "${TEMPS[@]}"; do rm -rf -- "${d:?}"; done
    fi
    TEMPS=()
}

# temps_still_present – gibt registrierte Pfade aus, die noch existieren.
# Dient dem Selbsttest (ohne Root) und der Abschlussprüfung der Skripte.
temps_still_present() {
    local d
    for d in ${TEMPS[@]+"${TEMPS[@]}"}; do
        [ -e "$d" ] && printf '%s\n' "$d"
    done
    return 0
}
