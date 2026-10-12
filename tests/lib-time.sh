# tests/lib-time.sh – Zeit- und Warte-Helfer ohne neue Prozesse.
#
# Alles hier ist reine Bash-Builtin-Arbeit (kein sleep/grep/date): Während ein
# Daemon lauscht, würde jeder externe Prozess als Ereignis auftauchen und ggf.
# den Hash-Cache wärmen (B5). Fristen kommen aus $EPOCHREALTIME (bash ≥ 5).
#
# Locale-Härtung: $EPOCHREALTIME nutzt im deutschen Locale ein Komma
# (1791792331,854623); ${EPOCHREALTIME%%.*} scheiterte daran mit
# „Ganzzahl erwartet“. now_s() schneidet Punkt UND Komma ab. Zusätzlich setzen
# beide Skripte LC_ALL=C, damit es gar nicht erst dazu kommt.

# now_s – ganze Sekunden seit der Epoche in $NOW_S (global, kein Fork).
now_s() {
  NOW_S="${EPOCHREALTIME%%[.,]*}"
}

# wait_for_content <datei> <muster> [sekunden] – 0, sobald der Dateiinhalt das
# Muster enthält. $(<...) forkt nicht.
wait_for_content() { # wait_for_content <datei> <muster> [sekunden]
  local file="$1" pat="$2" end content
  now_s; end=$(( NOW_S + ${3:-10} ))
  while :; do
    now_s; [ "$NOW_S" -ge "$end" ] && return 1
    content=$(<"$file" 2>/dev/null) || content=""
    case "$content" in *"$pat"*) return 0;; esac
  done
}

# wait_for_lines <datei> <mindest-zeilen> [sekunden] – mapfile ist ein Builtin.
wait_for_lines() { # wait_for_lines <datei> <mindest-zeilen> [sekunden]
  local file="$1" want="$2" end lines
  now_s; end=$(( NOW_S + ${3:-10} ))
  while :; do
    now_s; [ "$NOW_S" -ge "$end" ] && return 1
    mapfile -t lines < "$file" 2>/dev/null || lines=()
    [ "${#lines[@]}" -ge "$want" ] && return 0
  done
}

# wait_for_quiescence <datei> <mindest-zeilen> [sekunden] – 0, sobald die
# Zeilenzahl stabil bleibt (zweimal gleich). Warten urteilt nie.
wait_for_quiescence() { # wait_for_quiescence <datei> <mindest-zeilen> [sekunden]
  local file="$1" want="$2" end lines n last=-1 stable=0
  now_s; end=$(( NOW_S + ${3:-15} ))
  while :; do
    now_s; [ "$NOW_S" -ge "$end" ] && return 1
    mapfile -t lines < "$file" 2>/dev/null || lines=()
    n="${#lines[@]}"
    if [ "$n" -ge "$want" ] && [ "$n" -eq "$last" ]; then
      stable=$((stable+1))
      [ "$stable" -ge 2 ] && return 0
    else
      stable=0
    fi
    last="$n"
  done
}
