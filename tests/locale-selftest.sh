#!/usr/bin/env bash
# =============================================================================
# tests/locale-selftest.sh – Locale-Härtung der Zeit-Helfer (OHNE ROOT)
#
# Belegt den Fund aus dem ersten aussagekräftigen Lauf: $EPOCHREALTIME nutzt
# im deutschen Locale ein Komma (1791792331,854623); ${EPOCHREALTIME%%.*}
# scheiterte daran mit „Ganzzahl erwartet“, bevor überhaupt ein Fall lief.
#
# Prüft ohne Root und ohne eBPF, dass sich tests/lib-time.sh unter
# LC_ALL=de_DE.UTF-8 genauso verhält wie unter LC_ALL=C. Ist das deutsche
# Locale nicht installiert, skip mit Grund (kein Fehlschlag).
# Hinweis: grep/locale laufen hier VOR jedem Daemon – B5 gilt erst, sobald
# ein Daemon lauscht.
# =============================================================================
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib-time.sh
. "$HERE/lib-time.sh"

FAIL=0; PASS=0; SKIPPED=0
ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }
skip() { SKIPPED=$((SKIPPED+1)); printf '  SKIP  %s\n' "$1"; }

echo "locale-selftest.sh – Zeit-Helfer unter de_DE.UTF-8 vs C (kein Root nötig)"

if ! locale -a 2>/dev/null | grep -qi '^de_DE\.utf-\?8$'; then
  skip "de_DE.UTF-8 nicht installiert (locale -a) – kein Vergleich möglich"
  echo "  Matrix: $PASS pass, $FAIL fail, $SKIPPED skip"
  [ "$FAIL" -eq 0 ]
  exit "$?"
fi

check_locale() { # <locale> – now_s muss eine reine Ganzzahl liefern
  local loc="$1"
  LC_ALL="$loc" now_s
  case "$NOW_S" in
    ''|*[!0-9]*)
      bad "now_s unter $loc keine Ganzzahl: '$NOW_S' (EPOCHREALTIME='$EPOCHREALTIME')"
      return 1;;
  esac
  ok "now_s unter $loc ist Ganzzahl ($NOW_S)"
  # Arithmetik wie in den Warte-Helfern muss gelingen.
  local end=$(( NOW_S + 10 ))
  [ "$end" -gt "$NOW_S" ] || {
    bad "Frist-Arithmetik unter $loc gescheitert"; return 1; }
  ok "Frist-Arithmetik unter $loc gelingt"
}

check_locale C
check_locale de_DE.UTF-8

# wait_for_content unter deutschem Locale auf einer Temp-Datei (Verhalten wie C).
TMPF="$(mktemp "${TMPDIR:-/tmp}/locale-selftest.XXXXXX")" || {
  bad "mktemp fehlgeschlagen"; echo "  Matrix: $PASS pass, $FAIL fail"; [ "$FAIL" -eq 0 ]; exit "$?"; }
printf 'start\n  {"ev":"start"}\n' >"$TMPF"
LC_ALL=de_DE.UTF-8 wait_for_content "$TMPF" '"ev":"start"' 5 \
  && ok "wait_for_content findet start unter de_DE.UTF-8" \
  || bad "wait_for_content scheitert unter de_DE.UTF-8"
LC_ALL=de_DE.UTF-8 wait_for_lines "$TMPF" 2 5 \
  && ok "wait_for_lines zählt 2 Zeilen unter de_DE.UTF-8" \
  || bad "wait_for_lines scheitert unter de_DE.UTF-8"
rm -f -- "$TMPF"

echo "  Matrix: $PASS pass, $FAIL fail, $SKIPPED skip"
[ "$FAIL" -eq 0 ]
