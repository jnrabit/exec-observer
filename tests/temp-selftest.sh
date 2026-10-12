#!/usr/bin/env bash
# =============================================================================
# tests/temp-selftest.sh – Selbsttest der Temp-Verwaltung (OHNE ROOT)
#
# Belegt, was nach den ersten Root-Läufen fehlschlug: Nach einem Lauf blieben
# sechs /tmp/exec-observer-it.*-Verzeichnisse stehen, weil new_sink in einer
# Unterschale ($(...)) lief und die Liste der Temp-Verzeichnisse dort landete.
#
# Prüft ohne Root und ohne eBPF:
#   1. new_sink setzt SINK_PATH (kein stdout) und TEMPS wächst im ELTERNprozess
#   2. alle acht Pfade eines Laufs (6 Senken + Deep-Dir + Dateien) sind in TEMPS
#   3. cleanup_temps löscht alles; kein registrierter Pfad existiert danach
#   4. /tmp enthält nach dem Lauf keinen neuen exec-observer-*-Pfad
#   5. der rm -rf-Wächter (${d:?}) bricht bei leerem Pfad ab statt zu löschen
# =============================================================================
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib-temp.sh
. "$HERE/lib-temp.sh"

FAIL=0; PASS=0
ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }

echo "temp-selftest.sh – Temp-Verwaltung (kein Root nötig)"

BEFORE="$(ls -d "${TEMPPREFIX}"-* 2>/dev/null | sort | md5sum | cut -d' ' -f1)"

# ── 1. new_sink im Elternprozess ────────────────────────────────────────────
N0=${#TEMPS[@]}
new_sink || bad "new_sink meldet Fehler"
if [ -n "$SINK_PATH" ] && [ -d "${SINK_PATH%/exec.log}" ]; then
    ok "new_sink setzt SINK_PATH (kein Kommando-Substitution im Aufruf nötig)"
else
    bad "SINK_PATH ist kein Verzeichnis: '$SINK_PATH'"
fi
if [ "${#TEMPS[@]}" -eq $((N0 + 1)) ]; then
    ok "TEMPS wächst im Elternprozess (Aufruf ohne Unterschale)"
else
    bad "TEMPS blieb auf ${#TEMPS[@]} (Unterschale?) – das ist der alte Fehler"
fi

# ── 2. Pfade eines vollständigen Laufs ──────────────────────────────────────
for _ in 1 2 3 4 5; do new_sink || bad "new_sink (Phase-Run)"; done
new_dir deep    || bad "new_dir deep"
new_file argmap || bad "new_file argmap"
new_file nonex  || bad "new_file nonex"
NEEDED=9
if [ "${#TEMPS[@]}" -eq "$NEEDED" ]; then
    ok "alle $NEEDED Pfade eines Laufs sind registriert"
else
    bad "${#TEMPS[@]} von $NEEDED Pfaden registriert"
fi
MISSING=0
for d in ${TEMPS[@]+"${TEMPS[@]}"}; do
    [ -d "$d" ] || [ -f "$d" ] || { bad "registrierter Pfad existiert nicht: $d"; MISSING=$((MISSING+1)); }
done
[ "$MISSING" -eq 0 ] && ok "jeder registrierte Pfad existiert vor dem cleanup"

# ── 3. cleanup räumt ab ─────────────────────────────────────────────────────
cleanup_temps
LEFT="$(temps_still_present)"
if [ -z "$LEFT" ] && [ "${#TEMPS[@]}" -eq 0 ]; then
    ok "cleanup_temps löscht alle registrierten Pfade und leert die Liste"
else
    bad "nach cleanup übrig bzw. Liste nicht leer: ${LEFT:-<leer>} (${#TEMPS[@]} Einträge)"
fi

# ── 4. nichts Neues unter /tmp ──────────────────────────────────────────────
AFTER="$(ls -d "${TEMPPREFIX}"-* 2>/dev/null | sort | md5sum | cut -d' ' -f1)"
if [ "$AFTER" = "$BEFORE" ]; then
    ok "unter ${TEMPPREFIX}-* steht nach dem Selbsttest nichts Neues"
else
    bad "unter ${TEMPPREFIX}-* wurde etwas liegen gelassen"
fi

# ── 5. rm -rf-Wächter ───────────────────────────────────────────────────────
# ${d:?} muss bei leerem Pfad abbrechen – sonst wäre rm -rf -- "" gefährlich.
GUARD_RC=0
(
    set -u
    d=""
    # shellcheck disable=SC2086
    rm -rf -- "${d:?}" 2>/dev/null
) && GUARD_RC=0 || GUARD_RC=$?
if [ "$GUARD_RC" -ne 0 ]; then
    ok "leerer Pfad bricht \${d:?} ab (rc=$GUARD_RC), statt rm -rf laufen zu lassen"
else
    bad "leerer Pfad wurde nicht abgefangen (rc=0)"
fi

echo "  Matrix: $PASS pass, $FAIL fail"
[ "$FAIL" -eq 0 ]
