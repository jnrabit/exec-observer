"""Seed-Skript: exec-observer-Ledger als Ossifikat-Triples (STAGING only).

Gebrauch (menschliches Gate bleibt!), aus dem Repo-Wurzelverzeichnis:
    python3 ledger/seed.py                 # DB: ledger/data/ossifikat.db
    PYTHONPATH=ledger python3 -m ossifikat.cli review --db ledger/data/ossifikat.db

Review-Ermüdungs-Design:
- ALLES landet in Staging, nichts wird bestätigt (kein stilles Vergiften).
- Jede Source trägt den BELEG (Lauf, Datei, Code-Stelle), nicht nur ein Label.
- Confidence hat definierte Bedeutung: 1.0 = Lauf-belegt, 0.8 = Code-Review,
  0.6 = Annahme/beobachtet. Damit ist "was denkst du dazu" pro Gruppe schon
  beantwortet; Review = Veto, nicht Gutachten.

Prädikat-Konvention (klein, fest):
  status            -> belegt | behoben-und-bestaetigt | widerlegt |
                     beobachtet-Annahme | Annahme | offen | gegenstandslos |
                     Entwurf-ungetestet
  belegt_durch      -> Evidenz (Lauf, Test, Review)
  offenes_experiment-> genau ein diskriminierendes Experiment
  haengt_ab_von     -> anderes Subject (Stern-Kanten)
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ossifikat.store import OssifikatStore

SRC = "exec-observer-ledger-2026-10-12"

# (subject, predicate, object, confidence, Gruppe)
TRIPLES = [
    # --- Gruppe A: Erhaltungsgleichung (empfehle: bestätigen) ---
    ("exec-observer/erhaltung", "status", "belegt", 1.0),
    ("exec-observer/erhaltung", "belegt_durch", "cap-matrix Läufe 6-8, alle Mengen exakt (1.000)", 1.0),
    ("exec-observer/drops-doppelzaehlung", "status", "behoben-und-bestaetigt", 1.0),
    ("exec-observer/drops-doppelzaehlung", "belegt_durch", "Sensor-Fix + Verhältnis 2.000->1.000", 1.0),
    ("exec-observer/consume-then-break", "status", "behoben-und-bestaetigt", 1.0),
    ("exec-observer/consume-then-break", "belegt_durch", "Lauf 7: s2/s4 grün nach Fix (vorher 5x -1)", 1.0),
    ("exec-observer/k13-gleichung", "status", "belegt", 1.0),
    ("exec-observer/k13-gleichung", "belegt_durch", "K13-Root-Läufe + Smoke-Test synthetische Senken", 1.0),
    ("exec-observer/rauschen-konsistent", "status", "belegt", 1.0),
    ("exec-observer/rauschen-konsistent", "belegt_durch", "kernel_seen 1350+-50 über Läufe, Gleichung hält", 0.8),
    # --- Gruppe B: Capabilities (empfehle: bestätigen) ---
    ("exec-observer/cap-bpf-laufzeit", "status", "widerlegt", 1.0),
    ("exec-observer/cap-bpf-laufzeit", "belegt_durch", "over_nobpf 2x: null Caps, volle Funktion, exakt", 1.0),
    ("exec-observer/sys-ptrace", "status", "belegt", 1.0),
    ("exec-observer/sys-ptrace", "belegt_durch", "Matrix s2/s4-ok vs s1/s3-unreadable (a1000/aroot)", 1.0),
    ("exec-observer/dac-read-search", "status", "belegt", 1.0),
    ("exec-observer/dac-read-search", "belegt_durch", "Fall b0711: s4-ok vs s2-unreadable", 1.0),
    ("exec-observer/dumpable-setuid", "status", "belegt", 1.0),
    ("exec-observer/dumpable-setuid", "belegt_durch", "Fall c: s2/s4-ok vs s1/s3-unreadable", 1.0),
    ("exec-observer/perfmon-nur-laden", "status", "belegt", 1.0),
    ("exec-observer/perfmon-nur-laden", "belegt_durch", "Fall f: EPERM ohne, läuft mit", 1.0),
    ("exec-observer/root-ohne-ptrace", "status", "beobachtet-Annahme", 0.6),
    ("exec-observer/root-ohne-ptrace", "belegt_durch", "Fall aroot s1/s3-unreadable; Ursache ungeklärt", 0.6),
    # --- Gruppe C: geprüfte Grundlagen (empfehle: bestätigen) ---
    ("exec-observer/aya-consumer-still", "status", "belegt", 0.8),
    ("exec-observer/aya-consumer-still", "belegt_durch", "Code-Review aya 0.14 maps/ring_buf.rs", 0.8),
    ("exec-observer/kernel-ringbuf", "status", "Annahme", 0.6),
    ("exec-observer/kernel-ringbuf", "belegt_durch", "keine Quellen installiert, Standardpfad unauffällig", 0.6),
    # --- Gruppe D: Stern-Kanten (empfehle: bestätigen) ---
    ("exec-observer/k13-gleichung", "haengt_ab_von", "exec-observer/erhaltung", 1.0),
    ("exec-observer/consume-then-break", "haengt_ab_von", "exec-observer/erhaltung", 1.0),
    ("exec-observer/drops-doppelzaehlung", "haengt_ab_von", "exec-observer/erhaltung", 1.0),
    # --- Gruppe E: Offen (empfehle: liegen lassen bis Experiment) ---
    ("exec-observer/exe-identitaet-laufzeit", "status", "offen", 0.8),
    ("exec-observer/exe-identitaet-laufzeit", "offenes_experiment", "Integration Phase H K23/K24", 1.0),
    ("exec-observer/integration-matrix", "status", "offen", 0.8),
    ("exec-observer/integration-matrix", "offenes_experiment", "TESTREIHE Stufe 1: sudo tests/integration.sh", 1.0),
    ("exec-observer/stern-form", "status", "Entwurf-ungetestet", 0.8),
    ("exec-observer/stern-form", "offenes_experiment", "STERN.md-Testprotokoll im Integrationslauf", 1.0),
    ("exec-observer/keep-wanted-verengung", "status", "offen-entscheidung-ausstehend", 0.8),
    ("exec-observer/reused-k10", "status", "offen-manuell", 0.8),
    ("exec-observer/fall-c-d2", "status", "offen-deaktiviert", 0.8),
    ("exec-observer/interleave-hypothese", "status", "gegenstandslos", 1.0),
    ("exec-observer/interleave-hypothese", "belegt_durch", "Fall geschlossen ohne sie (Lauf 7)", 1.0),
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "ossifikat.db"), help="Ziel-DB")
    args = ap.parse_args()

    store = OssifikatStore(args.db)
    ids = []
    for subject, predicate, obj, conf in TRIPLES:
        ids.append(
            store.add_staging(
                subject=subject,
                predicate=predicate,
                object=obj,
                source=SRC,
                confidence=conf,
            )
        )
    print(f"{len(ids)} Triples in Staging gelegt (DB: {args.db})")
    print("Weiter mit: PYTHONPATH=ledger python3 -m ossifikat.cli review --db " + args.db)
    store.close()


if __name__ == "__main__":
    main()
