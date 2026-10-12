"""Prüfungen für das Ledger (ohne Abhängigkeiten, Lauf: python3 ledger/test_ledger.py).

Geprüft werden Invarianten, nicht Inhalte:
  1. Seed ist idempotent (zweiter Lauf legt nichts an)     – in Wegwerf-Kopie
  2. Keine doppelte Aussage (subject, predicate, object, source)
  3. Jede Bestätigung hat eine existierende Triple-Zeile    (keine Waisen)
  4. Jede Aussage mit staging=0 hat mindestens eine Bestätigung
  5. Staging und Bestätigung schließen sich aus (staging=0 <=> bestätigt)
  6. query_at liefert für die Gegenwart dasselbe wie query(only_confirmed)

Die echte DB wird nur gelesen. Der Seed-Test läuft in einer Kopie.
"""

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from ossifikat.store import OssifikatStore  # noqa: E402

REAL_DB = os.path.join(HERE, "data", "ossifikat.db")
fails = []


def check(name, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + name + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        fails.append(name)


def test_seed_idempotent():
    tmp = tempfile.mkdtemp(prefix="ledger-test-")
    try:
        shutil.copytree(HERE, os.path.join(tmp, "ledger"), ignore=shutil.ignore_patterns("data", "__pycache__"))
        seed = os.path.join(tmp, "ledger", "seed.py")
        db = os.path.join(tmp, "ledger", "data", "t.db")
        for _ in range(2):
            subprocess.run([sys.executable, seed, "--db", db], check=True, capture_output=True)
        s = OssifikatStore(db)
        n = s.conn.execute("SELECT COUNT(*) FROM triples").fetchone()[0]
        s.close()
        check("Seed idempotent (2 Läufe = 1 Lauf)", n == 40, f"Zeilen={n}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_real_db_invariants():
    if not os.path.exists(REAL_DB):
        check("echte DB vorhanden", False, REAL_DB)
        return
    s = OssifikatStore(REAL_DB)
    c = s.conn
    q = lambda sql: c.execute(sql).fetchone()[0]  # noqa: E731

    dups = q("""SELECT COUNT(*) FROM (SELECT 1 FROM triples
                GROUP BY subject, predicate, object, source HAVING COUNT(*) > 1)""")
    check("keine doppelte Aussage", dups == 0, f"Gruppen={dups}")

    orphans = q("""SELECT COUNT(*) FROM confirmations cf WHERE NOT EXISTS
                   (SELECT 1 FROM triples t WHERE t.content_hash = cf.triple_hash)""")
    check("keine verwaisten Bestätigungen", orphans == 0, f"Waisen={orphans}")

    confirmed_no_record = q("""SELECT COUNT(*) FROM triples t WHERE t.staging = 0 AND NOT EXISTS
                               (SELECT 1 FROM confirmations cf WHERE cf.triple_hash = t.content_hash)""")
    check("jede nicht-staging-Aussage hat Bestätigung", confirmed_no_record == 0,
          f"ohne={confirmed_no_record}")

    staged_with_record = q("""SELECT COUNT(*) FROM triples t WHERE t.staging = 1 AND EXISTS
                              (SELECT 1 FROM confirmations cf WHERE cf.triple_hash = t.content_hash)""")
    check("Staging und Bestätigung schließen sich aus", staged_with_record == 0,
          f"beides={staged_with_record}")

    try:
        by_time = {t.id for t in s.query_at("9999-12-31T23:59:59+00:00")}
        by_query = {t.id for t in s.query(only_confirmed=True)}
        check("query_at(Zukunft) == query(bestätigt)", by_time == by_query,
              f"query_at={len(by_time)} query={len(by_query)}")
    except Exception as e:  # noqa: BLE001
        check("query_at läuft", False, repr(e))
    s.close()


if __name__ == "__main__":
    test_seed_idempotent()
    test_real_db_invariants()
    print()
    if fails:
        print(f"{len(fails)} FAIL: {', '.join(fails)}")
        sys.exit(1)
    print("alle Prüfungen grün")
