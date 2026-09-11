"""Print the fixture report for an existing database.

    python -m seeds.report_cli --db var/test.db [--entropy]
"""

from __future__ import annotations

import argparse

from .db import connect, table_counts
from .report import entropy_report, render


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m seeds.report_cli", description=__doc__)
    p.add_argument("--db", default="var/test.db")
    p.add_argument("--entropy", action="store_true",
                   help="also show the lowest-entropy email local parts per domain")
    a = p.parse_args(argv)
    conn = connect(a.db)
    try:
        print(render(conn, counts=table_counts(conn)))
        if a.entropy:
            print("\nLOWEST-ENTROPY EMAIL DOMAINS (bits/char of the local part)")
            for domain, ent in entropy_report(conn):
                print(f"  {domain:<28}{ent:6.2f}")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
