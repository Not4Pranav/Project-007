from __future__ import annotations

import csv
import json
import sqlite3
import unittest

from seeds.db import connect, get_meta
from seeds.export import main
from tests._support import seed_db


class ExportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.db = seed_db("export", users=500, inject_bots=40, events=0.5)
        cls.out = cls.db.parent / "exported"
        code = main(["--db", str(cls.db), "--out", str(cls.out),
                     "--tables", "users,credentials,events,invite_edges", "--format", "csv,jsonl", "--quiet"])
        assert code == 0

    def read_csv(self, table: str) -> list[dict]:
        with (self.out / f"{table}.csv").open(newline="") as fh:
            return list(csv.DictReader(fh))

    def test_row_counts_match_source(self) -> None:
        conn = connect(self.db)
        try:
            for table in ("users", "credentials", "events", "invite_edges"):
                src = conn.execute(f"SELECT COUNT(*) c FROM {table}").fetchone()["c"]
                self.assertEqual(len(self.read_csv(table)), src, table)
        finally:
            conn.close()

    def test_header_order_matches_manifest_and_schema(self) -> None:
        manifest = json.loads((self.out / "export.json").read_text())
        with (self.out / "users.csv").open(newline="") as fh:
            header = fh.readline().strip().split(",")
        self.assertEqual(header[0], "id")
        self.assertIn("is_synthetic_abuse", header)
        self.assertEqual(header, manifest["tables"]["users"]["columns"])

    def test_manifest_records_provenance(self) -> None:
        manifest = json.loads((self.out / "export.json").read_text())
        conn = connect(self.db)
        try:
            self.assertEqual(manifest["fixture_hash"], get_meta(conn, "fixture_hash"))
        finally:
            conn.close()
        self.assertEqual(manifest["format"], ["csv", "jsonl"])
        self.assertGreater(manifest["tables"]["users"]["rows"], 100)

    def test_nulls_and_blobs_use_postgres_text_conventions(self) -> None:
        rows = self.read_csv("users")
        self.assertTrue(any(r["invited_by"] == "\\N" for r in rows), "NULL must serialize as \\N")
        cred = self.read_csv("credentials")[0]
        self.assertTrue(cred["salt"].startswith("\\x") and len(cred["salt"]) == 34, cred["salt"])
        self.assertTrue(cred["hash"].startswith("\\x"))
        self.assertEqual(cred["algo"], "sha256_fast")
        # jsonl form: None and hex without the \\x marker
        line = json.loads((self.out / "credentials.jsonl").open().readline())
        self.assertEqual(len(line["salt"]), 32)
        self.assertTrue(all(c in "0123456789abcdef" for c in line["hash"]))

    def test_jsonl_parses_line_by_line(self) -> None:
        lines = (self.out / "users.jsonl").open().read().strip().splitlines()
        self.assertGreater(len(lines), 100)
        for raw in lines[:50]:
            obj = json.loads(raw)
            self.assertEqual(obj["email_domain"], obj["email"].rsplit("@", 1)[-1])
            self.assertIsInstance(obj["signup_ts"], int)

    def test_the_csv_is_actually_loadable(self) -> None:
        """Not 'looks like CSV': load the export into a fresh database and prove
        the rows survive, which is the only test that catches quoting bugs."""
        target = self.db.parent / "loaded.db"
        conn = sqlite3.connect(target)
        conn.execute("""CREATE TABLE users (
            id INTEGER PRIMARY KEY, username TEXT, email TEXT, email_domain TEXT, display_name TEXT,
            dob TEXT, country TEXT, region TEXT, timezone TEXT, locale TEXT, signup_ts INTEGER,
            signup_ip TEXT, signup_ua TEXT, device_class TEXT, source TEXT, invited_by INTEGER,
            status TEXT, verified_ts INTEGER, has_phone INTEGER, newsletter INTEGER, bio TEXT,
            avatar_seed TEXT, is_synthetic_abuse INTEGER)""")
        rows = self.read_csv("users")
        for r in rows:
            placeholders = ", ".join("?" for _ in range(len(r)))
            conn.execute(f"INSERT INTO users VALUES ({placeholders})",
                         [None if v == "\\N" else v for v in r.values()])
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], len(rows))
        src = connect(self.db).execute(
            "SELECT id, username, email, signup_ts, status, invited_by FROM users ORDER BY id"
        ).fetchall()
        got = conn.execute(
            "SELECT id, username, email, signup_ts, status, invited_by FROM users ORDER BY id").fetchall()
        self.assertEqual([tuple(r) for r in src], [tuple(r) for r in got])
        # integers must not have arrived as text
        self.assertIsInstance(conn.execute("SELECT signup_ts FROM users LIMIT 1").fetchone()[0], int)
        conn.close()

    def test_no_plaintext_credentials_anywhere(self) -> None:
        blob = "".join(p.read_text() for p in self.out.glob("*") if p.suffix in (".csv", ".jsonl", ".sql", ".json"))
        for banned in ("Fixture-Test-Pass", "password_hash", "\"password\""):
            self.assertNotIn(banned, blob)

    def test_loader_script_is_generated(self) -> None:
        sql = (self.out / "import.postgres.sql").read_text()
        self.assertIn("\\copy users", sql)
        self.assertIn("NULL '\\N'", sql)
        self.assertIn("setval(pg_get_serial_sequence('users', 'id')", sql,
                      "explicit ids need a sequence bump or the app's next insert collides")

    def test_limit_and_where_narrow_the_output(self) -> None:
        out = self.db.parent / "limited"
        code = main(["--db", str(self.db), "--out", str(out), "--tables", "users", "--limit", "25", "--quiet"])
        self.assertEqual(code, 0)
        with (out / "users.csv").open(newline="") as fh:
            self.assertEqual(len(list(csv.DictReader(fh))), 25)

        out2 = self.db.parent / "filtered"
        code = main(["--db", str(self.db), "--out", str(out2), "--tables", "users",
                     "--where", "status='active'", "--quiet"])
        self.assertEqual(code, 0)
        with (out2 / "users.csv").open(newline="") as fh:
            rows = list(csv.DictReader(fh))
        self.assertTrue(rows and all(r["status"] == "active" for r in rows))

    def test_bad_table_and_format_are_rejected(self) -> None:
        self.assertEqual(main(["--db", str(self.db), "--tables", "secrets"]), 2)
        self.assertEqual(main(["--db", str(self.db), "--format", "parquet"]), 2)

    def test_split_writes_parallel_loadable_chunks(self) -> None:
        out = self.db.parent / "chunked"
        code = main(["--db", str(self.db), "--out", str(out), "--tables", "users", "--split", "--quiet"])
        self.assertEqual(code, 0)
        chunks = sorted(out.glob("users.[0-9][0-9][0-9].csv"))
        self.assertTrue(chunks, "expected at least one chunk file")
        total = sum(len(c.open().read().splitlines()) - 1 for c in chunks)
        self.assertEqual(total, len(self.read_csv("users")))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
