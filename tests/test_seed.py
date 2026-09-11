from __future__ import annotations

import datetime as dt
import unittest

from seeds.db import connect, get_meta
from seeds.profile import PasswordPolicy, verify_password
from tests._support import seed_db


class SeederTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.db = seed_db("core")
        cls.conn = connect(cls.db)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.conn.close()

    def q(self, sql, args=()):
        return self.conn.execute(sql, args).fetchall()

    def test_row_counts_match_request(self) -> None:
        n = self.q("SELECT COUNT(*) c FROM users")[0]["c"]
        self.assertEqual(n, 900)
        self.assertEqual(self.q("SELECT COUNT(*) c FROM credentials")[0]["c"], n)
        self.assertGreater(self.q("SELECT COUNT(*) c FROM events")[0]["c"], n)

    def test_usernames_and_emails_unique(self) -> None:
        for table in ("username", "email"):
            dupes = self.q(f"SELECT {table}, COUNT(*) c FROM users GROUP BY 1 HAVING c > 1")
            self.assertEqual(dupes, [], f"duplicate {table}s: {[dict(r) for r in dupes][:3]}")

    def test_signup_timestamps_stay_inside_window(self) -> None:
        params = __import__("json").loads(get_meta(self.conn, "seed_params"))
        row = self.q("SELECT MIN(signup_ts) a, MAX(signup_ts) b, COUNT(*) c FROM users")[0]
        lo, hi, n = row["a"], row["b"], row["c"]
        self.assertGreaterEqual(lo, params["start"])
        self.assertLess(hi, params["end"])
        self.assertEqual(n, params["users"])

    def test_age_floor_is_enforced(self) -> None:
        """13 is the line most consumer ToS use; a fixture that ignores it
        silently opts the app out of ever testing its own age gate."""
        today = dt.date(2026, 9, 11)
        bad = 0
        for r in self.q("SELECT dob FROM users"):
            y, m, d = (int(x) for x in r["dob"].split("-"))
            age = today.year - y - ((today.month, today.day) < (m, d))
            if age < 13:
                bad += 1
        self.assertEqual(bad, 0)

    def test_password_hash_roundtrip(self) -> None:
        """Regression: the seeder once recorded `iterations` that did not match
        how the hash was actually derived, so every fixture login 401'd."""
        rows = self.q(
            "SELECT u.id, cr.algo, cr.salt, cr.iterations, cr.hash FROM users u "
            "JOIN credentials cr ON cr.user_id = u.id ORDER BY RANDOM() LIMIT 25"
        )
        self.assertEqual(len(rows), 25)
        for r in rows:
            ok = verify_password(r["algo"], "Fixture-Test-Pass-2026!", bytes(r["salt"]),
                                 bytes(r["hash"]), int(r["iterations"]))
            self.assertTrue(ok, f"fixture password did not verify for user {r['id']}")
            self.assertFalse(verify_password(r["algo"], "wrong-password", bytes(r["salt"]),
                                             bytes(r["hash"]), int(r["iterations"])))

    def test_deterministic_for_a_fixed_seed(self) -> None:
        again = seed_db("core-repeat")
        c2 = connect(again)
        try:
            self.assertEqual(get_meta(self.conn, "fixture_hash"), get_meta(c2, "fixture_hash"))
        finally:
            c2.close()

    def test_referential_integrity(self) -> None:
        for table in ("events", "sessions"):
            orphan = self.q(f"SELECT COUNT(*) c FROM {table} WHERE user_id NOT IN (SELECT id FROM users)")[0]["c"]
            self.assertEqual(orphan, 0, f"{table} rows must reference a real user")
        # an inviter must predate the invitee, otherwise the graph is invented
        self.assertEqual(
            self.q("SELECT COUNT(*) c FROM invite_edges WHERE inviter >= invitee")[0]["c"], 0,
            "invite edges must point backwards in id order (ids follow signup order)",
        )

    def test_activity_skew_is_heavy_tailed(self) -> None:
        counts = [r["c"] for r in self.q("SELECT COUNT(*) c FROM events GROUP BY user_id ORDER BY c DESC")]
        self.assertGreater(len(counts), 100)
        top5 = sum(counts[: max(1, len(counts) // 20)])
        total = sum(counts)
        self.assertGreater(top5 / total, 0.25, "expected a fat head; check generate_activity's pareto alpha")

    def test_cohort_labels_are_written(self) -> None:
        labeled = self.q("SELECT COUNT(*) c FROM users WHERE is_synthetic_abuse = 1")[0]["c"]
        self.assertEqual(labeled, SMALL_LABELS)

    def test_policy_matches_fixture_password(self) -> None:
        self.assertTrue(PasswordPolicy(min_length=10).is_valid("Fixture-Test-Pass-2026!"))
        self.assertFalse(PasswordPolicy(min_length=10).is_valid("short"))

    def test_email_domains_are_split_by_reputation(self) -> None:
        free = self.q("SELECT COUNT(*) c FROM users WHERE email_domain = 'gmail.com'")[0]["c"]
        disp = self.q("SELECT COUNT(*) c FROM users WHERE email_domain = 'mailinator.com'")[0]["c"]
        self.assertGreater(free, 10 * max(1, disp))


SMALL_LABELS = 250


class SeederCliTest(unittest.TestCase):
    def test_refuses_to_append_into_a_non_empty_db(self) -> None:
        db = seed_db("again")
        from seeds.seed import main

        self.assertEqual(main(["--users", "10", "--db", str(db)]), 3)

    def test_zero_users_still_produces_a_schema(self) -> None:
        from seeds.seed import main

        path = seed_db("empty", users=0, inject_bots=0, no_activity=True)
        self.assertEqual(main(["--users", "0", "--days", "10", "--db", str(path), "--fresh", "--quiet"]), 0)

    def test_seed_report_renders(self) -> None:
        from seeds.report import render

        db = seed_db("report")
        conn = connect(db)
        try:
            text = render(conn)
        finally:
            conn.close()
        for needle in ("SEED REPORT", "peak hour", "disposable total", "WRITE SKEW", "fixture hash"):
            self.assertIn(needle, text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
