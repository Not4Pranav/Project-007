from __future__ import annotations

import contextlib
import csv
import io
import unittest

from abuse.detector import RULES, RuleEngine, grade, main
from seeds.db import connect
from seeds.text import entropy, ip_prefix24, username_template
from tests._support import seed_db


class TextHelpersTest(unittest.TestCase):
    def test_username_template_masks_digit_runs(self) -> None:
        self.assertEqual(username_template("guest00412"), username_template("guest00413"))
        self.assertNotEqual(username_template("guest00412"), username_template("user00412"))
        self.assertEqual(username_template(""), "")

    def test_ip_prefix24(self) -> None:
        self.assertEqual(ip_prefix24("203.0.113.44"), "203.0.113")
        self.assertEqual(ip_prefix24("garbage"), "garbage")

    def test_entropy_ranks_generated_above_human(self) -> None:
        self.assertLess(entropy("aaaa11"), entropy("xq7vk3zp"))


class DetectorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.db = seed_db("abuse")
        cls.conn = connect(cls.db)

    def run_cli(self, *args: str) -> tuple[int, str]:
        """Capture the report so `make test` stays readable."""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(list(args))
        return code, buf.getvalue()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.conn.close()

    def test_flags_are_persisted_with_composite_score(self) -> None:
        code, out = self.run_cli("--db", str(self.db), "--threshold", "0.5", "--velocity-min", "12",
                                 "--fan-in-min", "15", "--template-min", "4", "--allow-domain", "loadtest.invalid")
        self.assertEqual(code, 0)
        self.assertIn("SIGNUP ABUSE DETECTION", out)
        rows = self.conn.execute("SELECT user_id, rule, score, detail FROM flags LIMIT 5").fetchall()
        self.assertTrue(rows, "expected flagged accounts in a fixture with an injected cohort")
        for r in rows:
            self.assertGreaterEqual(r["score"], 0.5)
            self.assertIn("rule_weight=", r["detail"])
            self.assertIn(r["rule"], RULES)

    def test_score_is_noisy_or_not_a_sum(self) -> None:
        eng = RuleEngine(self.conn)
        one = eng.score({"disposable_email"})
        two = eng.score({"disposable_email", "signup_velocity"})
        all_rules = eng.score(set(RULES))
        self.assertAlmostEqual(one, RULES["disposable_email"])
        self.assertGreater(two, one)
        self.assertLess(two, 1.0)
        self.assertLess(all_rules, 1.0, "composite risk must saturate below 1.0, never exceed it")

    def test_injected_cohort_is_recovered_with_good_precision(self) -> None:
        """Rules must separate the labeled cohort from the organic population,
        otherwise the fixture is teaching nothing about detection."""
        self.run_cli("--db", str(self.db), "--threshold", "0.5", "--velocity-min", "12",
                     "--fan-in-min", "15", "--template-min", "4", "--allow-domain", "loadtest.invalid")
        flagged = {r["user_id"] for r in self.conn.execute(
            "SELECT DISTINCT user_id FROM flags WHERE score >= 0.5")}
        g = grade(self.conn, flagged)
        self.assertGreaterEqual(g["recall"], 0.85, f"missed {g['missed']:,} labeled accounts")
        self.assertGreaterEqual(g["precision"], 0.80, f"{g['false_positives']:,} false positives")
        # The 900-account test fixture is ~28% injected bots, so its ceiling on
        # lift is low by construction; the 30k demo fixture (4% base rate) lands
        # near 24x. Assert the meaningful separation instead of an absolute lift.
        self.assertGreater(g["lift"], 1.0 / max(0.01, g["base_rate"]) * 0.5,
                           "detector must beat a random draw by a wide margin")
        self.assertEqual(g["missed"] + g["true_positives"], g["positives"])

    def test_allowlisted_domains_are_not_scored(self) -> None:
        total = self.conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        scored = len(RuleEngine(self.conn, allow_domains=frozenset({"gmail.com"})).load())
        self.assertLess(scored, total, "allow-listing must actually shrink the scored population")
        gmail = self.conn.execute("SELECT COUNT(*) c FROM users WHERE email_domain='gmail.com'").fetchone()["c"]
        self.assertEqual(scored, total - gmail)

    def test_csv_export_carries_no_pii(self) -> None:
        out = self.db.parent / "flagged.csv"
        code, _ = self.run_cli("--db", str(self.db), "--velocity-min", "12", "--fan-in-min", "15",
                              "--template-min", "4", "--export", str(out), "--allow-domain", "loadtest.invalid")
        self.assertEqual(code, 0)
        with out.open() as fh:
            rows = list(csv.DictReader(fh))
        self.assertTrue(rows)
        self.assertEqual(set(rows[0].keys()), {"user_id", "score", "rules"})
        blob = out.read_text()
        for banned in ("@", "password", "token", "Bearer"):
            self.assertNotIn(banned, blob, f"export leaked a {banned!r} field")

    def test_scoring_never_touches_credentials(self) -> None:
        """A moderation fixture must not read the credential table at all - the
        detector's inputs are signup metadata only."""
        cols = set(RuleEngine(self.conn).load()[0].keys())
        self.assertTrue({"id", "username", "email", "signup_ts", "signup_ip", "is_synthetic_abuse"} <= cols)
        self.assertFalse(any("password" in c or "hash" in c or "salt" in c for c in cols), cols)
        self.assertNotIn("bio", cols)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
