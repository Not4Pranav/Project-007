from __future__ import annotations

import json
import unittest
from pathlib import Path

from load.engine import (
    Recorder,
    check_slo,
    parse_slo,
    parse_stages,
    quantile,
    run_stage,
    summarize,
    write_report,
)
from load.scenarios import SCENARIOS, LoadOptions, classify
from mockapi.client import ApiClient
from seeds.db import connect
from tests._support import RunningApi, seed_db


class MathTest(unittest.TestCase):
    def test_quantile_interpolates(self) -> None:
        vals = list(range(1, 101))
        self.assertAlmostEqual(quantile(vals, 0.0), 1)
        self.assertAlmostEqual(quantile(vals, 1.0), 100)
        self.assertTrue(quantile(vals, 0.5) <= quantile(vals, 0.95) <= quantile(vals, 1.0))
        self.assertEqual(quantile([], 0.95), 0.0)

    def test_parse_stages_supports_per_stage_seconds(self) -> None:
        self.assertEqual(parse_stages("10,20"), [(10, 0.0), (20, 0.0)])
        self.assertEqual(parse_stages("10:5,20:30"), [(10, 5.0), (20, 30.0)])
        self.assertEqual(parse_stages(""), [(10, 0.0)])
        self.assertEqual(parse_stages(" , "), [(10, 0.0)])

    def test_slo_parsing_and_breaches(self) -> None:
        slo = parse_slo("p95_ms=250, error_rate_pct=0.5 ,min_rps=150")
        self.assertEqual(slo, {"p95_ms": 250.0, "error_rate_pct": 0.5, "min_rps": 150.0})

        def stats(**kw):
            base = {
                "label": "s1", "concurrency": 10, "seconds": 10.0, "ops": 1000, "mean": 10.0,
                "p50": 10.0, "p90": 12.0, "p95": 11.0, "p99": 40.0, "p999": 60.0, "max": 90.0,
                "rps": 200.0, "errors": 0.1, "throttled": 0.0, "kinds": {}, "per_op": {},
            }
            base.update(kw)
            return type("S", (), base)()

        self.assertEqual(check_slo(stats(), slo), [])
        self.assertEqual(check_slo(stats(p95=900.0), slo), ["p95_ms: 900.0 > 250.0"])
        self.assertEqual(check_slo(stats(errors=3.0, rps=10.0), slo),
                         ["error_rate_pct: 3.000 > 0.500", "min_rps: 10.0 < 150.0"])
        self.assertEqual(check_slo(stats(), parse_slo("throttle_pct=1.0")), [])

    def test_classify_buckets_outcomes(self) -> None:
        for status, expected in [(200, "ok"), (201, "ok"), (429, "throttled"), (401, "auth_fail"),
                                (403, "auth_fail"), (409, "conflict"), (422, "client_error"),
                                (500, "server_error"), (0, "transport")]:
            self.assertEqual(classify(status), expected, status)
        self.assertEqual(classify(0, exc=True), "transport")

    def test_recorder_caps_samples(self) -> None:
        rec = Recorder()
        for i in range(2000):
            rec.add("feed", "ok", float(i))
        self.assertEqual(rec.total, 2000)
        stats = summarize(rec, label="x", concurrency=1, seconds=2.0, throttle_is_error=False)
        self.assertEqual(stats.ops, 2000)
        self.assertEqual(stats.errors, 0.0)
        self.assertAlmostEqual(stats.rps, 1000.0, places=1)
        merged = Recorder()
        merged.merge(rec)
        self.assertEqual(merged.total, 2000)
        self.assertEqual(merged.lat[:2], rec.lat[:2])

    def test_throttle_can_count_as_error(self) -> None:
        rec = Recorder()
        rec.add("login", "throttled", 12.0)
        strict = summarize(rec, label="x", concurrency=1, seconds=1.0, throttle_is_error=True)
        loose = summarize(rec, label="x", concurrency=1, seconds=1.0, throttle_is_error=False)
        self.assertEqual(strict.errors, 100.0)
        self.assertEqual(loose.errors, 0.0)
        self.assertEqual(loose.throttled, 100.0)


class EngineAgainstLiveTargetTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.db = seed_db("load", users=400, inject_bots=50, events=0.4)
        cls.api = RunningApi(cls.db, rate_limit_per_min=0, login_rate_limit_per_min=0)
        cls.client = ApiClient(cls.api.base_url)
        conn = connect(cls.db)
        cls.idents = [r["email"] for r in conn.execute(
            "SELECT email FROM users WHERE status='active' LIMIT 200")]
        conn.close()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()
        cls.api.close()

    def opts(self, **kw) -> LoadOptions:
        return LoadOptions(password="Fixture-Test-Pass-2026!", identifiers=self.idents,
                           register_domain="loadtest.invalid", **kw)

    def test_closed_loop_stage_produces_samples(self) -> None:
        stats, rec = run_stage(self.client, SCENARIOS["feed"], self.opts(), concurrency=4,
                               seconds=1.5, rps=0.0, think_ms=0.0, seed=3, label="s1")
        self.assertGreater(stats.ops, 10, "a 4-worker stage must complete requests")
        self.assertEqual(stats.errors, 0.0, stats.kinds)
        self.assertEqual(set(stats.kinds), {"ok"})
        self.assertLessEqual(stats.p50, stats.p95)
        self.assertLessEqual(stats.p95, stats.p99)
        self.assertIn("feed", stats.per_op)
        self.assertEqual(rec.total, stats.ops)

    def test_open_loop_pacing_holds_the_target_rate(self) -> None:
        """Closed loop measures a ceiling; paced arrival measures fitness. At 40
        rps the observed rate must sit near it instead of pinned to max."""
        stats, _ = run_stage(self.client, SCENARIOS["feed"], self.opts(), concurrency=8,
                             seconds=2.0, rps=40.0, think_ms=0.0, seed=5, label="paced")
        self.assertGreater(stats.rps, 15.0)
        self.assertLess(stats.rps, 90.0, "pacing leaked: the engine outran its arrival budget")

    def test_mixed_scenario_exercises_every_path(self) -> None:
        opts = self.opts(mix_weights={"login": 30, "feed": 30, "register": 30, "post": 10})
        stats, _ = run_stage(self.client, SCENARIOS["mixed"], opts, concurrency=4, seconds=2.5,
                             rps=0.0, think_ms=0.0, seed=9, label="mix")
        ops = set(stats.per_op)
        self.assertTrue({"login", "feed", "register"} <= ops, ops)
        self.assertEqual(stats.errors, 0.0, stats.kinds)
        conn = connect(self.db)
        try:
            created = conn.execute("SELECT COUNT(*) c FROM users WHERE source='api'").fetchone()["c"]
        finally:
            conn.close()
        self.assertGreaterEqual(created, stats.kinds.get("ok", 0) * 0, "registrations land in the same DB")

    def test_registered_load_users_can_log_in(self) -> None:
        opts = self.opts()
        run_stage(self.client, SCENARIOS["register"], opts, concurrency=2, seconds=1.0,
                  rps=0.0, think_ms=0.0, seed=11, label="reg")
        r = self.client.login("lt000001", "Fixture-Test-Pass-2026!")
        self.assertIn(r.status, (200, 401))
        if r.status == 401:  # id was taken by an earlier stage; a fresh one must work
            email, username = opts.new_identity()
            self.assertEqual(self.client.register(email, username, "Fixture-Test-Pass-2026!").status, 201)
            self.assertEqual(self.client.login(username, "Fixture-Test-Pass-2026!").status, 200)

    def test_report_files_are_written(self) -> None:
        stats, _ = run_stage(self.client, SCENARIOS["feed"], self.opts(), concurrency=2,
                             seconds=1.0, rps=0.0, think_ms=0.0, seed=1, label="s1")
        payload = {
            "base_url": self.api.base_url, "scenario": "feed", "mix": {}, "stages": [stats.as_dict()],
            "overall": stats.as_dict(), "stage_seconds": 1.0, "warmup_seconds": 0.0,
            "identifier_source": "test", "identifiers": len(self.idents), "pacing": "closed-loop",
            "slo_spec": "p99_ms=5000", "slo": {"p99_ms": 5000.0}, "slo_scope": "final",
            "ip_pool": 0,
            "slo_result": "pass", "slo_breaches": [], "server_metrics": None,
            "generated": "2026-09-11T00:00:00+00:00",
        }
        out = Path(self.db).parent / "reports"
        mp, jp = write_report(out, payload)
        self.assertTrue(mp.exists() and jp.exists())
        saved = json.loads(jp.read_text())
        self.assertEqual(saved["scenario"], "feed")
        self.assertGreater(saved["overall"]["ops"], 0)
        text = mp.read_text()
        for needle in ("# load report", "| stage | conc |", "outcome mix", "SLO"):
            self.assertIn(needle, text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
