from __future__ import annotations

import json
import random
import tempfile
import unittest
from pathlib import Path

from load.generic import GenericScenario, Op, Spec, Template, dig
from load.scenarios import LoadOptions
from mockapi.client import ApiClient
from tests._support import RunningApi, seed_db

ROOT = Path(__file__).resolve().parents[1]

SPEC = {
    "name": "probe",
    "ops": [
        {"name": "login", "weight": 50, "method": "POST", "path": "/auth/login",
         "json": {"identifier": "{{ident}}", "password": "{{password}}"},
         "expect": [200, 429], "capture": {"token": "token"}},
        {"name": "me", "weight": 30, "method": "GET", "path": "/users/me",
         "headers": {"Authorization": "Bearer {{token}}"}, "requires": ["token"], "expect": [200]},
        {"name": "feed", "weight": 20, "method": "GET", "path": "/feed",
         "query": {"limit": "{{feed_limit}}", "cursor": "{{cursor}}"}, "capture": {"cursor": "next_cursor"}},
        {"name": "broken", "weight": 0, "method": "GET", "path": "/nope/{{mystery}}", "expect": [200]},
    ],
}


class SpecTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="spec-"))

    def write(self, payload: dict) -> Path:
        path = self.tmp / "spec.json"
        path.write_text(json.dumps(payload))
        return path

    def test_load_validates_shape(self) -> None:
        self.assertEqual(len(Spec.load(self.write(SPEC)).ops), 4)
        with self.assertRaises(ValueError):
            Spec.load(self.write({"ops": []}))
        with self.assertRaises(ValueError):
            Spec.load(self.write({"ops": [{"name": "a", "weight": 0}]}))
        with self.assertRaises(ValueError):
            Spec.load(self.write({"ops": [{"name": "a", "weight": -1}]}))
        with self.assertRaises(ValueError):
            Op.from_dict({"method": "GET"})

    def test_dig_walks_dicts_lists_and_negative_indices(self) -> None:
        data = {"data": {"edges": [{"cursor": "c1"}, {"cursor": "c2"}], "n": 2}}
        self.assertEqual(dig(data, "data.edges.0.cursor"), "c1")
        self.assertEqual(dig(data, "data.edges.-1.cursor"), "c2")
        self.assertEqual(dig(data, "data.edges.9.cursor"), None)
        self.assertEqual(dig(data, "data.missing.cursor"), None)
        self.assertEqual(dig(None, "a"), None)

    def test_template_builtins(self) -> None:
        opts = LoadOptions(password="pw", identifiers=["a@b.c"], register_domain="loadtest.invalid")
        tpl = Template(opts)
        ctx: dict = {"rnd": random.Random(1)}
        first, err = tpl.resolve("s{{seq}} u{{username}} e{{email}}", ctx)
        self.assertIsNone(err)
        self.assertRegex(first, r"s\d+ u[a-z0-9]+\d+ e[a-z0-9.-]+@loadtest\.invalid")
        rand, _ = tpl.resolve("{{rand:10}}", ctx)
        self.assertTrue(rand.isdigit() and 0 <= int(rand) < 10)
        self.assertEqual(tpl.resolve("{{now}}", ctx)[0].isdigit(), True)
        uuid, _ = tpl.resolve("{{uuid}}", ctx)
        self.assertRegex(uuid, r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{8}$")

    def test_ctx_wins_and_present_but_empty_falls_back(self) -> None:
        """Regression: the engine used to start workers with token=None, and
        `str(None)` sent the literal "None" as a cursor, so every paged request
        was rejected. Empty/None state must resolve to the fallback, not the word."""
        opts = LoadOptions(password="pw", identifiers=["a@b.c"], register_domain="loadtest.invalid")
        tpl = Template(opts)
        self.assertEqual(tpl.resolve("c{{cursor}}", {"cursor": None})[0], "c")
        self.assertEqual(tpl.resolve("c{{cursor}}", {"cursor": ""})[0], "c")
        self.assertEqual(tpl.resolve("c{{cursor}}", {"cursor": "1:2"})[0], "c1:2")
        self.assertEqual(tpl.resolve("p{{password}}", {})[0], "p" + opts.password)

    def test_unknown_variable_is_reported_not_silently_dropped(self) -> None:
        tpl = Template(LoadOptions(password="x", identifiers=["a@b.c"], register_domain="d.invalid"))
        rendered, err = tpl.resolve("{{mystery}}", {})
        self.assertIn("mystery", err or "")
        self.assertEqual(rendered, "")

    def test_weights_select_ops_proportionally(self) -> None:
        spec = Spec.load(self.write(SPEC))
        scn = GenericScenario(spec)
        rnd = random.Random(7)
        picks = [scn.pick(rnd).name for _ in range(4000)]
        self.assertGreater(picks.count("login") / len(picks), 0.35)
        self.assertLess(picks.count("broken") / len(picks), 0.01, "weight 0 should essentially never fire")


class ShippedExamplesTest(unittest.TestCase):
    """The example specs are documentation you can run, so they are tested like code:
    they must load, and no op may use captured state without `requires` guarding it.
    Without that guard an example that looks fine on page 2 exits 3 (`{{org}}` before
    any response has carried an org) — a confusing first experience of the feature."""

    EXAMPLES = sorted((ROOT / "docs" / "examples").glob("*.load.json"))

    def test_examples_exist(self) -> None:
        self.assertTrue(self.EXAMPLES, "docs/examples vanished")

    def test_examples_load_and_guard_captured_state(self) -> None:
        for path in self.EXAMPLES:
            spec = Spec.load(path)
            self.assertTrue(spec.ops, path.name)
            # `cursor` legitimately starts empty (page one has no cursor), so it is
            # the one captured var an op may use unguarded.
            captured = {var for op in spec.ops for var in op.capture} - {"cursor"}
            for op in spec.ops:
                blob = json.dumps([op.path, op.query, op.headers, op.body])
                used = {var for var in captured if "{{" + var + "}}" in blob}
                if used:
                    self.assertTrue(set(op.requires) >= used,
                                    f"{path.name}/{op.name} uses {sorted(used)} without `requires`")


class ScenarioAgainstApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.db = seed_db("generic", users=300, inject_bots=20, events=0.3)
        cls.api = RunningApi(cls.db, rate_limit_per_min=0, login_rate_limit_per_min=0)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.api.close()

    def run_ops(self, spec: Spec, client: ApiClient, opts: LoadOptions, ctx: dict, n: int) -> list:
        scn = GenericScenario(spec)
        return [scn.run(client, ctx, opts) for _ in range(n)]

    def test_state_flows_capture_requires_and_expect(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "s.json"
            path.write_text(json.dumps(SPEC))
            spec = Spec.load(path)
            client = ApiClient(self.api.base_url)
            opts = LoadOptions(password="Fixture-Test-Pass-2026!", identifiers=[],
                               register_domain="loadtest.invalid")
            email, username = opts.new_identity()
            self.assertEqual(client.register(email, username, "Fixture-Test-Pass-2026!").status, 201)
            opts.identifiers = [email]

            me_only = Spec(name="me", base_url="", headers={}, ops=[Op.from_dict(
                {"name": "me", "method": "GET", "path": "/users/me",
                 "headers": {"Authorization": "Bearer {{token}}"}, "requires": ["token"], "expect": [200]})])
            login_only = Spec(name="login", base_url="", headers={}, ops=[Op.from_dict(
                {"name": "login", "method": "POST", "path": "/auth/login",
                 "json": {"identifier": "{{ident}}", "password": "{{password}}"},
                 "expect": [200], "capture": {"token": "token"}})])

            # no token yet -> the authed op is skipped, not fired with an empty bearer
            ctx: dict = {"rnd": random.Random(3)}
            self.assertEqual(self.run_ops(me_only, client, opts, ctx, 1)[0][0], "skipped")

            # a successful login captures, and the same op then succeeds
            self.assertEqual(self.run_ops(login_only, client, opts, ctx, 1)[0][0], "ok")
            self.assertIn("token", ctx, "a 200 login must capture the bearer token")
            self.assertEqual(self.run_ops(me_only, client, opts, ctx, 1)[0][0], "ok")

            # the full spec still works end to end, paging included
            res = self.run_ops(spec, client, opts, ctx, 150)
            self.assertEqual({k for k, _m, o in res if o == "feed"}, {"ok"})
            self.assertEqual({k for k, _m, o in res if o == "me"}, {"ok"})

            # an unexpected status is *not* coerced into ok
            bad = Spec(name="bad", base_url="", headers={}, ops=[Op.from_dict(
                {"name": "login", "method": "POST", "path": "/auth/login",
                 "json": {"identifier": "ghost@loadtest.invalid", "password": "{{password}}"}})])
            res = self.run_ops(bad, client, opts, {"rnd": random.Random(5)}, 3)
            self.assertEqual({k for k, _m, _o in res}, {"auth_fail"},
                             "401 is outside `expect`, so it must count as a failure")

            # an unresolvable variable is loud: spec_error, not a silently empty header
            broken = Spec(name="b", base_url="", headers={}, ops=[Op.from_dict(
                {"name": "broken", "method": "GET", "path": "/x/{{mystery}}"})])
            kind, _ms, op = self.run_ops(broken, client, opts, ctx, 1)[0]
            self.assertEqual((op, kind), ("broken", "spec_error"))
            client.close()

    def test_a_listed_failure_status_still_does_not_capture(self) -> None:
        """`expect` can legitimately include 401 (a login probe), but a failing response
        whose body happens to carry the field must not populate the state `requires`
        trusts. Stubbed client so the payload is under our control, not the mock API's."""
        spec = Spec(name="probe", base_url="", headers={}, ops=[Op.from_dict(
            {"name": "login", "method": "POST", "path": "/auth/login", "expect": [200, 401],
             "capture": {"token": "token"}})])

        class Resp:
            def __init__(self, status, data):
                self.status, self.data, self.ms, self.ok = status, data, 1.0, status < 400

        class Stub:
            def __init__(self, status, data):
                self._r = Resp(status, data)

            def request(self, *a, **kw):
                return self._r

        opts = LoadOptions(password="x", identifiers=["a@b.c"], register_domain="d.invalid")
        for status in (401, 500, 429):
            ctx: dict = {"rnd": random.Random(1)}
            kind, _ms, op = GenericScenario(spec).run(Stub(status, {"token": "stale"}), ctx, opts)
            self.assertEqual(op, "login")
            self.assertNotIn("token", ctx, f"{status} must not capture state")
            if status == 401:
                self.assertEqual(kind, "ok", "401 was listed in expect, so it is an expected outcome")
        # the same op on 200 does capture
        ctx = {"rnd": random.Random(1)}
        GenericScenario(spec).run(Stub(200, {"token": "good"}), ctx, opts)
        self.assertEqual(ctx.get("token"), "good")

    def test_spec_query_values_are_url_encoded(self) -> None:
        spec = Spec(name="q", base_url="", headers={}, ops=[Op.from_dict(
            {"name": "paged", "method": "GET", "path": "/feed",
             "query": {"limit": "3", "cursor": "1791522507:39318"}})])
        client = ApiClient(self.api.base_url)
        seen: dict = {}
        original = client.request

        def spy(method, path, body=None, extra_headers=None):
            seen["path"] = path
            return original(method, path, body, extra_headers)

        client.request = spy
        kind, _ms, _op = GenericScenario(spec).run(client, {"rnd": random.Random(1)},
                                                   LoadOptions(password="x", identifiers=[],
                                                               register_domain="d.invalid"))
        self.assertEqual(kind, "ok")
        self.assertIn("cursor=1791522507%3A39318", seen["path"], "the colon must be percent-encoded")
        client.request = original
        client.close()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
