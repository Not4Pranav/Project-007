"""The 3-tab console: settings rules, the loopback guard, and join/undo against a live fixture.

Three invariants this file exists to keep:

1. Settings are the only place a knob is interpreted, so a saved file must load back
   byte-for-byte and every rejected value must name the reason.
2. Nothing in the console may address a host other than 127.0.0.1, and no browser on
   another origin may drive it (DNS rebinding / CSRF).
3. "Server join" means a row in *your* fixture, and it is reversible by an explicit
   action over the ids the join reported — never a timer, never an invite link.
"""

from __future__ import annotations

import dataclasses
import http.client
import json
import re
import shutil
import socket
import sqlite3
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from urllib.parse import quote

from console import ops
from console.server import DUMP_NAME, Handler, serve
from console.settings import Settings, SettingsError, apply_updates, load, safe_fixture_path, save, validate
from seeds import roster
from tests._support import TMP, seed_db


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def call_state(port: int) -> str:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", "/api/state", headers={"Host": f"127.0.0.1:{port}"})
    body = conn.getresponse().read().decode()
    conn.close()
    return body


def request(port: int, method: str, path: str, *, host: str | None = None, headers: dict | None = None,
            body: str | None = None) -> tuple[int, str]:
    """One raw HTTP exchange, because the guard reads headers most clients refuse to set."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    hdrs = dict(headers or {})
    if host is not None:
        hdrs["Host"] = host
    if body is not None:
        hdrs.setdefault("Content-Type", "application/json")
    conn.request(method, path, body=body, headers=hdrs)
    resp = conn.getresponse()
    payload = resp.read().decode()
    status = resp.status
    conn.close()
    return status, payload


class SettingsTest(unittest.TestCase):
    def test_saved_file_loads_back_identical(self) -> None:
        """Regression: `seed` had no range rule, so validate() fell through to "unknown
        setting" on the *read* path — the first save wrote a file the console then
        refused to open, which dead every request that needed settings."""
        path = TMP / "settings-roundtrip.json"
        save(path, Settings(users=7, seed=99, db="var/probe.db", stages="5:2", write_mode="replace"))
        back = load(path)
        self.assertEqual((back.users, back.seed, back.db, back.stages), (7, 99, "var/probe.db", "5:2"))
        self.assertEqual(back.write_mode, "replace")
        self.assertTrue(back.fresh, "the read-only alias now answers with write_mode == 'replace'")
        self.assertNotIn("fresh", json.loads(path.read_text()),
                         "the file carries the mode, not the old boolean")
        self.assertEqual(load(path), load(path))
        self.assertEqual(save(path, Settings()), path)
        self.assertEqual(back.to_json_dict()["test_password"], Settings().test_password)

    def test_settings_file_is_not_world_readable(self) -> None:
        path = TMP / "settings-mode.json"
        save(path, Settings())
        self.assertEqual(path.stat().st_mode & 0o077, 0, f"{path} is group/other readable")

    def test_every_rejection_names_the_reason(self) -> None:
        bad = {
            "users": ["0", "-1", "900000000", "lots"],
            "seed": ["x"],
            "hash_algo": ["md5", "bcrypt"],
            "stages": ["rm -rf /", "0:0"],
            "slo": ["p95_ms=oops"],
            "register_domain": ["gmail.com", "not a domain"],
            "db": ["/etc/passwd", "notes.txt"],
            "test_password": ["", "abc"],
            "api_port": ["0", "70000"],
            "nope": ["1"],
        }
        for name, values in bad.items():
            for value in values:
                with self.subTest(name=name, value=value):
                    with self.assertRaises(SettingsError) as ctx:
                        validate(name, value)
                    self.assertIn(name, str(ctx.exception))

    def test_numeric_strings_are_coerced_not_stringified(self) -> None:
        merged = apply_updates(Settings(), {"users": "4000", "events": "1.5", "write_mode": "replace"})
        self.assertEqual(merged.users, 4000)
        self.assertIsInstance(merged.users, int)
        self.assertEqual(merged.events, 1.5)
        self.assertTrue(merged.fresh)  # write_mode "replace" == the old --fresh

    def test_unknown_keys_are_carried_and_ignored(self) -> None:
        merged = apply_updates(Settings(), {"stale_tab_field": "x", "users": 12})
        self.assertEqual(merged.users, 12)
        self.assertIn("stale_tab_field", merged.unknown)
        path = TMP / "settings-stale.json"
        save(path, merged)
        self.assertEqual(load(path).users, 12)  # a stale key must not poison the load

    def test_fixture_path_rule(self) -> None:
        self.assertEqual(safe_fixture_path("var/x.db"), "var/x.db")
        self.assertEqual(safe_fixture_path(str(TMP / "y.db")), (TMP / "y.db").as_posix())
        for refused in ("/etc/passwd", "var/prod.db", "var/live-users.sqlite", "seeds/../x.db", ""):
            with self.subTest(refused), self.assertRaises(SettingsError):
                safe_fixture_path(refused)

    def test_api_target_is_hard_pinned_to_loopback(self) -> None:
        """No setting, and no unknown key smuggled in by an old tab, can point the tool
        at somebody else's server."""
        self.assertEqual(Settings(api_port=8123).api_url(), "http://127.0.0.1:8123")
        merged = apply_updates(Settings(api_port=8123), {"api_host": "attacker.example",
                                                          "base_url": "http://api.real-prod",
                                                          "api_port": "9001"})
        self.assertEqual(merged.api_url(), "http://127.0.0.1:9001")
        for key in merged.to_json_dict():
            self.assertNotIn("host", key.lower())
            self.assertNotIn("base_url", key.lower())


class DumpNameTest(unittest.TestCase):
    def test_only_bare_dump_names_survive(self) -> None:
        for ok in ("accounts-20260911-062442.txt", "accounts-x_1-2.txt"):
            self.assertTrue(DUMP_NAME.fullmatch(ok), ok)
        for refused in ("../console.json", "var/accounts-x.txt", "accounts-x.md", "accounts-x.txt\0.png",
                        "accounts-..%2fx.txt", ""):
            with self.subTest(refused):
                self.assertIsNone(DUMP_NAME.fullmatch(refused))

    def test_build_refuses_paths_and_unknown_jobs(self) -> None:
        stub = SimpleNamespace(settings_path=TMP / "unused.json")
        settings = Settings(db=str(TMP / "console-none.db"), accounts_dir=str(TMP))
        with mock.patch.object(ops, "JOBS", ops.Runner()):
            cases = [
                ("join", {"server_id": 1, "source": "token-file", "token_file": "../etc/hosts"}, "path"),
                ("join", {"server_id": 1, "source": "token-file", "token_file": "a/b.txt"}, "path"),
                ("join", {"source": "fixture-logins"}, "server_id"),
                ("join", {"server_id": 0, "source": "fixture-logins"}, "between"),
                ("join", {"server_id": "1; rm -rf /", "source": "fixture-logins"}, "server_id"),
                ("load", {"use_tokens": "yes"}, "no token dumps"),
                ("leave", {}, "nothing to undo"),
                ("exec", {}, "unknown job"),
            ]
            for kind, params, needle in cases:
                with self.subTest(kind=kind, params=sorted(params)):
                    with self.assertRaises(ValueError) as ctx:
                        Handler._build(stub, kind, params, settings)
                    self.assertIn(needle, str(ctx.exception))

    def test_join_never_takes_a_target(self) -> None:
        """The join job's only address is a row id in settings.db. A payload that tries
        to name a server some other way must fail on the missing id, not go anywhere."""
        stub = SimpleNamespace(settings_path=TMP / "unused.json")
        settings = Settings(db=str(TMP / "console-none.db"), accounts_dir=str(TMP))
        for params in ({"url": "https://discord.gg/x", "invite": "abc", "server": "abc"},
                       {"base_url": "http://attacker", "server_id": 1, "source": "fixture-logins"}):
            with self.subTest(sorted(params)):
                fn = Handler._build(stub, "join", params, settings) if "server_id" in params else None
                if fn is None:
                    with self.assertRaises(ValueError):
                        Handler._build(stub, "join", params, settings)
                    continue
                # a callable may be built, but it can only ever dial settings.api_url()
                self.assertEqual(settings.api_url(), "http://127.0.0.1:8000")
                job = ops.Job(id=1, kind="join")
                with self.assertRaises(RuntimeError) as ctx:
                    fn(job)  # API not running: it refuses before touching a socket
                self.assertIn("not running", str(ctx.exception))


class RunnerTest(unittest.TestCase):
    def test_jobs_are_serialised(self) -> None:
        runner = ops.Runner()
        order: list[str] = []

        def slow(mark: str):
            def run(job: ops.Job) -> dict:
                order.append(f"start-{mark}")
                time.sleep(0.25)
                order.append(f"end-{mark}")
                return {"mark": mark}
            return run

        first = runner.submit("a", slow("1"))
        second = runner.submit("b", slow("2"))
        self.assertEqual(runner.busy(), f"a #{first.id}")
        for _ in range(120):
            if all(j["state"] == "done" for j in runner.snapshot(2)):
                break
            time.sleep(0.05)
        self.assertEqual(order, ["start-1", "end-1", "start-2", "end-2"])
        self.assertIsNone(runner.busy())
        snap = runner.snapshot(5)
        self.assertEqual([j["id"] for j in snap], [second.id, first.id], "snapshot must be newest-first")
        self.assertEqual(snap[0]["result"], {"mark": "2"})

    def test_failure_is_reported_not_swallowed(self) -> None:
        runner = ops.Runner()

        def boom(job: ops.Job) -> dict:
            job.say("about to fail")
            raise KeyError("missing table meta.fixture_hash")

        job = runner.submit("explode", boom)
        for _ in range(120):
            if job.state in ("done", "failed"):
                break
            time.sleep(0.05)
        self.assertEqual(job.state, "failed")
        self.assertIn("KeyError", "\n".join(job.log))
        self.assertIn("about to fail", "\n".join(job.log))

    def test_log_is_capped(self) -> None:
        job = ops.Job(id=1, kind="chatty")
        for i in range(ops.MAX_LOG_LINES + 120):
            job.say(f"line {i}")
        self.assertEqual(len(job.log), ops.MAX_LOG_LINES)
        self.assertEqual(job.log[-1], f"line {ops.MAX_LOG_LINES + 119}")
        self.assertNotIn("line 0", job.log)


class _ConsoleServerCase(unittest.TestCase):
    """Boots the console once on an ephemeral port, settings file in TMP."""

    allow_nonlocal = False

    @classmethod
    def setUpClass(cls) -> None:
        cls.settings_path = TMP / "console-server.json"
        save(cls.settings_path, Settings(db=str(TMP / "console-guard.db"), accounts_dir=str(TMP)))
        cls.port = free_port()
        cls.httpd = serve(cls.port, "127.0.0.1", cls.settings_path, verbose=False,
                          allow_nonlocal=cls.allow_nonlocal)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)
        Handler.allow_nonlocal = False
        Handler.bind_host = "127.0.0.1"

    def get(self, path: str, **kw) -> tuple[int, str]:
        return request(self.port, "GET", path, **kw)


class HostGuardTest(_ConsoleServerCase):
    def test_loopback_host_is_served(self) -> None:
        status, body = self.get("/", host=f"127.0.0.1:{self.port}")
        self.assertEqual(status, 200)
        self.assertIn("Operational Mode", body)
        self.assertGreater(len(body), 4000, "the page should be self-contained")
        self.assertEqual(body.count("<script"), 1)

    def test_rebinding_host_is_refused(self) -> None:
        for hostile in ("attacker.example", "evil.localhost", "169.254.169.254", "localhost.evil.test",
                        "[::ffff:127.0.0.1]"):
            with self.subTest(hostile):
                status, body = self.get("/api/state", host=hostile)
                self.assertEqual(status, 403, body[:120])
                self.assertIn("Host", body)

    def test_cross_site_and_cross_origin_are_refused(self) -> None:
        good = f"127.0.0.1:{self.port}"
        status, body = self.get("/api/state", host=good, headers={"Origin": "http://other.example"})
        self.assertEqual(status, 403, body[:120])
        status, body = self.get("/api/state", host=good, headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(status, 403, body[:120])
        status, _ = self.get("/api/state", host=good, headers={"Sec-Fetch-Site": "same-origin"})
        self.assertEqual(status, 200)

    def test_post_must_be_json(self) -> None:
        status, body = request(self.port, "POST", "/api/job", host=f"127.0.0.1:{self.port}",
                               headers={"Content-Type": "text/plain"}, body='{"kind":"scan"}')
        self.assertEqual(status, 400, body[:120])
        status, body = request(self.port, "POST", "/api/job", host=f"127.0.0.1:{self.port}",
                               body='{"kind":"nope"}')
        self.assertEqual(status, 400, body[:200])
        self.assertIn("unknown job", body)

    def test_reset_button_actually_resets(self) -> None:
        """Regression: the page used to POST with no Content-Type, the JSON-only rule
        refused it, and the button still reported success. The rail is right; the
        button was wrong, so both halves are asserted here."""
        keep = self.settings_path.read_text()  # this test rewrites state the class shares
        try:
            self._reset_round_trip()
        finally:
            self.settings_path.write_text(keep)

    def _reset_round_trip(self) -> None:
        save(self.settings_path, Settings(db="var/whatever.db", users=1234))
        status, body = request(self.port, "POST", "/api/settings/reset", host=f"127.0.0.1:{self.port}")
        self.assertEqual(status, 400, body[:120])  # a bodiless form POST stays refused
        self.assertIn("application/json", body)
        status, body = request(self.port, "POST", "/api/settings/reset", host=f"127.0.0.1:{self.port}",
                               body="{}")
        self.assertEqual(status, 200, body[:160])
        state = json.loads(call_state(self.port))
        self.assertEqual((state["settings"]["users"], state["settings"]["db"]),
                         (Settings().users, Settings().db), "defaults, not the saved values")
        # and the button itself must send the shape this endpoint accepts
        page = request(self.port, "GET", "/", host=f"127.0.0.1:{self.port}")[1]
        call_src = re.search(r"fetch\('/api/settings/reset'.*?\}\s*\)", page, re.S)
        self.assertIsNotNone(call_src, "the page no longer posts to /api/settings/reset")
        self.assertIn("application/json", call_src.group(0))
        self.assertIn("body", call_src.group(0))

    def test_state_shape(self) -> None:
        status, body = self.get("/api/state", host=f"127.0.0.1:{self.port}")
        self.assertEqual(status, 200)
        state = json.loads(body)
        for key in ("settings", "fixture", "api", "jobs", "busy"):
            self.assertIn(key, state)
        self.assertEqual(state["fixture"]["db"], str(TMP / "console-guard.db"))
        self.assertFalse(state["api"]["running"])
        self.assertFalse(state["fixture"]["exists"])

    def test_missing_db_is_reported_not_raised(self) -> None:
        status, body = self.get("/api/state", host=f"127.0.0.1:{self.port}")
        state = json.loads(body)
        self.assertEqual(status, 200)
        self.assertIn("dumps", state["fixture"])

    def test_dump_endpoint_refuses_traversal(self) -> None:
        for name in ("../console-server.json", "..%2Fconsole-server.json", "notes.txt"):
            with self.subTest(name):
                status, body = self.get(f"/api/dump?name={name}", host=f"127.0.0.1:{self.port}")
                self.assertEqual(status, 200)  # answered as text, but answered with a refusal
                self.assertIn("refused", body)

    def test_preview_matches_the_saved_settings(self) -> None:
        status, body = request(self.port, "POST", "/api/preview", host=f"127.0.0.1:{self.port}",
                               body=json.dumps({"users": 300}))
        self.assertEqual(status, 200, body[:160])
        command = json.loads(body)["command"]
        self.assertTrue(command.startswith("python3 -m seeds.seed "), command)
        self.assertIn("--users 300", command)
        self.assertIn("--test-password", command)
        status, body = request(self.port, "POST", "/api/preview", host=f"127.0.0.1:{self.port}",
                               body=json.dumps({"hash_algo": "md5"}))
        self.assertEqual(status, 400, body[:160])


class DumpsListingTest(unittest.TestCase):
    """The run-dumps table, on a console whose fixture is readable.

    It lives in its own class because `/api/state` builds that table inside
    fixture_status: on the host-guard console (no db at all) the payload degrades to an
    error and there is nothing to assert about listing.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.dir = TMP / "console-dumps"
        cls.dir.mkdir(parents=True, exist_ok=True)
        cls.settings_path = cls.dir / "console.json"
        save(cls.settings_path, Settings(db=str(seed_db("console-dumps-db", users=100)),
                                         accounts_dir=str(cls.dir)))
        cls.port = free_port()
        cls.httpd = serve(cls.port, "127.0.0.1", cls.settings_path, verbose=False)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)
    def test_run_dumps_are_listed_and_the_roster_exports_are_not(self) -> None:
        """The exports live in the same scratch dir and match `accounts-*.txt`, so the dumps
        table, the dump reader and the revoke button would all offer a plaintext password file
        as if it were a token dump. Three checks, because three separate ways in."""
        stamp = self.dir / "accounts-20260101-000000.txt"
        stamp.write_text("# from a load run\nzoe@mail.invalid\tses_dumped_token\n")
        secret = self.dir / "accounts-userpass.txt"
        secret.write_text("# the fixture's shared passwords\nzoe@mail.invalid:Fixture-Test-Pass-2026!\n")
        self.addCleanup(stamp.unlink, missing_ok=True)
        self.addCleanup(secret.unlink, missing_ok=True)
        self.assertTrue(DUMP_NAME.fullmatch(stamp.name) and DUMP_NAME.fullmatch(secret.name),
                        "both names pass the filename rule, which is why the guard is by path")
        state = json.loads(request(self.port, "GET", "/api/state")[1])
        listed = [d["name"] for d in state["fixture"]["dumps"]]
        self.assertIn(stamp.name, listed)
        self.assertNotIn(secret.name, listed, "the account list's export must not be a selectable dump")
        status, body = request(self.port, "GET", f"/api/dump?name={quote(stamp.name)}")
        self.assertEqual(status, 200)
        self.assertIn("hidden", body, "a dump is masked before ?reveal=1 as well")
        self.assertIn("not a run dump",
                    request(self.port, "GET", f"/api/dump?name={quote(secret.name)}")[1])
        code, raw = request(self.port, "POST", "/api/revoke", body=json.dumps({"name": secret.name}))
        payload = json.loads(raw)
        self.assertEqual(code, 400, payload)
        self.assertIn("account list or one of its exports", payload["error"])
        self.assertTrue(secret.exists(), "a refused revoke must not have touched the file")


class HostGuardWideBindTest(_ConsoleServerCase):
    """--allow-nonlocal widens *which Host names are trusted* (a LAN preview needs that)
    but never widens who may drive the console, and never trusts a rebinding Host."""

    allow_nonlocal = True

    def test_foreign_host_still_needs_to_match_origin(self) -> None:
        status, _ = self.get("/api/state", host="attacker.example")
        self.assertEqual(status, 200, "bind_wide defers the Host-name rule to the operator")
        status, body = self.get("/api/state", host="attacker.example",
                                headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(status, 403, body[:120])
        status, body = self.get("/api/state", host="attacker.example",
                                headers={"Origin": "http://other.example"})
        self.assertEqual(status, 403, body[:120])

    def test_mismatched_origin_for_localhost_is_refused(self) -> None:
        status, _ = self.get("/api/state", host=f"127.0.0.1:{self.port}",
                             headers={"Origin": f"http://127.0.0.1:{self.port}"})
        self.assertEqual(status, 200)
        status, _ = self.get("/api/state", host=f"127.0.0.1:{self.port}",
                             headers={"Origin": "http://evil:8010"})
        self.assertEqual(status, 403)


class JoinFlowTest(unittest.TestCase):
    """The Operational tab, end to end, against the API the console itself starts.

    The fixture's servers are randomised (some private, some at capacity), so this class
    rewrites two rows into the shapes it needs and joins into a known-public one. Every
    test undoes its own memberships: `left_ts` is how the fixture remembers them.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.db = seed_db("console-join")
        cls.accounts = TMP / "console-accounts"
        cls.accounts.mkdir(exist_ok=True)
        cls.port = free_port()
        cls.settings = Settings(db=str(cls.db), accounts_dir=str(cls.accounts), api_port=cls.port,
                                login_rate_limit_per_min=0, join_rate_limit_per_min=6000,
                                max_inflight=8, hash_algo="sha256_fast")
        c = sqlite3.connect(cls.db)
        c.execute("UPDATE servers SET private=0, capacity=NULL")
        c.execute("UPDATE servers SET private=1 WHERE id=5")
        c.execute("UPDATE servers SET capacity=1 WHERE id=6")
        c.execute("DELETE FROM memberships")  # a clean ledger makes the counts checkable
        c.execute("COMMIT")
        c.close()
        cls.public, cls.priv, cls.capped = 1, 5, 6
        cls.boot = ops.Job(id=999, kind="api-start")
        started = ops.API.start(cls.settings, cls.boot)
        assert started["state"] == "started", started

    @classmethod
    def tearDownClass(cls) -> None:
        ops.API.stop(cls.settings, ops.Job(id=998, kind="api-stop"))

    def conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.db)
        c.row_factory = sqlite3.Row
        return c

    def setUp(self) -> None:
        # a departed membership makes the next join a *rejoin*, and the API reports those
        # apart from new ones; each test gets the clean ledger setUpClass prepared
        c = sqlite3.connect(self.db)
        c.execute("DELETE FROM memberships")
        c.commit()
        c.close()

    def counts(self, server_id: int = 0) -> tuple[int, int]:
        c = self.conn()
        try:
            # COUNT(*) would count departed rows as "live": left_ts is the whole question.
            sql = ("SELECT COALESCE(SUM(left_ts IS NULL),0) live, "
                   "COALESCE(SUM(left_ts IS NOT NULL),0) gone FROM memberships")
            args: tuple = ()
            if server_id:
                sql += " WHERE server_id=?"
                args = (server_id,)
            row = c.execute(sql, args).fetchone()
            return int(row["live"]), int(row["gone"])
        finally:
            c.close()

    def run_job(self, fn) -> tuple[dict, ops.Job]:
        job = ops.Job(id=1, kind="probe")
        return fn(job), job

    def test_api_start_refuses_a_missing_fixture(self) -> None:
        """A fresh control, because this class already has the API up: start() is
        idempotent, so the guard only shows on a cold start."""
        ghost = Settings(db=str(TMP / "no-such-fixture.db"), api_port=free_port())
        with mock.patch.object(ops, "API", ops.ApiControl()), self.assertRaises(RuntimeError) as ctx:
            ops.API.start(ghost, ops.Job(id=2, kind="api-start"))
        self.assertIn("Generator Mode", str(ctx.exception))

    def test_join_then_undo_moves_memberships(self) -> None:
        before_live, before_gone = self.counts(self.public)
        result, job = self.run_job(ops.job_join(self.settings, self.public, "fixture-logins", "", 3, 0.0))
        self.assertEqual(result["counts"], {"joined": 3}, (result, job.log[-4:]))
        self.assertEqual(len(result["joined_user_ids"]), 3)
        self.assertEqual(self.counts(self.public), (before_live + 3, before_gone))
        # the join went through the API, so the audit columns are the API's, not ours
        c = self.conn()
        rows = c.execute("SELECT source, role FROM memberships WHERE server_id=?", (self.public,)).fetchall()
        c.close()
        self.assertEqual({tuple(r) for r in rows}, {("api", "member")})

        again, _ = self.run_job(ops.job_join(self.settings, self.public, "fixture-logins", "", 3, 0.0))
        self.assertEqual(again["counts"].get("already-member"), 3, again)
        self.assertEqual(self.counts(self.public)[0], before_live + 3, "re-joining must not invent rows")

        left, job2 = self.run_job(ops.job_leave(self.settings, self.public, result["joined_user_ids"]))
        self.assertEqual(left["left"], 3, (left, job2.log[-3:]))
        self.assertEqual(left["skipped"], 0)
        self.assertEqual(self.counts(self.public), (before_live, before_gone + 3))
        c = self.conn()
        departed = c.execute("SELECT COUNT(*) n FROM memberships WHERE left_ts IS NOT NULL").fetchone()["n"]
        c.close()
        self.assertGreaterEqual(departed, before_gone + 3, "undo stamps left_ts; it never deletes history")

    def test_rejoin_reopens_the_same_row(self) -> None:
        result, _ = self.run_job(ops.job_join(self.settings, self.public, "fixture-logins", "", 2, 0.0))
        ids = result["joined_user_ids"]
        self.run_job(ops.job_leave(self.settings, self.public, ids))
        live_after_leave = self.counts(self.public)
        total_after_leave = self.counts()[0] + self.counts()[1]
        result2, _ = self.run_job(ops.job_join(self.settings, self.public, "fixture-logins", "", 2, 0.0))
        self.assertEqual(result2["counts"].get("rejoined"), 2, result2)
        self.assertEqual(self.counts(self.public), (live_after_leave[0] + 2, live_after_leave[1] - 2))
        self.assertEqual(self.counts()[0] + self.counts()[1], total_after_leave,
                         "rejoin must update the row, not append")
        self.run_job(ops.job_leave(self.settings, self.public, result2["joined_user_ids"]))

    def test_private_and_full_servers_are_refused_honestly(self) -> None:
        private, _ = self.run_job(ops.job_join(self.settings, self.priv, "fixture-logins", "", 3, 0.0))
        self.assertEqual(private["counts"], {"refused": 3}, private)
        self.assertEqual(self.counts(self.priv), (0, 0), "a refusal must not half-write a row")
        full, job = self.run_job(ops.job_join(self.settings, self.capped, "fixture-logins", "", 3, 0.0))
        self.assertEqual(full["counts"].get("joined"), 1, full)
        self.assertEqual(full["counts"].get("refused"), 2, full)
        self.assertEqual(self.counts(self.capped)[0], 1, "capacity is the API's rule; we only report it")
        self.assertIn("at capacity", " ".join(job.log))
        self.run_job(ops.job_leave(self.settings, self.capped, full["joined_user_ids"]))

    def test_unknown_server_reports_no_such_server(self) -> None:
        result, job = self.run_job(ops.job_join(self.settings, 999999, "fixture-logins", "", 1, 0.0))
        self.assertEqual(result["counts"], {"no-such-server": 1}, result)
        self.assertIn("no such server", " ".join(job.log))

    def test_throttled_joins_are_counted_not_hidden(self) -> None:
        tight = Settings(**{**self.settings.to_json_dict(), "join_rate_limit_per_min": 2})
        stopped = ops.API.stop(self.settings, ops.Job(id=3, kind="api-stop"))
        self.assertEqual(stopped["state"], "stopped")
        try:
            ops.API.start(tight, ops.Job(id=4, kind="api-start"))
            result, _ = self.run_job(ops.job_join(tight, self.public, "fixture-logins", "", 6, 0.0))
            self.assertGreaterEqual(result["counts"].get("throttled", 0), 1, result)
            self.assertEqual(sum(result["counts"].values()), 6, "every account is accounted for")
            if result["joined_user_ids"]:
                self.run_job(ops.job_leave(tight, self.public, result["joined_user_ids"]))
        finally:
            ops.API.stop(tight, ops.Job(id=5, kind="api-stop"))
            ops.API.start(self.settings, ops.Job(id=6, kind="api-start"))

    def test_token_file_source_resolves_only_live_fixture_sessions(self) -> None:
        c = self.conn()
        email, token = c.execute(
            "SELECT u.email, s.token FROM users u JOIN sessions s ON s.user_id=u.id "
            "WHERE s.revoked=0 ORDER BY s.id LIMIT 1").fetchone()[:2]
        c.close()
        dump = self.accounts / "accounts-probe.txt"
        dump.write_text("# dump header, ignored\n"
                        f"{email}\t{token}\n"
                        "nobody@corp.invalid\tsecrev_" + "0" * 52 + "\n")
        pairs = ops.usable_accounts(self.settings, "token-file", dump.name, 10)
        self.assertEqual(len(pairs), 1, "a token that is not a live session must be dropped")
        self.assertEqual(pairs[0][1], token)
        self.assertIn("accounts-probe.txt", [d["name"] for d in ops.fixture_status(self.settings)["dumps"]])

        result, _ = self.run_job(ops.job_join(self.settings, self.public, "token-file", dump.name, 10, 0.0))
        self.assertEqual(result["counts"], {"joined": 1}, result)
        self.run_job(ops.job_leave(self.settings, self.public, result["joined_user_ids"]))

        only_bad = self.accounts / "accounts-stale.txt"
        only_bad.write_text("x@corp.invalid\t" + "0" * 56 + "\n")
        with self.assertRaises(RuntimeError) as ctx:
            ops.usable_accounts(self.settings, "token-file", only_bad.name, 5)
        self.assertIn("revoked or unknown", str(ctx.exception))

    def test_token_file_outside_the_accounts_dir_is_not_reachable(self) -> None:
        with self.assertRaises(RuntimeError) as ctx:
            ops.usable_accounts(self.settings, "token-file", "../console-server.json", 5)
        self.assertIn("no such token file", str(ctx.exception))

    def test_pacing_is_applied_between_accounts(self) -> None:
        t0 = time.time()
        result, _ = self.run_job(ops.job_join(self.settings, self.public, "fixture-logins", "", 3, 60.0))
        elapsed = time.time() - t0
        self.assertEqual(sum(result["counts"].values()), 3, result)
        self.assertGreaterEqual(elapsed, 0.12, "3 accounts at 60ms is at least two gaps")
        self.run_job(ops.job_leave(self.settings, self.public, result["joined_user_ids"]))

    def test_leave_needs_ids(self) -> None:
        with self.assertRaises(RuntimeError) as ctx:
            self.run_job(ops.job_leave(self.settings, self.public, []))
        self.assertIn("no user ids", str(ctx.exception))

    def test_join_from_the_roster_file(self) -> None:
        """Option B "accounts from the list": the roster is the selection, and a name in it
        that the fixture no longer knows is skipped rather than attempted."""
        c = self.conn()
        names = [r[0] for r in c.execute(
            "SELECT username FROM users WHERE status='active' ORDER BY id LIMIT 3")]
        c.close()
        roster.write_roster(Path(self.settings.account_list), [*names, "ghostaccount"])
        result, job = self.run_job(ops.job_join(self.settings, self.public, "roster", "", 3, 0.0))
        self.assertEqual(result["accounts"], 3, result)
        self.assertEqual(result["counts"].get("joined"), 3, (result, job.log[-3:]))
        self.assertEqual(self.counts(self.public)[0], 3)
        self.run_job(ops.job_leave(self.settings, self.public, result["joined_user_ids"]))
        self.assertEqual(self.counts(self.public)[0], 0)

    def test_undo_walks_back_past_a_join_that_added_nothing(self) -> None:
        """The reported bug: join, then join again (everything came back already-member),
        then Undo — which must undo the join that actually moved accounts, not refuse."""
        stub = SimpleNamespace(settings_path=TMP / "unused.json")
        c = self.conn()
        names = [r[0] for r in c.execute(
            "SELECT username FROM users WHERE status='active' ORDER BY id DESC LIMIT 3")]
        c.close()
        roster.write_roster(Path(self.settings.account_list), names)
        runner = ops.Runner()
        with mock.patch.object(ops, "JOBS", runner):
            first = runner.submit("join", ops.job_join(self.settings, self.public, "roster", "", 3, 0.0))
            self._settle(runner, first.id)
            self.assertEqual(first.state, "done", first.log[-3:])
            ids = first.result["joined_user_ids"]
            self.assertEqual(len(ids), 3)
            second = runner.submit("join", ops.job_join(self.settings, self.public, "roster", "", 3, 0.0))
            self._settle(runner, second.id)
            self.assertEqual(second.result["counts"], {"already-member": 3}, second.result)
            self.assertEqual(second.result["joined_user_ids"], [], "the retry created nothing")

            fn = Handler._build(stub, "leave", {}, self.settings)
            result, job = self.run_job(fn)
            self.assertEqual(result["left"], 3, (result, job.log[-3:]))
            c = self.conn()
            marks = ",".join("?" * len(ids))
            live = int(c.execute(f"SELECT COUNT(*) FROM memberships WHERE server_id=? AND left_ts IS NULL "
                                 f"AND user_id IN ({marks})", (self.public, *ids)).fetchone()[0])
            c.close()
            self.assertEqual(live, 0, "the accounts the join added are the ones the undo removed")

            again, _job2 = self.run_job(Handler._build(stub, "leave", {}, self.settings))
            self.assertEqual((again["left"], again["skipped"]), (0, 3),
                             "a second undo is an honest no-op, not an error")

    @staticmethod
    def _settle(runner: ops.Runner, job_id: int, timeout: float = 60.0) -> None:
        t0 = time.time()
        while time.time() - t0 < timeout:
            snap = {j["id"]: j["state"] for j in runner.snapshot(50)}
            if snap.get(job_id) in ("done", "failed"):
                return
            time.sleep(0.05)
        raise AssertionError(f"job {job_id} never finished")

    def test_fixture_status_describes_the_ledger(self) -> None:
        status = ops.fixture_status(self.settings)
        self.assertTrue(status["exists"])
        self.assertGreater(status["tables"]["users"], 0)
        self.assertEqual([s["id"] for s in status["servers"]], list(range(1, len(status["servers"]) + 1)))
        flags = {s["id"]: (s["private"], s["capacity"]) for s in status["servers"]}
        self.assertEqual(flags[self.priv], (1, None), "the tab must show which servers are private")
        self.assertEqual(flags[self.capped], (0, 1))
        live, gone = self.counts()
        self.assertEqual(status["tables"]["memberships"], live + gone,
                         "the tab counts rows, it does not re-derive them")
        c = self.conn()
        total = int(c.execute("SELECT COUNT(*) n FROM memberships").fetchone()["n"])
        c.close()
        self.assertEqual(status["tables"]["memberships"], total)


class RosterTest(unittest.TestCase):
    """The hand-editable account list: what it says, what a Sync would do, and the two
    plaintext exports it can produce."""

    @classmethod
    def setUpClass(cls) -> None:
        # one fixture build, copied per test: Sync deletes rows for real, and a shared db
        # would make every test here depend on the one that ran before it
        cls.base_db = seed_db("roster", users=40, inject_bots=0)

    def setUp(self) -> None:
        self.dir = TMP / f"roster-{self.id().rsplit('.', 1)[-1]}"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.db = self.dir / "fixture.db"
        src = sqlite3.connect(self.base_db)
        dst = sqlite3.connect(self.db)
        try:
            src.backup(dst)  # not shutil: this folds the WAL into the copy in one step
        finally:
            src.close()
            dst.close()
        self.roster_path = self.dir / "accounts.txt"
        self.settings = Settings(db=str(self.db), account_list=str(self.roster_path),
                                 accounts_dir=str(self.dir), bootstrap_accounts=3)

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.db)
        c.row_factory = sqlite3.Row
        return c

    def test_a_rebuild_rewrites_the_list_and_an_append_only_adds(self) -> None:
        """`_sync_roster_after_generate` is what keeps the file and the fixture from drifting
        apart after a Generate click — in opposite directions depending on the mode."""
        conn = self.conn()
        all_names = roster.fixture_identities(conn)
        roster.write_roster(self.roster_path, all_names[:2])
        before = ops._sync_roster_after_generate(self.settings, ops.Job(id=1, kind="g"),
                                                after_id=int(conn.execute(
                                                    "SELECT COALESCE(MAX(id),0) m FROM users").fetchone()["m"]))
        self.assertEqual(before["roster_added"], 0, "append mode with nothing new changes nothing")
        self.assertEqual(roster.read_roster(self.roster_path).identities, all_names[:2])
        rebuilt = Settings(**{**self.settings.to_json_dict(), "write_mode": "replace"})
        after = ops._sync_roster_after_generate(rebuilt, ops.Job(id=2, kind="g"), after_id=10_000)
        self.assertEqual(roster.read_roster(self.roster_path).identities, all_names,
                         "a rebuilt fixture must leave a list of the accounts it now has")
        self.assertEqual(after["roster_total"], len(all_names))
        conn.close()

    def test_every_setting_is_editable_in_the_tab(self) -> None:
        """The tab renders `FIELDS`, so a field added to the dataclass without an entry is a
        knob nobody can turn — and a removed one leaves a control that saves "ignored
        (unknown setting)" forever. `fresh` sat in the page as a checkbox for exactly one
        round after `write_mode` replaced it."""
        from console.server import PAGE

        block = PAGE[PAGE.index("const FIELDS=["):PAGE.index("];", PAGE.index("const FIELDS=["))]
        shown = set(re.findall(r'\["([a-z0-9_]+)"', block))
        real = {f.name for f in dataclasses.fields(Settings)} - {"unknown"}
        self.assertEqual(shown & real, real, f"not editable in Settings: {sorted(real - shown)}")
        self.assertEqual(sorted(shown - real), [], f"the page still offers removed settings: {sorted(shown - real)}")

    def test_write_mode_picks_the_seeder_flag(self) -> None:
        append = Settings(write_mode="append").base_argv()
        replace = Settings(write_mode="replace").base_argv()
        self.assertIn("--append", append)
        self.assertNotIn("--fresh", append)
        self.assertIn("--fresh", replace)
        self.assertNotIn("--append", replace)
        with self.assertRaises(SettingsError):
            apply_updates(Settings(), {"write_mode": "sideways"})

    def test_legacy_fresh_bool_is_read_as_a_mode(self) -> None:
        path = TMP / "settings-legacy.json"
        path.write_text(json.dumps({"users": 10, "fresh": True}))
        self.assertEqual(load(path).write_mode, "replace")
        path.write_text(json.dumps({"fresh": False}))
        self.assertEqual(load(path).write_mode, "append")

    def test_account_list_path_follows_the_scratch_rule(self) -> None:
        self.assertEqual(validate("account_list", "var/accounts.txt"), "var/accounts.txt")
        for refused in ("/etc/passwd", "accounts.txt", "var/notes.md2", "var/prod-users.txt"):
            with self.subTest(refused), self.assertRaises(SettingsError):
                validate("account_list", refused)
        self.assertEqual(Settings().bootstrap_accounts, 5)
        with self.assertRaises(SettingsError):
            validate("bootstrap_accounts", 10_000_000)

    def test_status_reports_drift_in_both_directions(self) -> None:
        expected = len(roster.fixture_identities(self.conn()))
        out = ops.job_roster(self.settings, "rewrite")(ops.Job(id=1, kind="r"))
        self.assertEqual(out, {"written": expected, "path": str(self.roster_path)},
                         "rewrite is the fixture's list, exactly")
        status = ops.roster_status(self.settings, conn=None)
        self.assertEqual((status["listed"], status["in_fixture"]), (status["listed"], status["listed"]))
        self.assertEqual(status["unlisted"], [])
        names = roster.read_roster(self.roster_path).identities
        roster.write_roster(self.roster_path, names[:-2])
        drift = ops.roster_status(self.settings, conn=None)
        self.assertEqual(drift["unlisted_count"], 2, "two accounts are no longer listed")
        self.assertEqual(drift["unlisted"], names[-2:])
        roster.write_roster(self.roster_path, [*names[:-2], "someone-who-is-not-here"])
        drift = ops.roster_status(self.settings, conn=None)
        self.assertEqual(drift["unknown"], ["someone-who-is-not-here"], "a typo is reported, not joined")

    def test_sync_removes_the_account_and_everything_hanging_off_it(self) -> None:
        roster.write_roster(self.roster_path, roster.fixture_identities(self.conn()))
        c = self.conn()
        names = roster.read_roster(self.roster_path).identities
        keep = names[:3]
        doomed = roster.resolve(c, names[3:])
        sid = int(c.execute("SELECT id FROM servers ORDER BY id LIMIT 1").fetchone()[0])
        first = int(c.execute("SELECT id FROM users ORDER BY id LIMIT 1").fetchone()[0])
        c.execute("INSERT INTO memberships(server_id, user_id, joined_ts, role, source) VALUES(?,?,?,'member','api')",
                  (sid, first, int(time.time())))
        before = {t: int(c.execute(f"SELECT COUNT(*) n FROM {t}").fetchone()["n"])
                  for t in ("users", "credentials", "sessions", "events", "memberships", "servers")}
        preview = roster.sync(c, keep, apply=False)
        after_preview = int(c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"])
        self.assertEqual(preview["would_delete"], len(names) - 3)
        self.assertEqual(after_preview, before["users"], "a preview must not touch a row")
        result = roster.sync(c, keep, apply=True)
        c.commit()
        self.assertEqual(result["deleted"], len(names) - 3)
        self.assertTrue(result["applied"])
        now = {t: int(c.execute(f"SELECT COUNT(*) n FROM {t}").fetchone()["n"])
               for t in ("users", "credentials", "sessions", "events", "memberships", "servers")}
        self.assertEqual(now["users"], 3)
        self.assertLess(now["credentials"], before["credentials"], "credentials follow the account")
        self.assertLess(now["sessions"], before["sessions"], "sessions follow it, revoked or not")
        self.assertEqual(now["memberships"], before["memberships"] - (1 if first in doomed.values() else 0))
        self.assertEqual(now["servers"], before["servers"], "rooms survive their owner being pruned")
        for table, column in (("credentials", "user_id"), ("sessions", "user_id"), ("events", "user_id")):
            orphans = c.execute(f"SELECT COUNT(*) n FROM {table} WHERE {column} NOT IN (SELECT id FROM users)"
                                ).fetchone()["n"]
            self.assertEqual(orphans, 0, f"{table} rows outlived the account")
        c.close()

    def test_seed_action_takes_the_newest_accounts(self) -> None:
        roster.write_roster(self.roster_path, ["keep-me"])
        out = ops.job_roster(self.settings, "seed")(ops.Job(id=2, kind="r"))
        self.assertEqual(out["seeded"], self.settings.bootstrap_accounts)
        listed = roster.read_roster(self.roster_path).identities
        self.assertEqual(out["written"], len(listed))
        self.assertIn("keep-me", listed, "seeding adds to the file, it does not replace a hand edit")
        c = self.conn()
        newest = [r[0] for r in c.execute("SELECT username FROM users ORDER BY id DESC LIMIT 3")]
        c.close()
        self.assertEqual(set(newest) <= set(listed), True)

    def test_the_two_exports_are_colon_pairs_at_0600(self) -> None:
        roster.write_roster(self.roster_path, roster.fixture_identities(self.conn()))
        listed = roster.read_roster(self.roster_path).identities
        c = self.conn()
        active = int(c.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0])
        with_session = int(c.execute("SELECT COUNT(*) FROM users u WHERE u.status='active' AND EXISTS"
                                    " (SELECT 1 FROM sessions s WHERE s.user_id=u.id AND s.revoked=0)"
                                    ).fetchone()[0])
        c.close()
        self.assertLess(with_session, active,
                        "some active accounts have no live session: that is what skipped_no_session is for")
        expected = {"userpass": active, "token": with_session}
        for kind in ("userpass", "token"):
            out = ops.job_accounts_info(self.settings, kind, 0, use_roster=True)(ops.Job(id=3, kind="i"))
            path = Path(out["path"])
            suffix = "tokens" if kind == "token" else "userpass"
            self.assertEqual(path.name, f"{self.roster_path.stem}-{suffix}.txt")
            self.assertEqual(out["written"], expected[kind],
                             f"{kind}: one line per account that can actually authenticate")
            self.assertEqual(out["skipped_inactive"], len(listed) - active,
                             "inactive accounts are named in the report, not silently missing")
            self.assertEqual(out["selection"], "roster")
            self.assertEqual(path.stat().st_mode & 0o077, 0, f"{path.name} is group/other readable")
            body = [ln for ln in path.read_text().splitlines() if ln and not ln.startswith("#")]
            self.assertEqual(len(body), out["written"])
            for line in body:
                head, sep, secret = line.partition(":")
                self.assertTrue(sep and head and secret, f"malformed export line {line!r}")
                self.assertIn(head, listed, "exports carry the roster's identities, nothing else")
                if kind == "userpass":
                    self.assertEqual(secret, self.settings.test_password)
                else:
                    self.assertTrue(secret.startswith("ses_"), secret)
                    self.assertNotIn(self.settings.test_password, secret,
                                     "the token export is not a password export with a new name")

    def test_inactive_accounts_are_never_exported(self) -> None:
        c = self.conn()
        active = int(c.execute("SELECT COUNT(*) n FROM users WHERE status='active'").fetchone()["n"])
        total = int(c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"])
        c.close()
        out = ops.job_accounts_info(self.settings, "userpass", 0, use_roster=False)(ops.Job(id=4, kind="i"))
        self.assertEqual(out["written"], active, "banned and pending accounts are not handed out")
        self.assertLess(active, total, "the fixture must still contain an inactive row for this to mean anything")
        self.assertEqual(out["selection"], "whole fixture")

    def test_roster_revoke_revokes_sessions_and_removes_the_file(self) -> None:
        ops.job_accounts_info(self.settings, "token", 0, use_roster=False)(ops.Job(id=5, kind="i"))
        path = ops.roster_export_path(self.settings, "token")
        self.assertTrue(path.exists())
        c = self.conn()
        live_before = int(c.execute("SELECT COUNT(*) n FROM sessions WHERE revoked=0").fetchone()["n"])
        c.close()
        out = ops.job_roster_revoke(self.settings, "token")(ops.Job(id=6, kind="r"))
        self.assertEqual(out["code"], 0, out)
        self.assertIn("revoked", out["output"])
        self.assertFalse(path.exists(), "the plaintext is gone once its sessions are dead")
        c = self.conn()
        live_after = int(c.execute("SELECT COUNT(*) n FROM sessions WHERE revoked=0").fetchone()["n"])
        c.close()
        self.assertLess(live_after, live_before, "the sessions behind it are actually revoked")
        # a user:pass export has no sessions to revoke: removing it is the whole action
        ops.job_accounts_info(self.settings, "userpass", 0, use_roster=False)(ops.Job(id=7, kind="i"))
        out = ops.job_roster_revoke(self.settings, "userpass")(ops.Job(id=8, kind="r"))
        self.assertIn("no sessions to revoke", out["output"])
        self.assertFalse(ops.roster_export_path(self.settings, "userpass").exists())

    def test_missing_files_and_bad_names_are_refused(self) -> None:
        with self.assertRaises(RuntimeError) as ctx:
            ops.job_roster(Settings(db=str(self.db), account_list=str(self.dir / "nope.txt")),
                           "sync")(ops.Job(id=9, kind="r"))
        self.assertIn("does not exist", str(ctx.exception))
        with self.assertRaises(RuntimeError) as ctx:
            ops.job_roster_revoke(self.settings, "userpass")(ops.Job(id=10, kind="r"))
        self.assertIn("was never written", str(ctx.exception))
        stub = SimpleNamespace(settings_path=TMP / "unused.json")
        cases = [("accounts-info", {"kind": "cookie"}, "userpass or user:token"),
                 ("roster", {"action": "drop-tables"}, "preview, sync, rewrite or seed"),
                 ("roster-revoke", {"kind": "cookie"}, "pick which export to clean up"),
                 ("join", {"server_id": 1, "source": "paste-my-own"}, "accounts must come from")]
        for kind, params, needle in cases:
            with self.subTest(kind=kind):
                with self.assertRaises(ValueError) as ctx:
                    Handler._build(stub, kind, params, self.settings)
                self.assertIn(needle, str(ctx.exception))

    def test_roster_view_masks_by_default_and_takes_no_path(self) -> None:
        ops.job_accounts_info(self.settings, "userpass", 0, use_roster=False)(ops.Job(id=11, kind="i"))
        stub = Handler.__new__(Handler)  # _roster_view reads its settings from self.settings_path
        stub.settings_path = self.dir / "settings.json"
        save(stub.settings_path, self.settings)
        masked = Handler._roster_view(stub, {"view": ["userpass"]})
        self.assertIn("hidden", masked)
        self.assertNotIn(self.settings.test_password, masked)
        revealed = Handler._roster_view(stub, {"view": ["userpass"], "reveal": ["1"]})
        self.assertIn(self.settings.test_password, revealed, "?reveal=1 is the explicit opt-in")
        self.assertIn("view must be", Handler._roster_view(stub, {"view": ["../../../etc/passwd"]}))
        plain = Handler._roster_view(stub, {})
        self.assertIn("accounts.txt", plain)
        roster.write_roster(self.roster_path, roster.fixture_identities(self.conn()))
        self.assertNotIn(self.settings.test_password, Handler._roster_view(stub, {}),
                        "the roster itself never carries secrets, so there is nothing to mask")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
