from __future__ import annotations

import contextlib
import io
import os
import stat
import unittest
from pathlib import Path
from types import SimpleNamespace
from urllib.request import Request, urlopen

from load.accounts import (
    AccountRow,
    collect,
    local_target,
    read_tokens,
    render_md,
    render_txt,
    write_artifacts,
)
from load.accounts import (
    main as revoke_main,
)
from load.engine import write_account_dump
from mockapi.client import ApiClient
from tests._support import RunningApi, seed_db

ROWS = [
    AccountRow(ident="zoë@mail.invalid", token="ses_a", source="login", stage="s1"),
    AccountRow(ident="a@b.invalid", token="ses_b", source="spec capture", stage="s2"),
]


class CollectTest(unittest.TestCase):
    def test_both_ctx_shapes_are_read(self) -> None:
        """Built-in scenarios store the identity as ctx['as']; the spec path stores the
        drawn identifier. A dump that only knew one of them would print 'worker-s1'
        for every row, which is useless for logging back in."""
        ledgers = [("s1", [{"token": "ses_1", "as": "someone@gmail.com"},
                           {"rnd": object()}]),
                   ("s2", [{"token": "ses_2", "last_email": "lt9@loadtest.invalid"},
                           {"rnd": object()}])]
        rows, workers, no_token = collect(ledgers, source="mixed")
        self.assertEqual(workers, 4)
        self.assertEqual(no_token, 2, "two workers never authenticated")
        self.assertEqual({r.ident for r in rows}, {"someone@gmail.com", "lt9@loadtest.invalid"})
        self.assertEqual({r.source for r in rows}, {"mixed"})

    def test_one_row_per_token_and_sorted(self) -> None:
        tok = "ses_same"
        ledgers = [("s1", [{"token": tok, "as": "early@x.invalid"}]),
                   ("s2", [{"token": tok, "as": "Late@x.invalid"}])]
        rows, workers, _ = collect(ledgers, source="mixed")
        self.assertEqual(len(rows), 1, "the same session must not appear twice per stage")
        self.assertEqual(rows[0].stage, "s2", "the later sighting wins")
        self.assertEqual(workers, 2)


class SplitPairTest(unittest.TestCase):
    """One parser for every account-list shape, because `--revoke` and a `--token-file` run
    read the same files and must not disagree about what a token is."""

    def pairs(self, blob: str) -> list[tuple[str, str]]:
        from load.accounts import parse_file, split_pair

        lines = [ln for ln in blob.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        parsed = parse_file(_tmp_write(blob))
        self.assertEqual(parsed, [p for p in (split_pair(ln) for ln in lines) if p],
                         "parse_file must be exactly split_pair over the accepted lines, "
                         "so the two readers of a dump cannot disagree")
        return parsed

    def test_three_accepted_shapes(self) -> None:
        got = self.pairs("bob\tses_tabtoken_1234567890\n"
                         "bob:ses_colontoken_1234567890\n"
                         "ses_bare_token_1234567890ab\n")
        self.assertEqual(got, [("bob", "ses_tabtoken_1234567890"), ("bob", "ses_colontoken_1234567890"),
                               ("", "ses_bare_token_1234567890ab")])

    def test_short_tab_tokens_still_count(self) -> None:
        """The tab form is what load.engine writes, so its old (looser) rule stays: no
        length gate on a line that is explicitly `identity<TAB>token`."""
        self.assertEqual(self.pairs("bob\tses_9\n"), [("bob", "ses_9")])

    def test_a_password_file_is_not_a_token_file(self) -> None:
        blob = "bob:Fixture-Test-Pass-2026!\nalice:ShortPw\njust some prose\n# comment\n"
        self.assertEqual(self.pairs(blob), [])
        from load.accounts import read_tokens

        self.assertEqual(read_tokens(_tmp_write(blob)), [],
                         "revoking a user:pass list must find nothing rather than guess")

    def test_email_identity_with_a_colon_inside_it(self) -> None:
        # rpartition on ':' keeps the longest token candidate, so an ident with a colon
        # still resolves; the shape gate does the rest
        self.assertEqual(self.pairs("a@b.invalid:ses_0123456789abcdef"),
                         [("a@b.invalid", "ses_0123456789abcdef")])


class RenderTest(unittest.TestCase):
    def test_txt_roundtrips_and_carries_no_password(self) -> None:
        text = render_txt(ROWS, base_url="http://127.0.0.1:8000", revoke_cmd="python3 -m load.accounts")
        lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
        self.assertEqual(len(lines), 2)
        self.assertTrue(all("\t" in ln for ln in lines), lines)
        self.assertIn("no passwords", text)
        self.assertNotIn("Fixture-Test-Pass", text)
        self.assertEqual(read_tokens(_tmp_write(text)), ["ses_a", "ses_b"])

    def test_read_tokens_skips_comments_and_bare_tokens(self) -> None:
        blob = ("# comment\n\nuser@x\t ses_9\nses_bare_that_is_long_enough\r\n"
                "not-a-token-line\n")
        self.assertEqual(read_tokens(_tmp_write(blob)), ["ses_9", "ses_bare_that_is_long_enough"],
                         "a stray space after the tab must not silently spare a session")

    def test_md_documents_provenance_and_the_gap(self) -> None:
        md = render_md(ROWS, base_url="http://127.0.0.1:8000", fixture_hash="a6270147ec3fa1d8",
                       scenario="mixed", stages="25,100", seed=7, workers=9, without_token=4,
                       revoke_cmd="python3 -m load.accounts --revoke x.txt")
        self.assertIn("a6270147ec3fa1d8", md)
        self.assertIn("- workers: 9 — 2 distinct tokens, 4 never authenticated", md)
        self.assertIn("`mixed`", md)
        self.assertIn("worker(s) ended without a token", md, "the skip count must be explained")
        self.assertNotIn("Fixture-Test-Pass", md, "passwords never belong in this file")

    def test_write_artifacts_are_private(self) -> None:
        out = Path(__import__("tempfile").mkdtemp(prefix="accounts-")) / "accounts-x"
        paths = write_artifacts(out, ROWS, meta={"base_url": "http://127.0.0.1:8000",
                                                "fixture_hash": "h", "scenario": "mixed",
                                                "stages": "1", "seed": 7, "workers": 2,
                                                "without_token": 0, "db": "var/test.db"})
        self.assertEqual([p.name.split("accounts-x")[1] for p in paths],
                         [".txt", ".md", ".revoke.sql"],
                         "the revoke file must be named as an obvious companion")
        for path in paths:
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(mode, 0o600, f"{path.name} is world-readable: {oct(mode)}")
        self.assertIn("UPDATE sessions SET revoked = 1", paths[2].read_text())


class TokenFileTest(unittest.TestCase):
    """`--token-file` is the reason a spec run can measure authed reads at all: workers
    start with a session, so the login limiter stops gating `requires`-guarded ops."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.db = seed_db("tokenfile", users=20, inject_bots=0, events=0.1)
        cls.api = RunningApi(cls.db, rate_limit_per_min=0, login_rate_limit_per_min=0)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.api.close()

    def parse(self, blob: str) -> Path:
        path = Path(__import__("tempfile").mkdtemp(prefix="pool-")) / "pool.txt"
        path.write_text(blob)
        return path

    def test_parser_accepts_dump_shape_and_bare_tokens(self) -> None:
        from load.accounts import parse_file

        live = self.api.base_url
        client = ApiClient(live)
        import sqlite3

        email = sqlite3.connect(self.db).execute(
            "SELECT email FROM users WHERE status='active' LIMIT 1").fetchone()[0]
        token = client.login(email, "Fixture-Test-Pass-2026!").data["token"]
        client.close()
        path = self.parse(f"# pool\n{email}\t{token}\n{token}\n")
        pairs = parse_file(path)
        self.assertEqual(pairs, [(email, token), ("", token)])

    def test_run_stage_preauths_workers_so_me_never_skips(self) -> None:
        import json

        from load.generic import GenericScenario, Spec
        from load.scenarios import LoadOptions

        spec = Spec(name="authed", base_url="", headers={}, ops=[
            __import__("load.generic", fromlist=["Op"]).Op.from_dict(
                {"name": "me", "method": "GET", "path": "/users/me",
                 "headers": {"Authorization": "Bearer {{token}}"}, "requires": ["token"],
                 "expect": [200]})])
        opts = LoadOptions(password="Fixture-Test-Pass-2026!", identifiers=[],
                           register_domain="loadtest.invalid")
        client = ApiClient(self.api.base_url)
        ledger: list[dict] = []
        from load.engine import run_stage

        stats, _rec = run_stage(client, GenericScenario(spec), opts, concurrency=3, seconds=1.5,
                                rps=0.0, think_ms=0.0, seed=1, label="s1", ledger=ledger,
                                token_pool=[("seeded@x.invalid", "ses_fake_should_401")])
        # a bogus token proves the wiring: it is *sent* (401 => auth_fail), not skipped
        self.assertGreater(stats.ops, 0)
        self.assertEqual(set(stats.kinds), {"auth_fail"},
                         f"pre-minted state must be used, got {stats.kinds}")
        self.assertTrue(all(c.get("token_source") == "token-file" for c in ledger), ledger)
        rows, workers, without = collect([("s1", ledger)], source="authed")
        self.assertEqual((workers, without), (3, 0))
        self.assertEqual({r.source for r in rows}, {"token-file"})
        self.assertEqual({r.ident for r in rows}, {"seeded@x.invalid"})

        # and with a real token the same op succeeds
        import sqlite3

        email = sqlite3.connect(self.db).execute(
            "SELECT email FROM users WHERE status='active' LIMIT 1").fetchone()[0]
        good = self.good_token(email)
        stats2, _ = run_stage(client, GenericScenario(spec), opts, concurrency=2, seconds=1.0,
                              rps=0.0, think_ms=0.0, seed=2, label="s2", token_pool=[(email, good)])
        self.assertEqual(set(stats2.kinds), {"ok"}, stats2.kinds)
        self.assertEqual(json.dumps(stats2.per_op["me"]["kinds"]), '{"ok": ' + str(stats2.ops) + "}")
        client.close()

    def good_token(self, email: str) -> str:
        client = ApiClient(self.api.base_url)
        token = client.login(email, "Fixture-Test-Pass-2026!").data["token"]
        client.close()
        return token


class GuardTest(unittest.TestCase):
    def test_local_target_matrix(self) -> None:
        for url, ok in (("http://127.0.0.1:8000", True), ("http://localhost:8000", True),
                        ("http://api.loadtest.invalid", True), ("http://staging.acme.io", True),
                        ("http://dev.acme.io", True), ("https://api.acme.io", False),
                        ("https://prod.acme.io", False), ("not a url", False)):
            self.assertEqual(local_target(url), ok, url)

    def test_remote_target_refuses_without_the_flag(self) -> None:
        args = SimpleNamespace(base_url="https://api.real-corp.com", accounts_file="auto",
                               allow_remote_tokens=False, out=str(Path(__import__("tempfile").mkdtemp())),
                               fixture_db=None, stages="25", seed=7)
        ledgers = [("s1", [{"token": "ses_x", "as": "u@v.com"}])]
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            written = write_account_dump(args, SimpleNamespace(name="mixed"), ledgers, False,
                                         Path("load-20260101-000000.md"))
        self.assertEqual(written, [], "a production host must not get a token dump by accident")
        self.assertIn("--allow-remote-tokens", err.getvalue())

    def test_empty_ledger_is_reported_as_an_auth_failure_not_a_clean_run(self) -> None:
        args = SimpleNamespace(base_url="http://127.0.0.1:8000", accounts_file="auto",
                               allow_remote_tokens=False, out="/tmp", fixture_db=None,
                               stages="25", seed=7)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            written = write_account_dump(args, SimpleNamespace(name="mixed"), [("s1", [{"rnd": 1}])],
                                         False, Path("load-x.md"))
        self.assertEqual(written, [])
        self.assertIn("no worker ended with a token", err.getvalue())


class RevokeAgainstApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.db = seed_db("accounts", users=40, inject_bots=0, events=0.2)
        cls.api = RunningApi(cls.db, rate_limit_per_min=0, login_rate_limit_per_min=0)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.api.close()

    def test_a_dumped_token_works_then_stops_working_as_a_unit(self) -> None:
        import sqlite3

        client = ApiClient(self.api.base_url)
        creds = sqlite3.connect(self.db)
        email = creds.execute("SELECT email FROM users WHERE status='active' LIMIT 1").fetchone()[0]
        resp = client.login(email, "Fixture-Test-Pass-2026!")
        self.assertEqual(resp.status, 200, resp.data)
        token = resp.data["token"]

        out_dir = Path(__import__("tempfile").mkdtemp(prefix="revoke-"))
        dump = out_dir / "accounts-y.txt"
        dump.write_text(render_txt([AccountRow(email, token, "login", "s1")],
                                   base_url=self.api.base_url, revoke_cmd="revoke"))

        # live now: it is a real session on the target
        me = urlopen(Request(f"{self.api.base_url}/users/me",
                             headers={"Authorization": f"Bearer {token}"}))
        self.assertEqual(me.status, 200)

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(revoke_main(["--revoke", str(dump), "--db", str(self.db), "--dry-run"]), 0)
        self.assertIn("1 currently live", out.getvalue())
        with contextlib.redirect_stdout(out):
            self.assertEqual(revoke_main(["--revoke", str(dump), "--db", str(self.db)]), 0)
        self.assertIn("revoked 1 live session", out.getvalue())

        with self.assertRaises(Exception) as raised:
            urlopen(Request(f"{self.api.base_url}/users/me", headers={"Authorization": f"Bearer {token}"}))
        self.assertIn("401", str(raised.exception), "the md's revoke claim must be true")

        # --delete finishes the job: a revoked token is only dead while the row is,
        # and seeded tokens come back identical on a re-seed
        (out_dir / "accounts-y.md").write_text("x")
        with contextlib.redirect_stdout(out):
            self.assertEqual(revoke_main(["--revoke", str(dump), "--db", str(self.db), "--delete"]), 0)
        self.assertFalse(dump.exists(), "the dump itself must go, not just its effect")
        self.assertFalse((out_dir / "accounts-y.md").exists(), "siblings too")
        self.assertFalse(list(out_dir.glob("accounts-y.*")), "nothing left to leak")
        client.close()

    def test_missing_files_are_clean_errors(self) -> None:
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(revoke_main(["--revoke", "/nope/none.txt", "--db", str(self.db)]), 2)
        self.assertIn("no such file", err.getvalue())


def _tmp_write(blob: str) -> Path:
    path = Path(__import__("tempfile").mkdtemp(prefix="tok-")) / "tokens.txt"
    path.write_text(blob)
    return path



if __name__ == "__main__":  # pragma: no cover
    unittest.main()
