"""`seeds.roster` — the hand-edited account list, its exports, and the one destructive action.

The roster is the seam between the .txt file an operator edits and the SQLite fixture the
console runs against, so these tests are about the three things that can go wrong there:
reading a file that is not shaped the way the writer wrote it, deleting the wrong set of
accounts, and writing a plaintext file somewhere it can be picked up by the wrong button.
"""

from __future__ import annotations

import os
import sqlite3
import stat
import unittest
from pathlib import Path

from seeds import roster
from tests._support import TMP, seed_db


def mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


class ReadWriteTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = TMP / "roster-rw"
        self.dir.mkdir(exist_ok=True)
        self.path = self.dir / "accounts.txt"

    def test_write_then_read_is_the_same_list(self) -> None:
        written = roster.write_roster(self.path, ["zoe1", "bob2", "marta1802"])
        self.assertEqual(written, 3)
        self.assertEqual(roster.read_roster(self.path).identities, ["zoe1", "bob2", "marta1802"])

    def test_comments_blanks_and_crlf_are_skipped(self) -> None:
        self.path.write_text("# mine\r\n\r\n  zoe1  \r\n# bob2\r\nzoe1\r\n", newline="")
        got = roster.read_roster(self.path)
        self.assertEqual(got.identities, ["zoe1"])
        self.assertEqual(got.duplicates, ["zoe1"], "a repeat is reported, not silently merged away")

    def test_case_insensitive_duplicates(self) -> None:
        self.path.write_text("Zoe1\nzoe1\n")
        got = roster.read_roster(self.path)
        self.assertEqual(got.identities, ["Zoe1"])
        self.assertEqual(got.duplicates, ["zoe1"])

    def test_a_pasted_userpass_file_still_reads_as_accounts(self) -> None:
        # people paste the export back into the list; the identity is the part before the secret
        self.path.write_text("zoe1:pw-here\nbob2\t ses_token\njust-a-bare-token\n")
        self.assertEqual(roster.read_roster(self.path).identities, ["zoe1", "bob2", "just-a-bare-token"])

    def test_missing_file_is_the_callers_problem(self) -> None:
        with self.assertRaises(OSError):
            roster.read_roster(self.dir / "nope.txt")

    def test_write_creates_the_directory_and_leaves_no_temp_file(self) -> None:
        # deliberately not 0600: the list is usernames only, and it has to stay editable in a
        # plain text editor without hunting for the owner's permission bits. The exports that
        # carry secrets are the ones that get the private mode (ExportTest).
        path = self.dir / "deeper" / "accounts.txt"
        roster.write_roster(path, ["a1"])
        self.assertEqual(roster.read_roster(path).identities, ["a1"])
        self.assertFalse(Path(str(path) + ".tmp").exists(), "the temp file must not survive the rename")

    def test_empty_list_writes_the_header_only(self) -> None:
        roster.write_roster(self.path, ["zoe1"])
        roster.write_roster(self.path, [])
        self.assertEqual(roster.read_roster(self.path).identities, [])
        self.assertIn("#", self.path.read_text(), "an emptied file still explains what it is for")


class SyncTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.db = seed_db("roster-sync", users=30, inject_bots=0)

    def setUp(self) -> None:
        # Sync deletes for real, so every test gets its own copy of the seeded ledger
        self.path = self.db.parent / f"sync-{self.id().rsplit('.', 1)[-1]}.db"
        src = sqlite3.connect(self.db)
        dst = sqlite3.connect(self.path)
        try:
            src.backup(dst)
        finally:
            src.close()
            dst.close()
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row

    def tearDown(self) -> None:
        self.conn.close()
        self.path.unlink(missing_ok=True)

    def names(self, n: int, *, skip: int = 0) -> list[str]:
        return [r[0] for r in self.conn.execute(
            "SELECT username FROM users ORDER BY id LIMIT ? OFFSET ?", (n, skip))]

    def test_preview_changes_nothing(self) -> None:
        keep = self.names(10)
        out = roster.sync(self.conn, keep, apply=False)
        self.assertEqual(out["would_delete"], 20)
        self.assertEqual(out["kept"], 10)
        self.assertFalse(out["applied"])
        self.assertEqual(int(self.conn.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]), 30)

    def test_apply_removes_exactly_the_unlisted(self) -> None:
        keep = self.names(10)
        out = roster.sync(self.conn, keep, apply=True)
        self.conn.commit()
        self.assertEqual(out["deleted"], 20)
        self.assertTrue(out["applied"])
        left = {r[0] for r in self.conn.execute("SELECT username FROM users")}
        self.assertEqual(left, set(keep))

    def test_children_go_with_the_account(self) -> None:
        keep = self.names(10)
        before = {t: int(self.conn.execute(f"SELECT COUNT(*) n FROM {t}").fetchone()["n"])
                  for t in ("credentials", "sessions", "events")}
        out = roster.sync(self.conn, keep, apply=True)
        self.conn.commit()
        for table in ("credentials", "sessions", "events"):
            after = int(self.conn.execute(f"SELECT COUNT(*) n FROM {table}").fetchone()["n"])
            self.assertLess(after, before[table], f"{table} rows outlived their account")
            orphans = int(self.conn.execute(
                f"SELECT COUNT(*) n FROM {table} WHERE user_id NOT IN (SELECT id FROM users)").fetchone()["n"])
            self.assertEqual(orphans, 0, f"{table} left dangling")
        self.assertGreater(sum(out["children"].values()), 0, "the report counts what it removed")

    def test_a_membership_is_removed_not_orphaned(self) -> None:
        doomed = self.names(30, skip=10)[0]
        uid = int(self.conn.execute("SELECT id FROM users WHERE username=?", (doomed,)).fetchone()[0])
        sid = int(self.conn.execute("SELECT id FROM servers ORDER BY id LIMIT 1").fetchone()[0])
        self.conn.execute("INSERT INTO memberships(server_id, user_id, joined_ts, role, source)"
                          " VALUES(?,?,?,'member','api')", (sid, uid, 1))
        self.conn.commit()
        roster.sync(self.conn, self.names(10), apply=True)
        self.conn.commit()
        self.assertEqual(int(self.conn.execute("SELECT COUNT(*) FROM memberships WHERE user_id=?",
                                               (uid,)).fetchone()[0]), 0)

    def test_rooms_survive_their_owner_being_pruned(self) -> None:
        """`servers.owner_id` carries ON DELETE CASCADE, so dropping an account that owns a
        room would take the room with it. Sync moves the room first and reports that it did."""
        owner = int(self.conn.execute("SELECT owner_id FROM servers ORDER BY id LIMIT 1").fetchone()[0])
        keep = [r[0] for r in self.conn.execute(
            "SELECT username FROM users WHERE id != ? ORDER BY id LIMIT 10", (owner,))]
        kept_ids = set(roster.resolve(self.conn, keep).values())
        self.assertNotIn(owner, kept_ids, "the owner has to be in the doomed set for this to mean anything")
        before = int(self.conn.execute("SELECT COUNT(*) n FROM servers").fetchone()["n"])
        out = roster.sync(self.conn, keep, apply=True)
        self.conn.commit()
        self.assertEqual(int(self.conn.execute("SELECT COUNT(*) n FROM servers").fetchone()["n"]), before,
                         "pruning accounts must not prune the rooms they were in")
        self.assertEqual(out["servers_deleted"], 0)
        self.assertGreater(out["servers_reassigned"], 0, "the room was handed to a survivor")
        orphans = int(self.conn.execute(
            "SELECT COUNT(*) n FROM servers WHERE owner_id NOT IN (SELECT id FROM users)").fetchone()["n"])
        self.assertEqual(orphans, 0, "no room may be left pointing at a deleted owner")

    def test_an_unrecognised_line_is_reported_not_joined(self) -> None:
        out = roster.sync(self.conn, [*self.names(10), "who-is-this"], apply=False)
        self.assertEqual(out["unknown"], ["who-is-this"])
        self.assertEqual(out["file"], 11, "the count is what the file said, not what matched")

    def test_an_empty_file_refuses_to_wipe_the_fixture(self) -> None:
        with self.assertRaises(RuntimeError) as ctx:
            roster.sync(self.conn, [], apply=True)
        self.assertIn("refusing to delete", str(ctx.exception))
        self.assertEqual(int(self.conn.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]), 30)
        # a file of nothing but comments is the same accident in disguise
        with self.assertRaises(RuntimeError):
            roster.sync(self.conn, ["# that is all I typed"], apply=True)
        # and a preview of the same input stays harmless
        self.assertEqual(roster.sync(self.conn, [], apply=False)["would_delete"], 30)

    def test_sync_with_everything_listed_is_a_no_op(self) -> None:
        out = roster.sync(self.conn, roster.fixture_identities(self.conn), apply=True)
        self.assertEqual(out["would_delete"], 0)
        self.assertNotIn("deleted", out, "nothing was deleted, so nothing claims to have been")


class IdentitiesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.db = seed_db("roster-ids", users=60, inject_bots=0)
        cls.conn = sqlite3.connect(cls.db)
        cls.conn.row_factory = sqlite3.Row

    @classmethod
    def tearDownClass(cls) -> None:
        cls.conn.close()

    def test_the_list_mirrors_inactive_accounts_too(self) -> None:
        total = int(self.conn.execute("SELECT COUNT(*) n FROM users").fetchone()["n"])
        active = int(self.conn.execute("SELECT COUNT(*) n FROM users WHERE status='active'").fetchone()["n"])
        listed = roster.fixture_identities(self.conn)
        self.assertEqual(len(listed), total, "leaving a pending account out would let a Sync delete it")
        self.assertLess(active, total, "this fixture has to contain inactive accounts to prove the point")
        self.assertEqual(len(set(listed)), len(listed))

    def test_resolve_matches_username_or_email(self) -> None:
        row = self.conn.execute("SELECT username, email, id FROM users ORDER BY id LIMIT 1").fetchone()
        uid = int(row["id"])
        self.assertEqual(roster.resolve(self.conn, [row["username"].upper()]), {row["username"]: uid},
                         "the key comes back with the fixture's spelling, and case does not matter")
        self.assertEqual(roster.resolve(self.conn, [row["email"]]), {row["email"]: uid})
        self.assertEqual(roster.resolve(self.conn, [row["username"], row["email"]]), {row["username"]: uid},
                         "one account listed two ways is still one account to drive, not two")
        self.assertEqual(roster.resolve(self.conn, ["nobody-here", "", "  "]), {},
                         "an unknown name resolves to nothing rather than to a guess")


class ExportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.db = seed_db("roster-export", users=20, inject_bots=0)
        cls.conn = sqlite3.connect(cls.db)
        cls.conn.row_factory = sqlite3.Row

    @classmethod
    def tearDownClass(cls) -> None:
        cls.conn.close()

    def setUp(self) -> None:
        self.dir = TMP / f"roster-export-{self.id().rsplit('.', 1)[-1]}"
        self.dir.mkdir(parents=True, exist_ok=True)

    def test_both_kinds_are_username_colon_secret(self) -> None:
        rows = roster.rows_for_export(self.conn, None, password="pw-for-everyone", limit=0)
        self.assertGreater(len(rows), 0, "the fixture must have something to export")
        for kind, needle in (("userpass", "pw-for-everyone"), ("token", "ses_")):
            path = self.dir / f"accounts-out-{kind}.txt"
            report = roster.write_export(path, kind, rows)
            body = [ln for ln in path.read_text().splitlines() if ln and not ln.startswith("#")]
            self.assertEqual(report["written"], len(body))
            for line in body:
                head, sep, secret = line.partition(":")
                self.assertTrue(sep and head and secret, line)
                if kind == "userpass":
                    self.assertEqual(secret, needle)
                else:
                    self.assertTrue(secret.startswith(needle), secret)
            self.assertEqual(mode(path), 0o600, f"{path.name} is world-readable")

    def test_token_export_skips_accounts_without_a_live_session(self) -> None:
        rows = [("zoe1", "pw", ""), ("bob2", "pw", "ses_live_one")]
        report = roster.write_export(self.dir / "accounts-tok.txt", "token", rows)
        self.assertEqual((report["written"], report["skipped_no_session"]), (1, 1))
        self.assertIn("bob2:ses_live_one", (self.dir / "accounts-tok.txt").read_text())

    def test_revoked_sessions_are_not_offered_as_tokens(self) -> None:
        rows = roster.rows_for_export(self.conn, None, password="pw", limit=0)
        live = {r[2] for r in rows if r[2]}
        c = self.conn
        revoked = {r[0] for r in c.execute("SELECT token FROM sessions WHERE revoked=1")}
        self.assertTrue(revoked, "the fixture must actually contain a revoked session")
        self.assertTrue(live.isdisjoint(revoked), "a revoked token must not reappear in an export")

    def test_selection_is_limited_to_the_names_given(self) -> None:
        name = self.conn.execute("SELECT username FROM users WHERE status='active' ORDER BY id"
                                 " LIMIT 1").fetchone()[0]
        rows = roster.rows_for_export(self.conn, [name], password="pw", limit=0)
        self.assertEqual([r[0] for r in rows], [name])

    def test_limit_is_applied_before_the_password_is_written(self) -> None:
        rows = roster.rows_for_export(self.conn, None, password="pw", limit=3)
        self.assertEqual(len(rows), 3)

    def test_unknown_kind_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            roster.write_export(self.dir / "x.txt", "cookie", [("a", "b", "c")])

    def test_mask_hides_the_secret_and_keeps_the_shape(self) -> None:
        masked = roster.mask("zoe1:ses_0123456789abcdef")
        self.assertTrue(masked.startswith("zoe1:se"))
        self.assertNotIn("0123456789", masked)
        self.assertIn("hidden", masked)
        for passthrough in ("# comment", "bare-with-no-colon"):
            self.assertEqual(roster.mask(passthrough), passthrough)

    def test_a_password_file_is_not_a_token_file(self) -> None:
        from load.accounts import read_tokens

        path = self.dir / "accounts-userpass.txt"
        roster.write_export(path, "userpass", roster.rows_for_export(self.conn, None,
                                                                      password="Fixture-Test-Pass-2026!",
                                                                      limit=0))
        self.assertEqual(read_tokens(path), [],
                         "feeding the user:pass export to the token reader must find nothing")
        pairs = roster.read_roster(path).identities
        self.assertTrue(pairs, "but the roster reader still recognises the accounts in it")


class StatusTest(unittest.TestCase):
    """`roster_status` lives in the console, but it is the UI's only view of drift."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.db = seed_db("roster-status", users=25, inject_bots=0)

    def setUp(self) -> None:
        from console.settings import Settings

        self.dir = TMP / f"roster-status-{self.id().rsplit('.', 1)[-1]}"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.roster_path = self.dir / "accounts.txt"
        self.settings = Settings(db=str(self.db), account_list=str(self.roster_path),
                                 accounts_dir=str(self.dir))

    def test_no_file_is_not_an_error(self) -> None:
        from console.ops import roster_status

        out = roster_status(self.settings, conn=None)
        self.assertFalse(out["exists"])
        self.assertEqual(out["listed"], 0)
        self.assertTrue(out["unlisted"], "the UI has to be able to say 'nothing is listed yet'")

    def test_drift_both_ways(self) -> None:
        from console.ops import roster_status

        all_names = roster.fixture_identities(sqlite3.connect(self.db))
        roster.write_roster(self.roster_path, [*all_names[2:], "typo-account", "typo-account"])
        out = roster_status(self.settings, conn=None)
        self.assertEqual(out["listed"], len(all_names) - 2 + 1,
                         "23 real names plus the typo line, counted once despite the repeat")
        self.assertEqual(sorted(out["unlisted"]), sorted(all_names[:2]))
        self.assertEqual(out["unknown"], ["typo-account"])
        self.assertEqual(out["duplicates"], ["typo-account"])

    def test_counts_agree_when_the_file_matches_the_fixture(self) -> None:
        from console.ops import roster_status

        conn = sqlite3.connect(self.db)
        roster.write_roster(self.roster_path, roster.fixture_identities(conn))
        out = roster_status(self.settings, conn=conn)
        self.assertEqual((out["listed"], out["in_fixture"]), (out["listed"], out["listed"]))
        self.assertEqual(out["unlisted"], [])
        self.assertEqual(out["unknown"], [])
        conn.close()


if __name__ == "__main__":
    unittest.main()
