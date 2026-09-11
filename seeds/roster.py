"""The account roster: one identity per line, and you own the file.

This is the list the console's Operational tab works from, and the one you can edit in any
text editor. It deliberately carries *identities only* — `username` or `email`, nothing else.
Secrets live in the fixture database (passwords are hashed, sessions are rows), and the two
derived files this module can write (`user:pass`, `user:token`) are exports with a 0600 mode
and a printed warning, because a plaintext credential file is the one artifact that outlives
every intention behind it.

Deleting an account here and running Sync removes the fixture's rows for it — through the
database's own foreign keys, so credentials, sessions, events, invite edges, flags and
memberships go with it. Nothing is deleted that the file did not ask to lose.
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path

COMMENT_LINES = (
    "# Signup fixture roster — one username or email per line. Blank lines and",
    "# anything starting with # are ignored.",
    "#",
    "# This file decides which fixture accounts the console may use. Remove a line and run",
    "# Settings > Sync account list to delete that account from the database, or click",
    "# Rewrite from fixture to make the file match the database again.",
    "# No passwords and no tokens are stored here, on purpose.",
)

# (table, user column). Everything that hangs off a user id, so a removal is one thing:
# no rows left that point at an account nobody can name any more.
CHILD_TABLES: tuple[tuple[str, str], ...] = (
    ("credentials", "user_id"), ("sessions", "user_id"), ("events", "user_id"),
    ("flags", "user_id"), ("memberships", "user_id"), ("invite_edges", "invitee"),
    ("invite_edges", "inviter"),
)

USERPASS_NOTE = (
    "# user:pass export — plaintext credentials for a LOCAL fixture only.",
    "# Delete this file when you are done; it is 0600 because it holds passwords.",
)
TOKEN_NOTE = (
    "# user:token export — session tokens for the local mock API only.",
    "# Revoke with: python3 -m load.accounts --revoke <this file> --db <fixture.db>",
)


@dataclass
class Roster:
    identities: list[str]
    unknown: list[str]  # in the file, not in the fixture
    duplicates: list[str]

    @property
    def count(self) -> int:
        return len(self.identities)


def read_roster(path: str | Path) -> Roster:
    """Identities from the file, in order, deduped. Raises OSError if it is missing."""
    seen: set[str] = set()
    dupes: list[str] = []
    out: list[str] = []
    for raw in Path(path).read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        ident = line.split("\t", 1)[0].split(":", 1)[0].strip()  # tolerate a pasted user:pass file
        if not ident:
            continue
        key = ident.lower()
        if key in seen:
            dupes.append(ident)
            continue
        seen.add(key)
        out.append(ident)
    return Roster(identities=out, unknown=[], duplicates=dupes)


def write_roster(path: str | Path, identities: list[str]) -> int:
    tmp = Path(str(path) + ".tmp")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text("\n".join([*COMMENT_LINES, "", *identities]) + "\n")
    os.replace(tmp, path)
    return len(identities)


def fixture_identities(conn: sqlite3.Connection) -> list[str]:
    """Every fixture account, by id: usernames, because they are shorter and unique.

    Deliberately not `WHERE status='active'`. The list is what Sync deletes from, so an
    account this function leaves out is an account a Sync quietly removes — and the fixture
    seeds pending/banned cohorts on purpose. Inactive accounts stay in the list and are
    refused where they matter: a join logs each name in, and a login the fixture refuses is
    reported as skipped rather than being treated as deleted.
    """
    return [r[0] for r in conn.execute("SELECT username FROM users ORDER BY id")]


def resolve(conn: sqlite3.Connection, identities: list[str]) -> dict[str, int]:
    """identity -> user id, matching on username OR email (case-insensitive usernames)."""
    wanted = {i.lower() for i in identities if i}
    found: dict[str, int] = {}
    for username, email, uid in conn.execute("SELECT username, email, id FROM users"):
        for candidate in (username, email):
            if candidate and candidate.lower() in wanted:
                found[candidate] = int(uid)
                break
    return found


def sync(conn: sqlite3.Connection, identities: list[str], *, apply: bool = True) -> dict:
    """Make the fixture match the file: accounts not listed are removed.

    `apply=False` is a dry run, which is what the UI shows before it lets you click the
    destructive version — "remove 400 accounts" should never be a mis-click.
    """
    keep = set(resolve(conn, identities).values())
    all_ids = {int(r[0]) for r in conn.execute("SELECT id FROM users")}
    doomed = sorted(all_ids - keep)
    known = {r[0].lower() for r in conn.execute("SELECT username FROM users")} | {
        r[0].lower() for r in conn.execute("SELECT email FROM users")}
    unknown = [i for i in identities if i.lower() not in known]

    out = {
        "would_delete": len(doomed),
        "kept": len(keep),
        "file": len(identities),
        "unknown": unknown[:20],
        "applied": False,
        "servers_reassigned": 0,
        "servers_deleted": 0,
    }
    if not apply or not doomed:
        return out
    if not keep:
        # the file recognised nothing, so "delete what is not listed" means everything.
        # An emptied or typo'd path must not be able to wipe the fixture through a preview
        # the operator trusted; rebuilding is what --fresh is for.
        raise RuntimeError(f"the list matches no account in this fixture: refusing to delete all "
                           f"{len(all_ids)} of them ({len(identities)} line(s) read, none of them "
                           f"recognised). Put one real username in it, or rebuild with --fresh")

    placeholders = ",".join("?" * len(doomed))
    ids = tuple(doomed)
    survivors = [i for i in all_ids if i not in set(doomed)]
    if survivors:
        # `servers.owner_id` references users with ON DELETE CASCADE: deleting an owner
        # would silently take the whole server row with it. Move the room first.
        new_owner = min(survivors)
        cur = conn.execute(f"UPDATE servers SET owner_id=? WHERE owner_id IN ({placeholders})",
                           (new_owner, *ids))
        out["servers_reassigned"] = cur.rowcount or 0
    else:
        out["servers_deleted"] = conn.execute("DELETE FROM servers").rowcount or 0
    # Children are deleted by name, not left to the foreign keys: `PRAGMA foreign_keys`
    # is per-connection and off by default, so a caller that connected without it would
    # leave orphaned credentials and live session tokens behind a "deleted" account.
    counts: dict[str, int] = {}
    for table, column in CHILD_TABLES:
        cur = conn.execute(f"DELETE FROM {table} WHERE {column} IN ({placeholders})", ids)
        counts[table] = cur.rowcount or 0
    if counts:
        out["children"] = counts
    conn.execute(f"DELETE FROM users WHERE id IN ({placeholders})", ids)
    out["applied"] = True
    out["deleted"] = len(doomed)
    return out


def rows_for_export(conn: sqlite3.Connection, identities: list[str] | None, *, password: str,
                    limit: int = 0) -> list[tuple[str, str, str]]:
    """(username, password-or-token, live-session?) triples for one roster slice.

    Tokens come from live sessions only (`revoked=0`), newest first: a token you cannot
    paste into a browser session you already revoked is noise, not a leak.
    """
    sql = ("SELECT u.username, u.email, u.id,"
           "       (SELECT s.token FROM sessions s WHERE s.user_id=u.id AND s.revoked=0"
           "         ORDER BY s.last_seen_ts DESC LIMIT 1) AS token"
           "  FROM users u WHERE u.status='active'")
    args: tuple = ()
    if identities:
        idents = list(identities)
        marks = ",".join("?" * len(idents))
        # parenthesised: without it the OR escapes the status filter and inactive rows leak in
        sql += f" AND (u.username IN ({marks}) OR u.email IN ({marks}))"
        args = tuple(idents) * 2
    sql += " ORDER BY u.id"
    if limit:
        sql += " LIMIT ?"
        args = args + (limit,)
    out: list[tuple[str, str, str]] = []
    for username, _email, _uid, token in conn.execute(sql, args):
        out.append((username, password, token or ""))
    return out


def write_export(path: str | Path, kind: str, rows: list[tuple[str, str, str]]) -> dict:
    """`userpass` -> username:password, `token` -> username:token (skipping any without a live one)."""
    if kind not in ("userpass", "token"):
        raise ValueError(f"unknown export kind {kind!r}; expected 'userpass' or 'token'")
    note = USERPASS_NOTE if kind == "userpass" else TOKEN_NOTE
    lines, missing = [], 0
    for username, password, token in rows:
        secret = password if kind == "userpass" else token
        if not secret:
            missing += 1
            continue
        lines.append(f"{username}:{secret}")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join([*note, "", *lines]) + ("\n" if lines else "\n"))
    os.chmod(path, 0o600)
    return {"path": str(path), "written": len(lines), "skipped_no_session": missing, "kind": kind}


def mask(line: str) -> str:
    """For previewing an export in the browser without serving secrets by default."""
    head, sep, tail = line.partition(":")
    if not sep or line.startswith("#"):
        return line
    return f"{head}:{tail[:2]}…({len(tail)} chars hidden)"
