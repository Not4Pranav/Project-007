"""Per-worker account dump, so a load run leaves behind browsable accounts.

    python -m load.engine --base-url http://127.0.0.1:8000 --accounts-file auto
    python -m load.accounts --revoke var/reports/accounts-<stamp>.txt --db var/test.db

A ramped run is usually thrown away: percentiles in, nothing out. But each worker
holds a *real session* on the target — the mock API mints a `sessions` row on login,
and the fixture accounts are yours — so the useful artifact is the list of accounts the
workers became, with the bearer token that makes you that user in a browser. That is how
you eyeball what a run actually wrote (its feed, its posts, its verification state) instead
of trusting a latency table.

Deliberate limits, because this file holds credentials-adjacent data:

- tokens only, never passwords, not even the shared fixture one. `email + bearer` is a
  session you can revoke in one statement; `email:password:token` is a credential dump
  that gets committed by accident.
- nothing is written when the target is not local/reserved unless you pass
  `--allow-remote-tokens`, which prints the resolved path first. A run against a real
  production host would export *other people's* sessions.
- files land in `var/` (gitignored) and are chmod 0600.
- `--revoke` exists so the run can be undone as a unit; it is printed inside the artifact.
"""

from __future__ import annotations

import argparse
import os
import re
import sqlite3
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

# `identity<TAB>token`, but hand-edited files drift: a space after the tab, a CRLF,
# a trailing column. Match the first two fields and ignore the rest rather than
# silently dropping a line, which would leave a session alive after a "revoke all".
TOKEN_LINE = re.compile(r"^\s*(?P<ident>\S+)\s*\t\s*(?P<token>\S+)")

# A host you can safely leave a token file for. Anything else needs the explicit flag.
_BARE_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{20,}")

LOCAL_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]")
RESERVED_SUFFIXES = (".invalid", ".test", ".example", ".local")
STAGING_HINTS = ("staging", "dev.", "preview", "qa.", "internal")


def local_target(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    if not host:
        return False
    if host in LOCAL_HOSTS or host.endswith(RESERVED_SUFFIXES):
        return True
    return any(h in host for h in STAGING_HINTS)


@dataclass
class AccountRow:
    ident: str
    token: str
    source: str
    stage: str


def collect(stage_ledgers: list[tuple[str, list[dict]]], source: str) -> tuple[list[AccountRow], int, int]:
    """Fold the per-stage worker contexts into one row per live token.

    Returns (rows, workers_seen, workers_without_token). A worker that never
    authenticated is a finding, not a missing row, so it is counted separately
    rather than quietly dropped.
    """
    by_token: dict[str, AccountRow] = {}
    workers = 0
    tokenless = 0
    for stage, contexts in stage_ledgers:
        for ctx in contexts:
            workers += 1
            token = ctx.get("token")
            if not token or not isinstance(token, str):
                tokenless += 1
                continue
            # built-in scenarios record who they became as ctx["as"]; the spec path
            # records the ident the template drew, and the email it registered
            ident = str(ctx.get("last_ident") or ctx.get("as") or ctx.get("last_email")
                        or f"worker-{stage}")
            by_token[token] = AccountRow(ident=ident, token=token,
                                       source=str(ctx.get("token_source") or source), stage=stage)
    rows = sorted(by_token.values(), key=lambda r: r.ident.lower())
    # Counted, not derived from len(rows): `--token-file` with one line hands every
    # worker the same session, and deduped rows would call 9 of 10 "never authenticated".
    return rows, workers, tokenless


def render_txt(rows: list[AccountRow], *, base_url: str, revoke_cmd: str) -> str:
    header = (
        f"# {len(rows)} live session tokens for {base_url}\n"
        f"# format: identity<TAB>bearer-token   (no passwords are ever written here)\n"
        f"# revoke every token in this file: {revoke_cmd}\n"
    )
    return header + "".join(f"{r.ident}\t{r.token}\n" for r in rows)


def render_md(rows: list[AccountRow], *, base_url: str, fixture_hash: str, scenario: str,
              stages: str, seed: int, workers: int, without_token: int,
              revoke_cmd: str) -> str:
    now = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%SZ")
    out = [
        f"# worker accounts — `{scenario}` on `{base_url}`",
        "",
        f"Generated {now} by `load.engine`. **These are live session tokens.**",
        "",
        f"- fixture `{fixture_hash or 'unknown'}` · seed {seed} · stages `{stages}`",
        f"- workers: {workers} — {len(rows)} distinct tokens, "
        f"{without_token} never authenticated",
        f"- revoke them all: `{revoke_cmd}`",
        "",
        "| identity | token | obtained by | first seen |",
        "|---|---|---|---|",
    ]
    out += [f"| `{r.ident}` | `{r.token}` | {r.source} | {r.stage} |" for r in rows]
    out += [
        "",
        "## Be one of them in a browser",
        "",
        "```bash",
        f"curl -H 'Authorization: Bearer {rows[0].token if rows else 'ses_...'}' {base_url}/users/me",
        "```",
        "",
        "The token resolves the same way your app resolves any login, so pasting it into",
        "your devtools session store shows the account exactly as the run left it — feed,",
        "posts, verification state. Sessions honour `revoked = 0`, so the revoke command",
        "above really does lock every one of them out.",
    ]
    if without_token:
        out += [
            "",
            f"> {without_token} worker(s) ended without a token. If your spec's login op is",
            "> throttled or its `capture` never fires, every authed op is counted `skipped` —",
            "> which is why the run's per-op outcomes column matters more than its median.",
        ]
    return "\n".join(out) + "\n"


def revoke_sql(rows: list[AccountRow]) -> str:
    if not rows:
        return "-- nothing to revoke\n"
    quoted = ", ".join("'" + r.token.replace("'", "''") + "'" for r in rows)
    return (
        "-- One statement per run, so 'undo this' is not a grep-and-hope exercise.\n"
        "UPDATE sessions SET revoked = 1 WHERE token IN (\n"
        f"    {quoted}\n"
        ");\n"
    )


def write_artifacts(out_base: Path, rows: list[AccountRow], *, meta: dict) -> list[Path]:
    """`out_base` is a stem without extension: `var/reports/accounts-<stamp>`."""
    out_base.parent.mkdir(parents=True, exist_ok=True)
    revoke_cmd = f"python3 -m load.accounts --revoke {out_base}.txt --db {meta.get('db', 'var/test.db')}"
    paths: list[Path] = []
    txt = out_base.with_suffix(".txt")
    txt.write_text(render_txt(rows, base_url=meta["base_url"], revoke_cmd=revoke_cmd))
    paths.append(txt)
    md = out_base.with_suffix(".md")
    md.write_text(render_md(rows, base_url=meta["base_url"], fixture_hash=meta.get("fixture_hash", ""),
                           scenario=meta.get("scenario", ""), stages=meta.get("stages", ""),
                           seed=int(meta.get("seed", 0)), workers=int(meta.get("workers", 0)),
                           without_token=int(meta.get("without_token", 0)), revoke_cmd=revoke_cmd))
    paths.append(md)
    if meta.get("db"):
        sql = out_base.with_suffix(".revoke.sql")
        sql.write_text(revoke_sql(rows))
        paths.append(sql)
    for path in paths:
        os.chmod(path, 0o600)  # including revoke.sql: it inlines the token list
    return paths


def split_pair(line: str) -> tuple[str, str] | None:
    """One line of an account list to (identity, token), or None when it is not one.

    Three shapes are accepted, because the same file is read by a load run and by
    `--revoke`: `identity<TAB>token` (what `load.engine` writes), `identity:token` (what
    the console's accounts-info export writes, and the shape people already keep local
    credentials in), and a bare token. The right-hand side has to look like a token, which
    is what keeps a stray word — or a whole `user:pass` file — from becoming a revocation
    a stray word still cannot become a revocation target. A `user:pass` line therefore
    yields nothing: `--revoke` reports 0 live sessions rather than guessing.
    """
    text = line.strip()
    if not text or text.startswith("#"):
        return None
    if m := TOKEN_LINE.match(text):  # what load.engine writes: no shape gate on the token
        return m.group("ident"), m.group("token")
    if ":" in text:
        head, _, tail = text.rpartition(":")
        head, tail = head.strip(), tail.strip()
        if head and tail and _BARE_TOKEN.fullmatch(tail):
            return head, tail
        return None
    return ("", text) if _BARE_TOKEN.fullmatch(text) else None


def read_tokens(path: Path) -> list[str]:
    """Parses the emitted .txt (comments and blank lines ignored).

    A hand-written file may also carry one bare token per line. "Bare" is gated on
    shape (`[A-Za-z0-9_.:-]{20,}`) rather than "no tab present", otherwise a stray
    word in a note becomes a revocation target; the fixture's tokens are 25 chars.
    """
    tokens: list[str] = []
    for line in path.read_text().splitlines():
        pair = split_pair(line)
        if pair:
            tokens.append(pair[1])
    return tokens


def parse_file(path: str | Path) -> list[tuple[str, str]]:
    """The input direction: a dump (or hand-written list) becomes a pool of
    (identity, token) pairs the engine can hand to workers.

    Identities are kept so the account dump can label a row as pre-minted instead of
    captured, and so a `--token-file` run is still traceable to an account. `identity:token`
    is accepted alongside `identity<TAB>token`, which is what lets the console's own
    `user:token` export be fed straight back in.
    """
    pairs: list[tuple[str, str]] = []
    for line in Path(path).read_text().splitlines():
        pair = split_pair(line)
        if pair:
            pairs.append(pair)
    return pairs


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m load.accounts",
        description="revoke every session token listed in an accounts dump from load.engine")
    p.add_argument("--revoke", metavar="FILE", help="mark every token in this dump as revoked")
    p.add_argument("--db", default="var/test.db", help="database holding the `sessions` table")
    p.add_argument("--dry-run", action="store_true", help="count what would be revoked")
    p.add_argument("--delete", action="store_true",
                   help="also remove the dump (and its .md/.revoke.sql siblings) afterwards")
    a = p.parse_args(argv)
    if not a.revoke:
        p.error("--revoke FILE is required (this module's job is revoking dumps)")
    path = Path(a.revoke)
    if not path.exists():
        print(f"no such file: {path}", file=sys.stderr)
        return 2
    tokens = read_tokens(path)
    if not tokens:
        print(f"{path}: no tokens found (expected 'identity<TAB>token' lines)", file=sys.stderr)
        return 2
    db = Path(a.db)
    if not db.exists():
        print(f"no such database: {db}", file=sys.stderr)
        return 2
    conn = sqlite3.connect(db, timeout=10)
    try:
        marks = ", ".join("?" for _ in tokens)
        live = conn.execute(f"SELECT COUNT(*) FROM sessions WHERE revoked = 0 AND token IN ({marks})",
                            tokens).fetchone()[0]
        if a.dry_run:
            print(f"{len(tokens)} tokens listed, {live} currently live in {db}")
            return 0
        conn.execute(f"UPDATE sessions SET revoked = 1 WHERE token IN ({marks})", tokens)
        conn.commit()
        still = conn.execute(f"SELECT COUNT(*) FROM sessions WHERE revoked = 0 AND token IN ({marks})",
                             tokens).fetchone()[0]
        print(f"revoked {live} live session(s) from {path.name}; {still} left active")
        if a.delete:
            # revoking is enough only while the rows live. Seeded session tokens are
            # deterministic in --seed, so re-seeding the same fixture resurrects every
            # token in a stale dump; deleting the file is the part that cannot be undone
            # by an UPDATE.
            gone = [path, *path.parent.glob(path.stem + ".*")]
            for victim in sorted(set(gone)):
                victim.unlink(missing_ok=True)
            print(f"deleted {len(set(gone))} artifact(s) next to {path.name}")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
