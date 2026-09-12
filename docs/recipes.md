# Recipes

End-to-end procedures for the parts of this fixture pipeline you are most likely
to wire into something real. Each block is a command sequence that was run against
this repository, not pseudocode.

---

## 1. Get the bulk artifacts into Postgres

The exporter writes Postgres `COPY` text conventions, so the load is a `\copy`
away — but the type mapping and the sequence bump are yours to handle.

```bash
python3 -m seeds.seed --db var/pg.db --users 100000 --seed 11 --fresh
python3 -m seeds.export --db var/pg.db --out var/pg-out --limit 100000
#  users 100,000 rows, credentials 100,000, events/invite_edges ...
```

`seeds/export.py` copies whatever is in the database; it does not re-derive rows. So the
pre-import sanity check is a query, not a flag — and the two that actually catch a
truncated or mis-shaped seed are a coverage check and a shape check:

```bash
python3 - <<'PY'
import sqlite3
c = sqlite3.connect("var/pg.db")
print("users:", c.execute("select count(*) from users").fetchone()[0])
# every user must have a credential row, or login fails for that row at runtime
print("missing creds:", c.execute(
    "select count(*) from users u left join credentials c on c.user_id = u.id where c.user_id is null"
).fetchone()[0])
# referral edges never point forward by id (that would be a cycle)
print("forward refs:", c.execute(
    "select count(*) from users u where u.invited_by is not null and u.invited_by >= u.id"
).fetchone()[0])
# ...but timestamps CAN be inverted, and that is deliberate: see the note below
print("back-dated invites:", c.execute(
    "select count(*) from users u join users i on i.id = u.invited_by where i.signup_ts > u.signup_ts"
).fetchone()[0])
SQL
python3 -m seeds.report_cli --db var/pg.db | tail -12     # what the fixture thinks it looks like
```

Create the tables first — the column types for this schema are in the header of
`var/pg-out/import.postgres.sql` (`citext` for identifiers, `inet` for IPs,
`timestamptz` for epochs, `bytea` for salts/hashes). Then:

```bash
psql "$PG_DSN" -f var/pg-out/import.postgres.sql
```

That file contains one `\copy` per table **plus** a `setval` per table with an `id`.

1. **Why `setval` matters.** The CSV carries explicit `id` values, so after loading
   100 000 rows the sequence is still at 1 and the application's next `INSERT`
   collides. `import.postgres.sql` bumps every sequence; if you hand-roll the
   `\copy`, do not skip it.
2. **NULL vs empty string.** Exported NULLs are the two-character token `\N`. If
   you drop `NULL '\N'` from the `\copy` options, every nullable column loads as the
   literal string `\N` — which in this fixture is visible as `invited_by = '\N'`
   instead of a real FK gap.
3. **Timestamps are epoch seconds**, not ISO strings, because that is what the
   fixture stores. Convert on the way in:

   ```sql
   -- instead of loading signup_ts as bigint:
   ALTER TABLE users ALTER COLUMN signup_ts TYPE timestamptz
     USING to_timestamp(signup_ts) AT TIME ZONE 'UTC';
   ```
4. **Blobs.** `credentials.salt` and `.hash` arrive as `\x`-prefixed hex, which
   `bytea` accepts natively under `COPY`. In the JSONL form the same values are bare
   lowercase hex, because embedding `\x` in a JSON string just invites escaping bugs.
5. **Verify, don't assume.** The manifest is the ground truth to diff against:

   ```bash
   psql "$PG_DSN" -Atc "select count(*) from users"
   python3 -c "import json; m=json.load(open('var/pg-out/export.json')); \
     print(m['tables']['users']['rows'], m['fixture_hash'])"
   ```

   Row counts must match exactly, and if you also imported `flags`, the abuse counts
   must match `flags` (`detector_rules` in the manifest is the per-rule story).
6. **Foreign keys.** Load order in the generated file is users → credentials →
   events → invite_edges, which satisfies the self-referencing `invited_by` FK. If
   you bulk-load into a table with live traffic, disable triggers for the load
   (`session_replication_role = replica`) rather than dropping constraints.

### Parquet, if Postgres is not the target

`seeds/export.py` deliberately has no Parquet writer — a stdlib-only repo cannot
write it. Convert after the fact, keeping the dtypes explicit so epoch seconds do not
become strings:

```python
import pandas as pd
df = pd.read_csv("var/pg-out/users.csv", na_values=["\\N"])
df["signup_ts"] = pd.to_datetime(df["signup_ts"], unit="s", utc=True)
df.to_parquet("var/pg-out/users.parquet")   # ~5x smaller than the CSV
```

---

## 2. Drive pytest fixtures from the export

The JSONL artifacts are line-delimited objects, so a session fixture can build a pool
without `sqlite3` in the test process at all.

```python
# tests/conftest.py in your app
import json
from pathlib import Path
import pytest

ARTIFACTS = Path("var/out")          # from: python3 -m seeds.export --out var/out

@pytest.fixture(scope="session")
def user_rows():
    with (ARTIFACTS / "users.jsonl").open() as fh:
        return [json.loads(line) for line in fh]

@pytest.fixture(scope="session")
def synthetic_bots(user_rows):
    """The injected cluster: the thing your detector is supposed to catch."""
    return [r for r in user_rows if r["is_synthetic_abuse"]]

@pytest.fixture
def login_creds(user_rows):
    row = user_rows[0]
    # the fixture's shared password, not the hash: credentials.csv can't tell you it
    return row["email"], "Fixture-Test-Pass-2026!"
```

Parametrize over the artifact so a failing case names the row that caused it:

```python
ROWS = [json.loads(line) for line in (ARTIFACTS / "users.jsonl").read_text().splitlines() if line.strip()]

@pytest.mark.parametrize("row", ROWS[:200], ids=lambda r: r["username"])
def test_profile_shape_is_stable(row):
    assert row["email"].endswith("@" + row["email_domain"])
    assert row["signup_ts"] > 0
    assert row["username"] == row["username"].lower()
```

Read that third number before you trust it. On `var/test.db` as shipped it is **120**, and
120 is not corruption: the injected cohort is created one account per second starting at
`hi - 900` (clamped to `hi - 1`, so with `--inject-bots 1200` the tail piles up in the
newest bucket) while the single "amplifier" that nominally invited every third
of them is the last organic row, so ~120 invite edges point at an account that did not exist
yet. That is what a real farm looks like in a database — the invite code is attached after
the fact — so do not "fix" it and do not write a fixture test that assumes `invited_by` is
chronologically consistent. The invariant that *does* hold is `invited_by < id` (a DAG, no
forward references), and it is the one worth asserting.

Those 120 rows are already flagged (`abuse.detector` catches them through `invite_chain_fanout`,
0 false negatives on that subset in this fixture), so the back-dating is spare evidence — but if
you want a sharper signal it is a single query, not a new model: count users whose inviter
signed up after them, grouped by inviter.

Two properties a fixed `--seed` buys you, and they are worth asserting in your own tests:
usernames stay unique and lowercase, and the invite graph never references forward.
`tests/test_seed.py`
is the executable version of that claim (it re-derives the same seed twice and compares the
digest, and calls `seeds.profile.verify_password` against stored hashes); the export can
only carry those properties along, not break them.

There is no plaintext credential to export: the seeder hashes `--test-password` (default
`Fixture-Test-Pass-2026!`, empty means random per user) and `credentials.csv` carries
`algo/salt/iterations/hash` — which is what your target app needs in order to accept that
password. To see the derivation yourself:

```bash
python3 -c 'import sqlite3, sys; sys.path.insert(0, ".")
from seeds.profile import verify_password
row = sqlite3.connect("var/pg.db").execute(
    "select algo, salt, iterations, hash from credentials limit 1").fetchone()
print(verify_password(row[0], "Fixture-Test-Pass-2026!", row[1], row[3], row[2]))'
```

---

## 3. Load a non-mock API from a JSON spec

`python3 -m load.engine --spec your.load.json` exists because the built-in scenarios
know this repository's routes. Point a spec at your staging app and the same
closed-loop driver, latency recorder, SLO gate, and per-op breakdown apply.

```jsonc
{
  "name": "staging",
  "headers": {"x-api-key": "loadtest"},
  "ops": [
    {"name": "login", "weight": 50, "method": "POST", "path": "/auth/login",
     "json": {"identifier": "{{ident}}", "password": "{{password}}"},
     "expect": [200, 401, 429], "capture": {"token": "access_token"}},
    {"name": "whoami", "weight": 50, "method": "GET", "path": "/me",
     "requires": ["token"], "headers": {"Authorization": "Bearer {{token}}"},
     "think_ms": 250, "expect": [200, 401]}
  ]
}
```

```bash
python3 -m load.engine --base-url https://staging.example.com --spec staging.load.json \
  --fixture-db var/test.db --stages 25,50:60 --max-inflight 100 --slo p95_ms=400,error_rate_pct=0.5
```

Reading the output — the `outcomes` column is what makes a bad run diagnosable:

```
| s2 | whoami | 1,503 | 41.2 | 47.9 | 52.1 | 88.4 | ok 1,470, auth_fail 33 |
```

Three rungs of strictness, and why each earns its keep:

| rung | how | catches |
|---|---|---|
| report | `python3 -m load.engine ...` | a human reads the table; good for a first soak |
| gate | `--slo p95_ms=400,error_rate_pct=0.5` → exit 4 | CI fails on a real regression, not on `curl` flakiness |
| spec | `--spec` with `expect` lists + `requires` | a 200-shaped failure: an endpoint that answers `200` with `{"errors":[...]}`, or an authed op silently running unauthenticated |

Both files in `docs/examples/` are covered by a test that loads them and refuses any op
which reads a captured variable without `requires`, so the copy-paste path stays runnable.

`requires` exists for that second case: an op whose token was never captured is counted as
`skipped` instead of firing a 401 that you then spend time explaining. If the spec can't
resolve a `{{var}}` at all, the run ends with `spec_error` (exit 3) rather than sending an
empty header — that exact bug once turned every paged request into a 400 by rendering
`None` as the string `"None"`.

### Mirror abuse on your real signup endpoint

The detector rules (`abuse/rules.py`) were written against this fixture's columns. On a
real endpoint, log these per signup and the rules keep working unchanged:

| to capture | rule it feeds |
|---|---|
| client IP (so the /24 bucket is derivable) | `shared_subnet_burst` |
| User-Agent string | `user_agent_reuse` |
| username + email local part | `templated_name`, `numeric_suffix_username` |
| signup_ts and verify_ts as separate columns | `instant_email_verify` (sub-30s) |
| referrer / invite code | `sequential_usernames` context, `invite_chain_fanout` |
| per-IP request counters for `POST /auth/register` | `registration_burst` |

Then re-use the harness instead of rewriting it: seed your staging DB with
`python3 -m inject_bots --db ... --bots N --seed 42`, sign up that cluster through the real
endpoint, export with `seeds/export.py`, and run `python3 -m abuse.detector --db ...` —
`--bots N` is the number your detection-rate assertion should use (the fixture reports
precision/recall and per-rule hit counts).

---

## 4. CI wiring

```yaml
- run: python3 -m seeds.seed --db var/ci.db --users 2000 --seed 7 --fresh
- run: python3 -m seeds.export --db var/ci.db --out var/ci-out --tables users,credentials
- run: python3 -m abuse.detector --db var/ci.db
- run: python3 -m load.engine --base-url http://127.0.0.1:8000 \
      --fixture-db var/ci.db --stages 25:30 --slo p99=400,err=0.5
- run: python3 -c "import json,glob; s=json.load(open(sorted(glob.glob('var/reports/load-*.json'))[-1]))['stages']; assert all(x['client_error_pct']==0.0 for x in s), s"
```

Notes from hard experience, all of which the harness already encodes:

- **The valid SLO keys are exactly `p50_ms`, `p90_ms`, `p95_ms`, `p99_ms`, `p999_ms`,
  `max_ms`, `error_rate_pct`, `throttle_pct`, `min_rps`** (`parse_slo` accepts `k=v` for any
  `k`, and `check_slo` only reads those). A typo like `err=0.5` is therefore *silently
  dropped* — the run prints `slo ... PASS` for a gate that never evaluated. Prefer
  `--slo-scope overall` on a long run so a single fast stage cannot carry a bad one.
- **Never `|| true` the load step.** A load test that cannot fail is a latency sample with
  extra steps. Use `--slo`, which exits non-zero *and* prints which threshold broke.
- **Warm up first.** `--warmup-seconds` (default 2, per stage) is excluded from the
  percentiles; without it the first second of every stage is a fresh-connection and
  cold-JIT tax that reads like a regression.
- **Rate-limit deliberately.** `--login-rate-limit-per-min 0` is set in `make load`
  because login is shared, bursty, and otherwise starts 429-ing while p99 still looks
  great — you learn nothing about your system, only about its limiter. Set the limiter
  on purpose, then read the `429%` column: it is printed separately from `err%` for
  that reason.
- **Pin the client to one connection per thread** (the harness reuses a thread-local
  keep-alive). Otherwise `--max-inflight` is fiction: the real concurrency becomes
  connections/threads, and closing each request adds 3–10 ms that lands in your p99
  as if it were server work.
- **`--ip-pool N`** rotates the mock's `X-Forwarded-For` so the server-side rate limiter
  is not the bottleneck when the point of the run is DB read scaling.
- **`fixture_hash`** in `export.json` is the seed's identity; log it next to the load
  numbers. Two runs on different fixture hashes are not comparable, which is the usual
  reason a "regression" cannot be reproduced.

---

## 5. Browse as one of the accounts the run used

A load run normally leaves percentiles and nothing else. `--accounts-file` also
leaves the *identities*: one row per worker, with the bearer token that worker was
using when the stage ended.

```bash
python3 -m load.engine --base-url http://127.0.0.1:8000 --fixture-db var/test.db \
  --stages 25:15 --scenario mixed --accounts-file auto
# accounts    var/reports/accounts-20260911-051253.txt
# accounts    var/reports/accounts-20260911-051253.md
# accounts    var/reports/accounts-20260911-051253.revoke.sql
```

```
alina59@aol.com         ses_srPCEdLCbuHkDqjq-S2NNELu      # identity<TAB>token, 0600
```

Then be that user, without logging in again:

```bash
curl -H "Authorization: Bearer ses_srPCEdLCbuHkDqjq-S2NNELu" \
  http://127.0.0.1:8000/users/me
# {"id": 6589, "username": "enzo.rossi37", "event_count": 24, "verified_ts": ...}
```

Or paste the token into your app's session store and click through the UI — this is the
fastest way to see what a benchmark *wrote*, which no latency table will tell you.

Three properties of the artifact, all deliberate:

- **Tokens, never passwords.** `email + bearer` is a session you can revoke in one
  statement; `email:password:token` is a credential file, and it is the shape that ends up
  committed. The `.md` names the fixture password only as prose pointing at `--test-password`.
- **Scoped to what the run touched.** Rows come from the worker ledger (the per-worker
  `ctx` the engine already owns), so a 250-connection run yields ~250 rows, not 30k.
  `--accounts-file PATH` overrides the location; anything outside `var/` needs
  `--allow-remote-tokens` as well as your own judgement, and a non-local host needs that
  flag regardless — a dump of a production host's sessions is not a test artifact.
- **Revocable as a unit.** `revoke.sql` sits next to it, and the CLI does the same thing
  with a count:

  ```bash
  python3 -m load.accounts --revoke var/reports/accounts-*.txt --db var/test.db --dry-run
  # 5 tokens listed, 5 currently live in var/test.db
  python3 -m load.accounts --revoke var/reports/accounts-20260911-051253.txt --db var/test.db
  # revoked 5 live session(s) from accounts-20260911-051253.txt; 0 left active
  ```

  Verified against the mock API: the same token returns 200 before and 401 after.

  Add `--delete` to remove the dump and its `.md`/`.revoke.sql` siblings with it, and prefer
  that over leaving them in `var/`: revocation is only durable while the `sessions` rows
  are, and seeded tokens are deterministic in `--seed` — re-seed the fixture and every token
  in a stale dump is minted again, live, with the same string. Deleting the file is the part
  an `UPDATE` cannot undo.

If the `.md` says `N never authenticated`, that is a finding about the run, not the writer:
login was throttled, or a spec's `capture` never matched, so every authed op was counted
`skipped`. Fix that before reading the percentiles.

Reusing the dump as input (skip the login limiter entirely on the next run):

```bash
python3 -m load.engine --base-url http://127.0.0.1:8000 --token-file \
  var/reports/accounts-20260911-051253.txt --stages 25:15
```

`--token-file` hands each worker a pre-minted bearer in rotation, so authed reads are
measured without the login path's rate limiter in the way — the thing that made an earlier
run report `me: skipped 330` instead of usable authed latency.

## 6. Scaling and limits

Verified shapes for the modules added here (`--users 100000` into SQLite, 2 CPU cores):

| step | measured here |
|---|---|
| `seeds.seed --users 100000 --days 180` | 110 s, 679 MB database |
| `seeds.export` (4 tables, csv + jsonl) | 317 012 rows in 4.0 s, 136 MB of artifacts |
| `seeds.export` (2 tables, csv) | 200 000 rows in 1.5 s |
| `load.engine --stages 25:6` | 3 356 ops at 555 ops/s on 2 cores (client-bound, not server-bound) |

The export is ~80 000 rows/s *per format* because it streams with `fetchmany(5000)` and
never materializes a table; if you are choosing formats in CI, note that csv and jsonl are
written in the same pass, so asking for both costs roughly one extra write, not a second scan.

Three honest caveats:

- **`--limit` counts rows per table.** Useful for shard-sized artifacts; do not read it
  as a global sample. `--where` is applied verbatim to *every* selected table, which is
  why an unrelated table is skipped rather than silently mis-filtered.
- **The exporter writes the `users` column set this repo generates.** Your schema gets
  `ValueError: table X not exported by this fixture` — extend `TABLES` in
  `seeds/export.py` and the DDL hints in the same commit, or the generated loader lies.
- **The spec renderer is string-only.** `{{count}}` becomes `"5"`, so an endpoint that
  requires a JSON *number* in a field must be sent with a fixed literal in the spec
  (`{"limit": 5}`); template values in a numeric position will be quoted.
