# signup fixture lab

Bulk test accounts, realistic signup history, a signup-abuse detector you can
grade, and a load engine with an SLO gate — for **your own** app.

The starting point is the problem everyone hits at staging-review time: you need
ten thousand accounts, their session history, and a signup curve that looks like
traffic, because "one user, tested once" tells you nothing about your rate
limiter, your feed pagination, your nightly jobs, or your moderation queue.
Everything here is stdlib Python 3.11+, deterministic, and pointed at a database
you own.

```
make smoke     # 4k accounts, a scan, and a short load ramp, ~40s
make test      # 80 tests, no install step
make export    # var/out: csv+jsonl + import.postgres.sql for a 30k-account run
```

## Layout

| path | what it does |
|---|---|
| `seeds/` | the generator: profile shapes, signup curve, schema, writer, report |
| `abuse/detector.py` | scores accounts for automated-signup signals, grades itself against fixture labels |
| `mockapi/` | a throwaway register/login/feed app so the harness has an honest target |
| `load/` | concurrency-ramped load engine, scenario library (built-in or JSON `--spec`), SLO gate, reports |
| `seeds/export.py` | bulk CSV/JSONL artifacts + a generated Postgres loader, for staging and pytest |
| `load/accounts.py` | per-worker account dump (identity + bearer token) so a run leaves browsable accounts behind |
| `docs/recipes.md` | the wiring: Postgres import, pytest fixtures from JSONL, CI gate, spec-driven load |
| `tests/` | the suite (`unittest`, no pytest needed) |
| `var/` | generated databases and reports (gitignored) |

## What is *not* here

Bulk account creation on Discord or any other service you don't operate. That's
the shape of the two links this started from: signup automation aimed at a
third-party platform, defeating its CAPTCHA, email-verification and per-IP
limits, which is a ToS violation on that platform and the substrate for raiding,
scam servers and engagement fraud. Nothing in this repo ports that, and it is not
what the tooling below is for — every fixture here lands in a SQLite file you own.

That includes the adjacent shapes: no driving accounts into a server via an invite link
someone else controls, and no join-then-leave-on-a-timer scheduling (it exists to move a
crowd through a room before moderation lands). The `--accounts-file` dump below is the
inverse of a `login.txt` credential file — identity plus a revocable session on *your*
target, never a password, and refuses to write anything for a host that is not local or
reserved.

## 60-second tour

```bash
python3 -m seeds.seed --db var/test.db --users 30000 --days 180 --inject-bots 1200 --fresh
python3 -m seeds.report_cli --db var/test.db
python3 -m abuse.detector --db var/test.db --allow-domain loadtest.invalid --export var/reports/flagged.csv
python3 -m mockapi.server --db var/test.db --port 8000      # in another shell; --max-inflight 256
python3 -m load.engine --base-url http://127.0.0.1:8000 --fixture-db var/test.db \
  --stages 25,100,250 --slo "p95_ms=250,error_rate_pct=0.5,min_rps=200"
python3 -m seeds.report_cli --db var/test.db --entropy
```

Seeding 30,000 accounts (1.68M events, 90k sessions, hashed credentials) takes
about 42s on two cores:

```
timing: generate 12.5s  insert 29.8s  events 1,683,860  sessions 90,261
```

## Why the fixture bothers being realistic

Each of these is a thing that quietly breaks a test when the data is uniform:

- **Signups follow a curve, not a range.** Linear growth across the window ×
  weekday seasonality × a bimodal diurnal shape computed per-region, so 20:00 in
  São Paulo and 03:00 in Tokyo land where your traffic actually lands. Peak hour
  is where rate limiters, cron jobs and partition boundaries fail.
- **Bursts.** `--burst-count` injects Pareto-sized clusters spaced seconds apart
  (launch, HN, a campaign link). Uniform data never trips a burst bug.
- **Write volume is Pareto, not Poisson.** The top 5% of accounts hold ~50% of
  all writes, which is the skew that breaks `OFFSET` pagination and per-user
  caches. The report prints the number so you can see it.
- **Verification delay is minutes-to-days, lognormal.** Sub-10-second email
  verification is one of the strongest automation tells there is, so the fixture
  produces both: slow for humans, instant for the injected cohort.
- **Realistic identifiers.** Mixed username styles, plus-addressing, free
  providers *and* throwaway domains, IP sharing that models NAT and carrier
  egress (12% of users reuse a `/24`) — because "one signup per IP" is a
  false-positive machine on real traffic.
- **Statuses and edges.** 86% active, plus pending/suspended/deleted, sessions
  with `revoked`, and a referral graph with preferential fan-in.
- **Age floor is enforced** (`dob` derived so nobody is under 13), so your own
  age gate gets exercised rather than embarrassed by the fixture.
- **Password hashes are real.** PBKDF2-SHA256 with per-user salt and a per-user
  `iterations` value, so login paths verify for real. `--hash-algo sha256_fast`
  trades that for speed on 100k+ runs, and `credentials.algo` records which was
  used — the same shape you need to test a hash-algo migration.

Reproducibility is a hard feature: one seed drives every draw, and the run writes
a `fixture_hash` over the user table.

```
seed params   {"bursts": 12, "days": 180, "hash_algo": "pbkdf2_sha256", "inject_bots": 1200,
               "pbkdf2_iterations": 1200, "seed": 42, "shared_password": true, "users": 30000}
fixture hash  a6270147ec3fa1d8
```

## Seeding

`python3 -m seeds.seed` — the flags that matter:

| flag | meaning |
|---|---|
| `--users` / `--days` / `--end` | population size, history window, newest signup (default: this hour) |
| `--seed` | determinism |
| `--growth`, `--burst-count`, `--burst-share` | curve shape |
| `--inject-bots` | size of the labeled automated-signup cohort |
| `--events`, `--sessions`, `--no-activity` | activity tail volume |
| `--test-password` | one shared fixture password; empty = random per account |
| `--hash-algo`, `--pbkdf2-iterations` | hashing cost/semantics |
| `--fresh` | rebuild in place instead of refusing |

It refuses to run against a database that already has users unless you pass
`--fresh`, so a typo in `--db` costs you a rerun and not a table.

**Schema** (`seeds/schema.sql`): `users`, `credentials`, `sessions`, `events`,
`invite_edges`, `flags`, `meta`. Notable indexes: `users(signup_ts)`,
`events(user_id, ts)`, a **partial** `events(ts DESC, id DESC) WHERE kind IN
('post','message')` for the feed, and expression indexes on `lower(email)` /
`lower(username)` for case-insensitive login. `migrate()` also does additive
`ALTER TABLE` for columns that later versions add.

## The abuse scan

`python3 -m abuse.detector` reads signup metadata only — never `credentials`,
never a password, never a token — and writes per-account scores to `flags`.
Composite risk is a noisy-OR (`1 - Π(1 - w)`) so overlapping evidence saturates
instead of double-counting.

| rule | w | what it keys on |
|---|---|---|
| `bot_user_agent` | .45 | headless/automation/CLI tokens in the UA |
| `signup_velocity` | .40 | ≥N signups from one `/24` inside a sliding window |
| `disposable_email` | .30 | throwaway domain |
| `instant_email_verify` | .25 | verified within 10s of signup |
| `username_template_cluster` | .25 | digit-masked name shape shared in batch |
| `template_shared_subnet` | .20 | …and the cluster sits in few subnets |
| `referral_fan_in` | .20 | one inviter accumulating dozens of invitees |
| `no_phone_disposable` | .20 | throwaway domain + no phone |
| `low_entropy_local_part` | .15 | flat mailbox strings |
| `no_activity_24h` | .12 | active, zero writes in the first day |

Because the seeder *labels* the cohort it injects, the scan grades itself:

```
users scored        30,000
flagged >= 0.5 w/ >=1 rule(s)   1,247  (4.2% of population)   0.7s
  labeled positives    1,200   flagged 1,247
  tp 1,200   fp 47   missed 0
  precision 0.962   recall 1.000   f1 0.981   lift 24.1x over a 4.0% base rate
```

Tune it as a real queue would be tuned — `--threshold`, `--velocity-min`,
`--template-min`, `--batch-seconds-per-account`, `--min-rules 2` for
"corroborate before you act" — and watch precision/recall move on data whose truth
you know. The 47 false positives are legitimate campaign-burst accounts that share
a subnet and register minutes apart; that ambiguity is not a bug to fix here, it
is the reason real moderation keeps a human in the loop.

One shape worth knowing before you assert on the graph: `invited_by` never points
*forward by id*, but the injected cohort's edges can point at an inviter who signed
up *later* (`--inject-bots` writes the amplifier last, on purpose — that is what a
back-filled invite code looks like in a database). All of those rows are still
flagged. `docs/recipes.md` has the query and the number for the fixture as shipped.

`--allow-domain loadtest.invalid` keeps your own synthetic traffic out of the
scoring. This matters more than it looks: accounts created *through* the API by
the load engine come from one IP, with digit-walking names and instant
verification, so they trip every rule and quietly become 100% of your "false
positives". The export carries `user_id,score,rules` only — a test that asserts
no `@`, no `password`, no `token` appears in it.

## Load runs

The engine ramps concurrency stages (`--stages 25,100,250`, or `25:10,100:30` for
per-stage seconds), warms each stage up and excludes it, and reports mean/p50/p90/
p95/p99/max with an outcome mix per stage. Percentiles for the rollup are computed
from pooled samples, never by averaging stage percentiles.

- **closed-loop** (default) — every worker fires as fast as it can: finds the ceiling.
- **`--rps`** — paced arrival, open-loop: answers "can it hold production traffic".
- **`--ip-pool N`** — each worker gets a TEST-NET-3 address via `X-Forwarded-For`,
  so per-IP limits see many clients instead of one monster.
- **`--slo "p95_ms=250,error_rate_pct=0.5,min_rps=200"`** — exit code 4 on breach,
  which is the whole point: it is a CI gate, not just a console table.
- **`--token-file var/tokens.txt`** — workers start with a pre-minted session instead of
  logging in, so authed reads are measured past the login rate limiter. This is not a
  convenience: a spec run at 25 connections spent its time on 429'd logins and reported
  `me: skipped 330` instead of authed latency. A dump from a previous run is a valid pool.
- **`--accounts-file auto`** — writes each worker's identity and bearer token to
  `var/reports/accounts-<stamp>.{txt,md,revoke.sql}` (0600, gitignored dir) so you can open
  one in a browser and see what the run actually did. Tokens only: passwords are never
  written, and nothing is written for a non-local target unless you pass
  `--allow-remote-tokens`. `python3 -m load.accounts --revoke <file> --db <db>` kills every
  token in it as a unit — the mock API honours `sessions.revoked`, so a revoked session
  401s immediately.
- **https targets are verified by default**; `--insecure` exists for a self-signed staging
  box and prints a warning when used, because a load harness that silently stops checking
  certificates is how a test run ends up talking to the wrong host.
- Scenarios: `feed`, `login`, `register`/`signup`, `post`, and `mixed` with
  `--mix register=4,login=40,feed=45,post=11`. Outcomes are separated into
  `ok / throttled / conflict / auth_fail / client_error / server_error / transport`,
  because a 429 from your limiter and a 500 from your code are not the same event.
- Reports land in `var/reports/load-*.md` and `.json`, including what `GET /metrics`
  said server-side, so client-observed and server-observed can be compared.

The same traffic, throttled versus distributed:

```
A) every worker shares one IP                 B) --ip-pool 200
   stage  conc   rps     p95    429%            stage  conc   rps     p95   err%
   s1      25    557    48.2    38.95           s1      25    554    48.3    0.00
   s2     100   2170    51.5    54.20           s2     100   1570   108.3    0.00
   s3     250   1837   419.9    55.13           s3     250   1229   418.5    0.00
   slo: FAIL -> p95_ms: 419.9 > 250.0           slo: FAIL -> p95_ms: 418.5 > 250.0
```

A says "half your logins get throttled". B says "no — that was one IP; the real
cost at 250 connections is write contention, and throughput drops". You need both
to read your limiter correctly.

## Getting the accounts out of the fixture

`python3 -m seeds.export` turns the database into bulk artifacts, because the point of
a fixture this size is to be *loaded somewhere else*:

```bash
python3 -m seeds.export --db var/test.db --out var/out \
  --tables users,credentials,events,invite_edges --format csv,jsonl
```

- **CSV uses Postgres `\copy` conventions** — `\N` for NULL, `\x`-hex for blobs — and the
  directory gets an `import.postgres.sql` with the `\copy` lines, the DDL types to create
  first, and the `setval` bump that stops your app's next `INSERT` colliding with a
  fixture id. `--split` writes 50k-row chunks so a big import can run in parallel.
- **JSONL is for test harnesses**: one object per line, `json.loads` it, done. It is also
  the labels ride along, so a pytest parametrization can assert against your detector's
  verdict without a database handle: `users.is_synthetic_abuse` is always there, and
  `--tables flags` adds the detector's per-rule rows (`user_id, rule, score, detail`),
  which is one line per piece of evidence — the aggregate you want in an assertion is
  `max(score)` per user, and `--format jsonl` keeps the JSON `detail` intact per row.
- **No plaintext credentials, by construction.** `credentials.csv` carries
  `algo,salt,iterations,hash` exactly as stored — a fixture that ships a recoverable
  password is a fixture someone will copy into production.
- `export.json` is the manifest: row counts per table, the seed params, and
  `fixture_hash`, so an import can be tied to the seed that produced it.

## Driving a non-mock API

`load/scenarios.py` knows this repo's routes. A `--spec` file knows yours, so the ramped
stages, warmup exclusion, per-op percentiles, outcome accounting and SLO gate apply to
any HTTP API — no Python edit:

```bash
python3 -m load.engine --base-url https://staging.example.com \
  --spec docs/examples/mockapi.load.json --stages 25,100:15 --slo "p95_ms=250,error_rate_pct=0.5"
```

Ops are weighted (`weight: 0` = never picked), `capture` stores a response field into the
worker's state (`{"token": "access_token"}`), `{{token}}` interpolates it back into any
path/header/query/body, and `requires` counts an op as `skipped` when its dependency was
never captured — which is the difference between a run that measures authed reads and one
that measures how fast your API returns 401. Statuses outside `expect` (default
`[200, 201, 204]`) are counted as failures, so a 401 you expected has to be listed. The report's `outcomes` column prints the mix per op, so a single
broken op is attributable instead of being a percentage in a header.

## Pointing it at your app

The mock API is a shape, not a product. To exercise your real service:

1. Seed your staging DB with `seeds/` by replacing `insert_rows` with your ORM or a
   `COPY` — the profile/distribution code is storage-agnostic and returns dicts.
2. Point `--base-url` at staging and edit `load/scenarios.py`: each scenario gets a
   keep-alive `ApiClient` and a per-worker `ctx` dict, so swap `_op_login` for your
   auth path and `_op_feed` for your read path. Return `(kind, latency_ms, label)`.
3. `--password` / `--fixture-db` are how the login scenario gets identities. Against
   your app, prefer an allow-listed set of staging logins (or `GET
   /auth/sample-identifiers` if you expose the equivalent).
4. Keep `--register-domain` on a reserved TLD (`.invalid`/`.test`/`.example`). The
   engine rejects anything else, so a run can never mail a real mailbox.
5. Gate on it: `--slo "p95_ms=250,error_rate_pct=0.25" --slo-scope overall`; exit 4
   fails CI, and the `.md` artifact explains why.

## What the harness found in itself

Not a brag, a workflow demo — both were invisible without running it under load.

1. **`lower(email)` login scans.** The feed and login paths measured p50 ≈ 1.5s at
   100 connections because `WHERE lower(email) = ? OR lower(username) = ?` couldn't
   use the unique indexes. Two expression indexes later: **1558ms → 48ms p50,
   56 → 1191 rps** on the identical command.
2. **Admission slots leaked on aborted connections.** Releasing the in-flight
   semaphore from the handler's `finish()` looked correct, but a reset before the
   request line never reaches `finish()`; after a rough stage the process accepted
   TCP and went deaf. Release now happens in a `finally` inside the server, idle
   keep-alives expire at 30s, and each connection retires its SQLite handle.
   `test_aborted_connections_do_not_leak_admission_slots` covers it.
3. Also fixed while building: a 429 that returned before draining the request body
   left the JSON in the socket, so the next request on that keep-alive connection
   parsed as a request line and the client saw a `400` HTML page — plus a seeder
   that recorded `iterations: 1200` while hashing at 120,000, which made every
   fixture login 401.

## Limits, honestly

- The fixture API is a stdlib `ThreadingHTTPServer` on a shared GIL. It saturates
  around 1.5–2.2k rps for cheap reads on 2 cores and its tail degrades past ~100
  connections. Numbers describe *this* target; the harness and the fixture are what
  you take to your own service.
- SQLite is single-writer; heavy `register`/`post` mixes measure WAL lock queueing.
  `--max-inflight` (256) queues excess connections — keep it above your biggest stage.
- Thread-based generator: fine to ~2–3k rps, after that the harness is the
  bottleneck, not the target. Percentiles are exact for kept samples, capped at
  400k per stage (the run says when it truncates).
- Generated identities are *believable*, not real: names, inboxes and IPs are
  synthetic, and IPs come from reserved ranges.

## Safety rails in the code

No plaintext credential dump anywhere — one shared `--test-password` instead, which
is also how fixtures get consumed by tests. `--users` includes the labeled abuse
cohort so counts stay honest. The seeder refuses a non-empty target without
`--fresh`. `register` domains are validated against reserved TLDs. `credentials`
is never read by the detector. The mock API only speaks to a local fixture DB, and
`--inject-bots` only ever writes rows into the database you pass it.
