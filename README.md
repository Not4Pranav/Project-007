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
make test      # 200 tests, no install step
make console   # the same pipeline behind three tabs: Generator / Operational / Settings
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
| `console/` | the three-tab control plane over those modules: Generator Mode, Operational Mode, Settings |
| `seeds/roster.py` | the account list the operator edits: read, rewrite, sync (delete what is not listed), exports |
| `run.bat` | Windows entry point: checks the interpreter, starts the console with `--bootstrap --open-browser` |
| `build_exe.bat` | optional: builds `dist\SignupFixtureLab.exe` on Windows with PyInstaller |
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
crowd through a room before moderation lands). Option B below does take a *link* in its room
box, because a link is how people write down which room they mean — but it is parsed as a way
of naming a row of your own `servers` table, a host that is not the fixture's loopback API is
refused before any lookup happens, and the request it makes is always the fixed local one. The
`--accounts-file` dump below is the
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
python3 -m console            # or drive all of the above from a browser tab instead
```

Seeding 30,000 accounts (1.68M events, 90k sessions, hashed credentials) takes
about 42s on two cores:

```
timing: generate 12.5s  insert 29.8s  events 1,683,860  sessions 90,261
```

### On Windows, by double-click

`run.bat` sits in the repo folder. It finds `py -3` / `python` on `PATH`, refuses if the
interpreter is older than 3.11, then runs:

```
python -m console --bootstrap --open-browser
```

which opens `http://127.0.0.1:8010/`. Anything you type after the script is passed through,
so `run.bat --port 8090` works. If the `python` on PATH is the Microsoft Store stub rather than
a real interpreter, the script says so instead of failing quietly.

`--bootstrap` is the first-run setup: with no fixture database yet it generates
`bootstrap_accounts` accounts (5 — the *list* size, deliberately not the Generator tab's
`users`, which defaults to 4,000 because load tests want that), and writes those names to
`var\accounts.txt` so the tabs open with something readable instead of an empty form. More
accounts come from Generator Mode, which appends: the new ones are saved alongside the five,
with ids that continue, and the list grows by exactly the new accounts. `--bootstrap` never
touches an existing database — it is a no-op once `var\test.db` exists.

`build_exe.bat` is the optional next step: it runs PyInstaller and produces
`dist\SignupFixtureLab.exe`, one file you can copy wherever you work. It has to be run on
Windows — PyInstaller is not a cross-compiler, so a binary built on Linux or macOS will not
execute here. The `.exe` sets the same defaults `run.bat` passes (it has no place to type
flags) and works from its own folder — it `chdir`s to where the `.exe` sits, so a Start-menu
shortcut cannot seed an empty `var\` somewhere else and make your accounts look missing. Keep
it somewhere writable (not Program Files).

Neither one installs anything, needs admin rights, or opens a port beyond `127.0.0.1`.

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
| `--fresh` | wipe the rows (schema stays) and rebuild from this seed |
| `--append` | add a *new* cohort after the highest existing id, leaving every earlier row alone |

It refuses to run against a database that already has users unless you pick one of those two,
so a typo in `--db` costs you a rerun and not a table. Passing both is refused too: they
contradict each other.

`--append` is what the console's Generator Mode uses by default (Settings > `write mode`), and
it is the difference between "grow the fixture" and "lose the accounts you have been editing":
the second batch continues the id sequence, gets signup stamps in the last 24 hours rather than
spread across the window, and leaves `servers`, `sessions` and every hand-written row from the
first pass in place. Re-appending does not invent a second set of rooms. `meta.seed_params`
describes the whole fixture afterwards (`users` = total, `last_batch` = this run,
`appended: true`), which is what the report and the fixture hash read.

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

## The console

`python3 -m console` (or `make console`) serves one page on `http://127.0.0.1:8010/`
with three tabs. It is not a second engine: every button runs the same module the CLI
runs, and the Generate tab prints that command before running it — the preview and the
job are built by the same function, so the preview cannot lie about what will happen.
The page is 22,628 bytes of inline HTML/CSS/JS (22,597 characters) with no build step
and no asset server.

| tab | what it is for |
|---|---|
| **Generator Mode** | build or rebuild the fixture — users, credentials, activity, sessions, servers — i.e. the accounts Operational Mode then spends |
| **Operational Mode** | two options: **get accounts info** (`user:pass` or `user:token` for the accounts in your list) and **join servers** (N accounts from that list into a room of your fixture), plus the load run and the mock API's start/stop |
| **Settings** | every knob the other two tabs read, the account list (edit, sync, rewrite, seed), validated on save into `var/console.json` (mode 0600) |

Jobs run one at a time, deliberately: SQLite has one writer and `--fresh` truncates, so
a second generator job would corrupt the fixture rather than race with the first. The tab
queues your click and streams the log tail. Measured: 300 accounts (878 sessions, 18,883
events, 6 servers, `sha256_fast`) in 0.3 s, then a 25-account join in 2.3 s at the API's
default 40 ms simulated latency.

### Operational Mode's two options

The tab is two numbered options, because that is the order people actually want them in:
first you get the accounts out, then you spend them.

**Option A — accounts info.** Writes one file out of the account list in two possible
formats: `username:password` (the fixture's own shared password, from Settings) or
`username:token` (a live session row of the mock API above). You choose the format, whether
the selection is the whole fixture or just the accounts your list names, and a maximum line
count; the buttons are *Write the file*, *Show it (masked)* and *Revoke those tokens*. Both files land
next to the list at 0600 (`var/accounts-userpass.txt`, `var/accounts-tokens.txt`) and both are
local-only:

```
liam.voss24:Fixture-Test-Pass-2026!        vdelgado2061:ses_90c801f97b7684319e1b429ad56
```

The token half is the important limitation: it is a session on **this** fixture's API, minted
from sessions with `revoked=0`, newest first. It is not a token for any platform you do not
run, and a `user:token` file you point at someone else's API is simply not understood by it.
*Show it* renders the file masked (`lara.cruz8:se…(32 chars hidden)`) with a `?reveal=1`
opt-in, and *Revoke those tokens* runs `load.accounts --revoke <file> --delete`, which kills
those sessions and removes the plaintext — measured `revoked 4 live session(s) from
accounts-tokens.txt; 0 left active`. A `user:pass` file has no sessions to revoke, so the
same button only removes it, and says so: `removed accounts-userpass.txt (no sessions to
revoke: it held passwords)`.

Below that table sit the dumps a load run left behind (`identity<TAB>token` per worker). They
are the same kind of object and behave the same way. The two exports above are deliberately
*not* in that list, and `/api/dump` and `/api/revoke` refuse them by name — the dumps table is
a list of files whose tokens can be spent and revoked, so a password file must not be
selectable there even though `accounts-userpass.txt` passes the filename rule.

**Option B — server join.** Name the room in the box — `7`, `wild-lantern`, `Wild Lantern`,
`/servers/wild-lantern`, or the whole link your own app prints,
`http://127.0.0.1:8000/servers/wild-lantern` — and it is resolved as a row of your fixture's
`servers` table. Every shape lands on the same room, and the report says which route it took
(`matched_by: link->slug`). The dropdown beside the box lists the rooms the fixture actually
has (id, name, live member count, capacity, private flag, and its slug for the public ones) and
is the fallback when the box is empty. A link to anywhere else is refused before the lookup:

```
that link points at discord.com — this console only joins rooms of its own fixture, reached at
http://127.0.0.1:8052; a room somebody else operates is not something this tool drives, at any
port and in any form
```

That is the whole boundary, and it is a lookup rather than a promise: there is no way for the
box to reach a room that this database does not describe. Two names tied on one text (a slug
of one room that is another room's name, say) resolve to the slug owner; two rooms tied on a
name refuse and list their ids, because guessing which room to fill is not a thing a bulk join
should do quietly.

Pick where the accounts come from (the account list, a token dump from a previous run, or the
newest fixture logins), how many, and the pacing; then *Join server* sends each account through
the mock API's own `POST /servers/<id>/join`, one at a time. The result is the API's answer per
account, not a hope:

```
{"server_id": 1, "accounts": 3, "counts": {"joined": 3}, "p50_ms": 43.99, "max_ms": 45.08,
 "joined_user_ids": [3, 4, 5]}
```

Those are your app's rules, applied by your app: a repeat 3-account join into the same room
returns `{"already-member": 3}` and adds no rows; a `private` row returns `{"refused": 3}`
(the gate in this fixture is the row's own `slug`, `GET /servers` blanks that column on
private rows so a listing cannot hand out the code, and there is no field anywhere that takes
an invite code from outside); a `capacity=1` row given three accounts returns
`{"joined": 1, "refused": 2}` and leaves exactly one live membership. Set
`private=1` on a row and join it without a code: `{"refused": 2}`, `joined_user_ids: []`, zero
rows written, and the log names the gate — `this fixture gates a private room on the row's own
slug`. Paste that row's `slug` into the invite box and the same join reports
`{"joined": 2}, "invited": true`; paste a wrong code and it refuses again. The console will not
fill the box for you, and the room listing hides a private row's slug: the gate is your app's,
so it stays observable instead of being routed around.
`join_rate_limit_per_min` to 1 in Settings, restart the API so it re-reads config, and a
6-account join reports `{"already-member": 1, "throttled": 5}` — throttling shows up as a
count instead of quietly becoming a success.

When the accounts come from the list, a name the fixture does not recognise is dropped before
anything is sent and reported, and an account that cannot log in (pending verification, or
banned) is skipped rather than half-joined. That is why the list carries inactive accounts:
see the account list below.

Undo is a button, not a scheduler. The join job returns the `user_id`s it created rows for,
and *Leave* replays `POST /servers/<id>/leave` over exactly those ids (measured:
`{"server_id": 1, "left": 3, "skipped": 0}`). `left_ts` is set and the row stays — a fixture
whose joins vanish cannot be audited — and re-joining reopens the same row (`{"rejoined": 2}`)
instead of appending one. The button walks back to the newest join that actually created
memberships, so joining, retrying the same accounts (all `already-member`), and then clicking
*Undo: those accounts leave* still removes the three that went in — it walks back to the
newest join that created rows — and refuses with a named reason only when no join in the
session created anything. Clicking it twice is an honest no-op (`{"left": 0, "skipped": 3}`),
because those ids are already gone, not an error.

A pasted link is therefore a *name*, never a destination. Nothing in Option B can point the
tool at a room it does not already know how to reach: the target is the fixed loopback URL, the
room must be a row of your `settings.db`, and leaving is the explicit button over the ids the
join reported rather than a countdown. That combination is what makes it usable as a test of
your own join path — capacity, the private gate, idempotence, throttling — and what keeps the
bulk-joining shape out of it.

### Settings, and what the console refuses

Settings are validated before they are saved, and the reason comes back verbatim. Measured
responses:

```
users must be between 1 and 200,000 (got 900,000,000)
db must live under a var/ or tmp directory, got /etc/passwd
db looks like a real database (prod-users.db); refusing
hash_algo must be one of pbkdf2_sha256, sha256_fast
register_domain must be a reserved TLD (.invalid/.test/.example) so a run can never mail a real mailbox
stages need at least 1 concurrent user (got '0:0')
```

A hand-edited `var/console.json` that no longer parses gets the same treatment as a bad
save: the API answers `400 settings file unreadable: …` instead of dropping the
connection, and saving a valid patch replaces the broken file with a note saying it did.
`test_password` lives here (and only here) so the fixture the generator seeds and the
accounts the Operational tab logs in with cannot drift apart — the password is written into
the seeder's own `--test-password`, and the settings file is 0600 because of it.

The account list is its own card here, because it is the thing Option A and Option B both
read: a plain text file (`var/accounts.txt` by default, path editable in Settings) of one
username or email per line, with `#` comments. It is a *selection*, not a copy — it says
which fixture accounts the Operational tab may use — and it is meant to be hand-edited:

| button | what it does |
|---|---|
| Preview removal | the dry run of Sync: how many accounts the file does not list, how many stay |
| Sync: delete what the file omits | deletes every fixture account the file does not list, and their credentials, sessions, events, flags and memberships |
| Rewrite file from fixture | replaces the file with every account the fixture has, in id order |
| Seed from newest accounts | first-run helper: adds the newest `bootstrap_accounts` accounts to whatever the file already holds |
| View file | the file's contents in the browser (usernames only — the list holds no secrets) |

Editing the file to two of nine accounts and pressing *Sync* is how you remove accounts; the
preview first, because deleting the wrong set of accounts is the one irreversible thing in the
tool. Measured, a Sync of five removed accounts reported
`{"deleted": 5, "kept": 4, "children": {"credentials": 5, "sessions": 16, "events": 27,
"flags": 0, "memberships": 0, "invite_edges": 0}}` with zero orphan rows and all three servers
still present — rooms are handed to a surviving owner (`ON DELETE CASCADE` on `servers.owner_id`
would otherwise delete the room with its founder). Two guards sit in front of that: a file
whose lines match nothing is refused outright rather than read as "delete everything"
(`the list matches no account in this fixture: refusing to delete all 30 of them`), and the
list keeps inactive accounts on purpose, since anything the list omits is what the next Sync
removes.

Two things no tab, no field, and no command-line flag will do:

* **address anything that is not `127.0.0.1`.** There is no base-URL or host field, and the one
  link-shaped box in the UI is parsed for a room name, not a destination: a host other than the
  loopback API (or a loopback link naming the wrong port) is refused before any lookup, and the
  request that does go out is built by `Settings.api_url()` from the port number alone
  (`http://127.0.0.1:<api_port>`), and `load.engine` keeps its own `local_target()` check
  for the same reason. This is the line in *What is not here*, enforced in the place where a
  URL would otherwise be typed.
* **take orders from another web page.** Each request is checked on its `Host` header —
  `Host must be 127.0.0.1:8010 to reach this console (got 'attacker.example'); it runs jobs
  that rewrite your fixture` — plus `Origin` must equal `Host`, and
  `Sec-Fetch-Site: cross-site` is refused outright. `POST` bodies must be
  `application/json`, so a form from another origin cannot fire a job. Those checks stay on
  with `--allow-nonlocal`, which exists so a device on a LAN you own can open the page; it
  widens which hostname is trusted, not who may drive the console, and it prints a warning
  naming the port at startup.

```
python3 -m console --port 8010 --settings var/console.json --verbose
python3 -m console --bootstrap --open-browser        # what run.bat does
```

`--host` and `--allow-nonlocal` are the two flags that change the security posture, and
`--bootstrap` / `--open-browser` are the first-run pair the launcher passes: `--bootstrap`
generates `bootstrap_accounts` accounts and seeds the list **only when the fixture database
does not exist yet**, then does nothing on every later start. The `db`, `api_port` and other
knobs belong to the Settings tab, not to the command line — there is deliberately no `--db`
or base-URL flag to point at somebody else's system.

The suite behind all of this is `tests/test_console.py` (61 tests: the settings rules, the
header guard, the file-name rules, the exports, and join/undo against a live fixture) plus
`tests/test_roster.py` (28 on the list itself: reading a hand-edited file, what a Sync may
and may not delete, the export shape and its permissions); the routes have 26 in
`tests/test_mockapi.py`, and the repo is at 200 under `make test`.

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

The console adds the two that matter for a browser: no setting or payload field can name
a host (the target is always built as `http://127.0.0.1:<api_port>`), and every request is
rejected unless its `Host`, `Origin` and `Sec-Fetch-Site` say it came from the page itself
— so a remote site cannot drive a console that truncates your fixture. Its `db` field goes
through the same scratch-directory rule as the seeder's `--db`, dumps and `revoke.sql` are
written 0600, and `var/console.json` too because it holds `test_password`.

Two more, added when the account list became the thing both Operational options read:

* the list and its two exports are **not run dumps**. They live in the same scratch directory
  and match `accounts-*.txt`, so the dumps table, `/api/dump` and `/api/revoke` each refuse
  those three names by path (`refused: accounts-userpass.txt is the account list or one of its
  exports, not a run dump`). A password file must never be selectable as a token source, and
  `--revoke` on it would report a successful no-op.
* `Sync` refuses a list that matches **nothing** in the fixture rather than reading it as
  "delete everything" — an emptied or typo'd file is an accident, and rebuilding is what
  `--fresh` is for. The dry run never refuses anything: a preview has no side effects to protect.
