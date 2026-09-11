# Bulk test accounts for YOUR OWN app: seed -> inspect -> detect -> load -> gate.
# Everything is stdlib; `PY=python3.12 make seed` works if you prefer another interpreter.

PY      ?= python3
DB      ?= var/test.db
USERS   ?= 30000
DAYS    ?= 180
BOTS    ?= 1200
SEED    ?= 42
PORT    ?= 8000
CPORT   ?= 8010
STAGES  ?= 25,100,250
SLO     ?= p95_ms=250,error_rate_pct=0.5

W ?= -W ignore::ResourceWarning   # the throwaway server's daemon threads leak sockets by design

.DEFAULT_GOAL := help

# Without this, `make load`/`make test`/`make report` silently do nothing: a directory
# named `load/`, `tests/` or `seeds/report*` exists, so make considers the target
# up to date. Targets that are not files must say so.
.PHONY: help seed report detect api load load-spec export revoke smoke demo console test lint clean

help: ## list targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "  vars: DB=$(DB) USERS=$(USERS) DAYS=$(DAYS) BOTS=$(BOTS) STAGES=$(STAGES)"
	@echo "        SLO='$(SLO)' PORT=$(PORT) CPORT=$(CPORT)   (make seed USERS=200000)"

seed: ## rebuild the fixture database (users, credentials, activity, sessions)
	$(PY) $(W) -m seeds.seed --db $(DB) --users $(USERS) --days $(DAYS) --seed $(SEED) \
	  --inject-bots $(BOTS) --fresh

report: ## print the shape of the fixture (signup curve, skew, domains, verification lag)
	$(PY) $(W) -m seeds.report_cli --db $(DB)

detect: ## score signup-abuse signals and grade them against the fixture labels
	$(PY) $(W) -m abuse.detector --db $(DB) --allow-domain loadtest.invalid \
	  --export var/reports/flagged.csv

api: ## run the mock app (register/login/feed) on $(PORT) for the load engine
	$(PY) $(W) -m mockapi.server --db $(DB) --port $(PORT) --host 0.0.0.0

load: ## ramped load run against the mock app, with an SLO exit code
	$(PY) $(W) -m load.engine --fixture-db $(DB) --stages $(STAGES) --stage-seconds 15 \
	  --base-url http://127.0.0.1:$(PORT) --slo "$(SLO)" --accounts-file auto
	@echo "  browse as a worker: see var/reports/accounts-*.md   undo: make revoke"

revoke: ## kill every session token in the newest account dump
	@latest=$$(ls -t var/reports/accounts-*.txt 2>/dev/null | head -1); \
	 if [ -z "$$latest" ]; then echo "no dump in var/reports (run: make load)"; exit 1; fi; \
	 echo "revoking $$latest"; $(PY) -m load.accounts --revoke "$$latest" --db $(DB)

smoke: ## fast path: 4k accounts, 3 short stages, ~40s total
	$(PY) $(W) -m seeds.seed --db var/smoke.db --users 4000 --days 30 --inject-bots 200 --fresh
	$(PY) $(W) -m abuse.detector --db var/smoke.db --velocity-min 12 --fan-in-min 15 --template-min 4
	@echo "now: make api  (then, in another shell) "
	@echo "     python3 -m load.engine --fixture-db var/smoke.db --stages 20,60 --stage-seconds 8"

export: ## write bulk csv/jsonl + import.postgres.sql for $(DB) into var/out
	$(PY) $(W) -m seeds.export --db $(DB) --out var/out \
	  --tables users,credentials,events,invite_edges --format csv,jsonl

load-spec: ## drive the API at $(PORT) from a JSON scenario spec instead of built-in ops
	$(PY) $(W) -m load.engine --base-url http://127.0.0.1:$(PORT) \
	  --spec docs/examples/mockapi.load.json --fixture-db $(DB) --stages $(STAGES) \
	  --slo "$(SLO)"

console: ## the three tabs (Generator / Operational / Settings) on http://127.0.0.1:$(CPORT)
	@echo "seeding var/console.json with DB=$(DB) PORT=$(PORT); the other knobs live in the Settings tab"
	@$(PY) -c "import sys; sys.path.insert(0,'.'); from pathlib import Path; from console.settings import Settings, apply_updates, load, save; p=Path('var/console.json'); cur=(load(p) if p.exists() else Settings()); save(p, apply_updates(cur, {'db':'$(DB)', 'api_port':'$(PORT)', 'users':'$(USERS)', 'days':'$(DAYS)', 'bots':'$(BOTS)', 'seed':'$(SEED)', 'stages':'$(STAGES)', 'slo':'$(SLO)'}))"
	$(PY) $(W) -m console --port $(CPORT) --settings var/console.json

demo: seed detect ## seed at full size, then scan it

test: ## the whole suite, no installs
	$(PY) $(W) -m unittest discover -s tests -t .

lint: ## optional, needs `pip install ruff`
	$(PY) -m ruff check . || true

clean: ## drop every generated database and report
	rm -rf var
