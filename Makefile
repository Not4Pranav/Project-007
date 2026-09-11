# Bulk test accounts for YOUR OWN app: seed -> inspect -> detect -> load -> gate.
# Everything is stdlib; `PY=python3.12 make seed` works if you prefer another interpreter.

PY      ?= python3
DB      ?= var/test.db
USERS   ?= 30000
DAYS    ?= 180
BOTS    ?= 1200
SEED    ?= 42
PORT    ?= 8000
STAGES  ?= 25,100,250
SLO     ?= p95_ms=250,error_rate_pct=0.5

W ?= -W ignore::ResourceWarning   # the throwaway server's daemon threads leak sockets by design

.DEFAULT_GOAL := help

help: ## list targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "  vars: DB=$(DB) USERS=$(USERS) DAYS=$(DAYS) BOTS=$(BOTS) STAGES=$(STAGES)"
	@echo "        SLO='$(SLO)' PORT=$(PORT)   (make seed USERS=200000)"

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
	  --base-url http://127.0.0.1:$(PORT) --slo "$(SLO)"

smoke: ## fast path: 4k accounts, 3 short stages, ~40s total
	$(PY) $(W) -m seeds.seed --db var/smoke.db --users 4000 --days 30 --inject-bots 200 --fresh
	$(PY) $(W) -m abuse.detector --db var/smoke.db --velocity-min 12 --fan-in-min 15 --template-min 4
	@echo "now: make api  (then, in another shell) "
	@echo "     python3 -m load.engine --fixture-db var/smoke.db --stages 20,60 --stage-seconds 8"

demo: seed detect ## seed at full size, then scan it

test: ## the whole suite, no installs
	$(PY) $(W) -m unittest discover -s tests -t .

lint: ## optional, needs `pip install ruff`
	$(PY) -m ruff check . || true

clean: ## drop every generated database and report
	rm -rf var
