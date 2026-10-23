.PHONY: bootstrap test inventory validate-profiles matrix-list matrix matrix-refresh matrix-full extract-offsets up down up-platform down-platform up-remote down-remote restart check verify solve solve-remote shell-remote reset logs help

bootstrap:
	cd solver && python3 bootstrap_upstream.py

test:
	python3 -m unittest discover -s tests -v

inventory:
	./research/profile_inventory.py --output solver/profiles/INVENTORY.md

validate-profiles:
	./research/profile_inventory.py --check

matrix-list:
	./research/matrix_runner.py --set full --list

matrix:
	./research/matrix_runner.py --set $(or $(MATRIX),verified) --stop-on-error

matrix-refresh:
	./research/matrix_runner.py --set $(or $(MATRIX),verified) --refresh --stop-on-error

matrix-full:
	./research/matrix_runner.py --set full --refresh --stop-on-error

extract-offsets:
	@if [ -z "$(IMAGE)" ]; then echo 'Usage: make extract-offsets IMAGE=php:8.4.26-apache [PLATFORM=linux/amd64]'; exit 2; fi
	./research/extract_offsets.py --image "$(IMAGE)" $(if $(PLATFORM),--platform "$(PLATFORM)",)

up:
	@mkdir -p runtime/out
	@chmod 1777 runtime/out
	docker compose -f challenge/compose/local.yml up -d --build

down:
	docker compose -f challenge/compose/local.yml down

up-remote:
	docker compose -f challenge/compose/remote.yml up -d --build

down-remote:
	docker compose -f challenge/compose/remote.yml down

up-platform:
	@mkdir -p runtime/out
	@chmod 1777 runtime/out
	docker compose -f challenge/compose/platform.yml up -d --build

down-platform:
	docker compose -f challenge/compose/platform.yml down

restart:
	docker compose -f challenge/compose/local.yml restart

check:
	./scripts/check_lab.sh

verify:
	./scripts/verify_flag.sh

solve:
	./solver/solve_local.py

solve-remote:
	@if [ -z "$(TARGET)" ]; then echo 'Usage: make solve-remote TARGET=http://challenge-host:8426'; exit 2; fi
	./solver/solve_remote.py "$(TARGET)"

shell-remote:
	@if [ -z "$(TARGET)" ]; then echo 'Usage: make shell-remote TARGET=http://challenge-host:8426'; exit 2; fi
	./solver/solve_remote.py "$(TARGET)" --shell

reset:
	./scripts/reset_lab.sh
	@mkdir -p runtime/out
	@chmod 1777 runtime/out

logs:
	docker compose -f challenge/compose/local.yml logs -f

help:
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-22s %s\\n", $$1, $$2}'
