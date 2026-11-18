SHELL := /bin/bash

.PHONY: help setup worker-deps worker-dev worker-test runner-test test check \
	install-scanner local-scan send-test-webhook deploy

help: ## Show available commands
	@awk 'BEGIN {FS = ":.*## "} /^[a-z-]+:.*## / {printf "  %-22s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

setup: ## Create local config files and a Python virtual environment
	bash scripts/setup.sh

worker-deps: ## Install the Worker's npm packages
	cd worker && npm install

worker-dev: ## Start the Worker locally
	cd worker && npm run dev

worker-test: ## Run Worker unit tests
	cd worker && npm test

runner-test: ## Run runner unit tests
	PYTHONPATH=runner python3 -m unittest discover -s runner/tests -v

test: worker-test runner-test ## Run every test suite

check: ## Type-check the Worker and run every test suite
	cd worker && npm run typecheck
	$(MAKE) test

install-scanner: ## Download osv-scanner into ./bin
	bash scripts/install-scanner.sh

local-scan: ## Run a local scan (use ARGS="--repo /path --format json")
	bash scripts/local-scan.sh $(ARGS)

send-test-webhook: ## Send a signed sample webhook to the local Worker
	bash scripts/send-test-webhook.sh

deploy: ## Deploy the Worker to Cloudflare
	cd worker && npm run deploy
