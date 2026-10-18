SHELL = /bin/sh
.SHELLFLAGS := -ec
.ONESHELL:
.DELETE_ON_ERROR:
.SUFFIXES:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

.DEFAULT_GOAL := all

CRYSTAL ?= crystal
SHARDS  ?= shards
PREFIX  ?= /usr/local
DESTDIR ?=
DATADIR ?= $(PREFIX)/share
DOCDIR  ?= $(DATADIR)/doc/crystal-ecc-constant

AMEBA := bin/ameba
FLAW  := bin/flaw

.PHONY: all deps test check lint format docs install uninstall clean help

all: lint test ## Run static analysis and test suite

deps: $(AMEBA) $(FLAW) ## Install shard dependencies and build linter binaries

bin:
	mkdir -p $@

$(AMEBA): | bin
	@if [ ! -f lib/ameba/src/cli.cr ]; then $(SHARDS) install; rm -f shard.lock; fi
	$(CRYSTAL) build lib/ameba/src/cli.cr -o $@

$(FLAW): | bin
	@if [ ! -f lib/flaw/src/cli.cr ]; then $(SHARDS) install; rm -f shard.lock; fi
	$(CRYSTAL) build lib/flaw/src/cli.cr -o $@

test: ## Run Crystal test suite
	$(CRYSTAL) spec

check: test ## Alias for test

lint: $(AMEBA) $(FLAW) ## Run Ameba and Flaw static analysis
	$(CRYSTAL) tool format --check src spec
	./$(AMEBA) --all
	./$(FLAW) scan .

format: ## Format Crystal source and spec files
	$(CRYSTAL) tool format src spec

docs: ## Generate Crystal API documentation
	$(CRYSTAL) docs --output=docs/technical/api

install: docs ## Install documentation to DESTDIR/DOCDIR
	install -d $(DESTDIR)$(DOCDIR)
	cp -r docs/* $(DESTDIR)$(DOCDIR)/

uninstall: ## Remove installed documentation from DESTDIR/DOCDIR
	rm -rf $(DESTDIR)$(DOCDIR)

clean: ## Remove build artifacts and generated documentation
	rm -rf docs/technical/api .crystal lib bin shard.lock

help: ## Display available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'
