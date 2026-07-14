# cpa-login-hub — build orchestration
#
# Targets:
#   make build       — build the shared library for the current OS
#   make build-all   — build for macOS + Linux (Windows requires cross-toolchain)
#   make test        — run go vet + gofmt check
#   make clean       — remove build artifacts
#   make install     — copy .so + worker/ into $(CPA_PLUGIN_DIR)/cpa-login-hub/
#
# CPA_PLUGIN_DIR defaults to ~/.cli-proxy-api/plugins — override to point at
# a non-default install:
#   CPA_PLUGIN_DIR=/path/to/plugins make install

CPA_PLUGIN_DIR ?= $(HOME)/.cli-proxy-api/plugins
PLUGIN_NAME := cpa-login-hub
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
  EXT := dylib
else ifeq ($(UNAME_S),Linux)
  EXT := so
else
  EXT := dll
endif

.PHONY: build build-all test clean install worker-setup

build:
	go build -buildmode=c-shared -o $(PLUGIN_NAME).$(EXT) .

build-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 \
	  go build -buildmode=c-shared -o $(PLUGIN_NAME).so .

build-darwin:
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 \
	  go build -buildmode=c-shared -o $(PLUGIN_NAME).dylib .

build-all: build-linux build-darwin
	@echo "Windows builds require a cross-toolchain (mingw-w64) — run separately."

test:
	go vet ./...
	@if [ -n "$$(gofmt -l .)" ]; then \
	  echo "gofmt violations:"; gofmt -l .; exit 1; \
	fi

clean:
	rm -f $(PLUGIN_NAME).so $(PLUGIN_NAME).dylib $(PLUGIN_NAME).dll $(PLUGIN_NAME).h

install: build
	@mkdir -p "$(CPA_PLUGIN_DIR)/$(PLUGIN_NAME)"
	cp $(PLUGIN_NAME).$(EXT) "$(CPA_PLUGIN_DIR)/$(PLUGIN_NAME)/"
	@# worker/ ships alongside so the venv is provisioned inside the
	@# plugin bundle CPA discovers.
	rsync -a --delete \
	  --exclude '.venv/' --exclude '__pycache__/' --exclude '*.pyc' \
	  --exclude '.setup_done' --exclude '.setup.lock' \
	  --exclude 'runs/' --exclude 'output/' \
	  worker/ "$(CPA_PLUGIN_DIR)/$(PLUGIN_NAME)/worker/"
	@echo "Installed to $(CPA_PLUGIN_DIR)/$(PLUGIN_NAME)/"
	@echo "First login run will auto-provision Python venv (~90s)."

worker-setup:
	@# Manual venv setup for dev / offline environments.
	bash scripts/setup_venv.sh
