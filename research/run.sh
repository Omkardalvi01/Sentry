#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p bin
GOCACHE="${SENTRY_GO_CACHE:-/tmp/sentry-go-cache}" go build -o bin/sentry ./cmd/sentry
uv venv --python 3.11 .venv
uv pip install --python .venv/bin/python --require-hashes -r research/requirements.lock
.venv/bin/python research/benchmark.py "$@"
