#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p .integration-data/memgraph-data .integration-data/memgraph-logs .integration-data/kafka-data bin
chmod 777 .integration-data/memgraph-data .integration-data/memgraph-logs .integration-data/kafka-data
export SENTRY_TEST_UID="$(id -u)" SENTRY_TEST_GID="$(id -g)"
trap 'docker compose -f compose.integration.yaml down' EXIT
COMPOSE_PROGRESS=plain docker compose -f compose.integration.yaml up -d
GOCACHE="${SENTRY_GO_CACHE:-/tmp/sentry-go-cache}" go build -o bin/sentry ./cmd/sentry
uv venv --python 3.11 .venv
uv pip install --python .venv/bin/python --require-hashes -r research/requirements.lock
if [ "${CI:-}" = true ]; then .venv/bin/playwright install --with-deps chromium; else .venv/bin/playwright install chromium; fi
.venv/bin/python - <<'PYWAIT'
import socket,time
for port in [7689,19093,6389]:
    deadline=time.monotonic()+60
    while True:
        try:
            with socket.create_connection(('127.0.0.1',port),timeout=1): break
        except OSError:
            if time.monotonic()>deadline:raise RuntimeError(f'Service on {port} did not start')
            time.sleep(.5)
PYWAIT
SENTRY_TEST_MEMGRAPH=bolt://127.0.0.1:7689 GOCACHE="${SENTRY_GO_CACHE:-/tmp/sentry-go-cache}" go test -v ./internal/graph
.venv/bin/python research/integration.py --browser
