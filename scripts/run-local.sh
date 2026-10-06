#!/bin/sh
# Full local fixture demo: native app processes plus Docker dependencies.
set -eu
cd "$(dirname "$0")/.."
if [ "${1:-}" = --stop ]; then
    .venv/bin/python research/demo.py --stop
    docker compose -f compose.local.yaml down
    exit 0
fi
if [ -x .venv/bin/python ] && .venv/bin/python research/demo.py --running; then
    printf '%s\n' 'Sentry is already running: http://127.0.0.1:8088'
    exit 0
fi
if [ ! -x bin/sentry ]; then mkdir -p bin; go build -o bin/sentry ./cmd/sentry; fi
if [ ! -x .venv/bin/python ]; then
    uv venv --python 3.11 .venv
    uv pip install --python .venv/bin/python --require-hashes -r research/requirements.lock
fi
mkdir -p .local-data/memgraph .local-data/graph-logs .local-data/kafka .local-data/app/logs
chmod 777 .local-data/memgraph .local-data/graph-logs .local-data/kafka
export SENTRY_LOCAL_UID="$(id -u)" SENTRY_LOCAL_GID="$(id -g)"
# Reuse available dependency images on machines with limited Docker disk space.
if [ -z "${SENTRY_LOCAL_MEMGRAPH_IMAGE:-}" ]; then
    SENTRY_LOCAL_MEMGRAPH_IMAGE="$(docker image inspect memgraph/memgraph:3.0.0 --format '{{.Id}}' 2>/dev/null || docker image inspect memgraph/memgraph:latest --format '{{.Id}}' 2>/dev/null || printf '%s' memgraph/memgraph:3.0.0)"
    SENTRY_LOCAL_MEMGRAPH_IMAGE="$(printf '%s' "$SENTRY_LOCAL_MEMGRAPH_IMAGE" | tr -d '\r\n')"
    export SENTRY_LOCAL_MEMGRAPH_IMAGE
fi
if [ -z "${SENTRY_LOCAL_REDIS_IMAGE:-}" ]; then
    SENTRY_LOCAL_REDIS_IMAGE="$(docker image inspect redis:7.4.2-alpine --format '{{.Id}}' 2>/dev/null || docker image inspect redis:7.4.7-alpine --format '{{.Id}}' 2>/dev/null || printf '%s' redis:7.4.2-alpine)"
    SENTRY_LOCAL_REDIS_IMAGE="$(printf '%s' "$SENTRY_LOCAL_REDIS_IMAGE" | tr -d '\r\n')"
    export SENTRY_LOCAL_REDIS_IMAGE
fi
trap 'docker compose -f compose.local.yaml down' EXIT
COMPOSE_PROGRESS=plain docker compose -f compose.local.yaml up -d --wait --wait-timeout 90
.venv/bin/python research/demo.py
