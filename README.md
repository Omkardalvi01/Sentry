# Sentry

Sentry compares API specifications, observed traffic, and active HTTP responses to identify inventory discrepancies and suspicious behavior. It retains the original five strategies: deprecated endpoints, alternate versions, undocumented methods, shadow paths, and authentication verification.

A reachable deprecated endpoint is a lifecycle finding. It is not automatically a critical vulnerability or proof of overdue retirement. Behavioral novelty is reported separately from inventory evidence.

## Run locally

Requires Go matching `go.mod`, Python 3.11, and Docker Compose for the complete pipeline.

```sh
go build -o bin/sentry ./cmd/sentry
uv venv --python 3.11 .venv
uv pip install --python .venv/bin/python --require-hashes -r research/requirements.lock
```

The complete container environment uses Memgraph, a Kafka-compatible Redpanda broker, Redis, the Python detector, three local testbeds, the consumer, and dashboard:

```sh
docker compose up -d --build
```

The dashboard is at `http://127.0.0.1:8088`. The local testbeds are at ports 9001–9003; Memgraph is exposed at 7688 and Kafka at 19092. Existing services on port 8080 are unaffected.

Generate and ingest a local fixture specification:

```sh
mkdir -p research/generated
curl --fail http://127.0.0.1:9001/openapi.json -o research/generated/resource.json
docker compose run --rm -v "$PWD/research/generated:/specs:ro" dashboard ingest --file /specs/resource.json
```

When scanning from the container dashboard, use `http://resource:9001` as the target. The host browser talks to the dashboard, while probes originate from the Go service.

For processes running directly on the host:

```sh
bin/sentry ingest --file research/generated/resource.json --memgraph-uri bolt://127.0.0.1:7688
bin/sentry dashboard --port 8088 --memgraph-uri bolt://127.0.0.1:7688 --sqlite-db traffic.db
```

The host dashboard and consumer must use the same SQLite file. A container database is in its named volume and is separate from a host `traffic.db`.

## Scanner behavior

```sh
bin/sentry scan --target http://127.0.0.1:9001 --spec-title resource --spec-version 1 \
  --memgraph-uri bolt://127.0.0.1:7688 --header 'Authorization: Bearer fixture'

bin/sentry scan-spec --file research/generated/resource.json \
  --target http://127.0.0.1:9001 --dry-run
```

- Select one specification and version per scan. Identical routes in different inventories remain distinct.
- Dry runs generate the plan without sending baseline or target requests.
- GET, HEAD, and OPTIONS are enabled by default. `--allow-mutating` enables POST/PUT/PATCH/DELETE probes for resettable targets.
- Three nonexistent-route baselines are collected per directory, method, and authentication context. Matching compares normalized response content and media type, never just body length.
- Responses are read up to 1 MiB, configurable with `--max-response-bytes`. Evidence keeps a separate short snippet.
- Schema outcomes are `matched`, `mismatched`, `unavailable`, or `truncated`. Unsupported recursive schemas remain unavailable instead of being treated as matches.
- A protected deprecated operation is tested without credentials only when credentials were supplied. Authentication exposure requires comparable successful content.
- Passive undocumented routes join the active shadow-path plan, with provenance retained in findings.
- Findings expose severity, confidence, verification outcome, schema result, operation identity, and provenance independently.

## Traffic and models

Kafka traffic events use the fields in `internal/model/traffic.go`. Provide `spec_title` and `spec_version` when multiple inventories exist. Route templates are resolved before prediction. Ambiguous or unavailable context stays unknown.

Every event is evaluated. Redis only caches inventory snapshots for 60 seconds; it never caches a normal endpoint verdict. Redis is optional and configured by the deployment, without application-wide `CONFIG SET` calls.

The consumer stores traffic and prediction outcomes atomically before committing Kafka offsets. Detector outages persist `pending` records, which are retried after recovery and across consumer restarts. Invalid events are rejected durably with their Kafka source identity. Duplicate request IDs do not duplicate stored traffic.

The Python detector combines endpoint-relative body-size checks and Isolation Forest. Its features include HTTP method, route and query shape, decoded traversal/injection indicators, response status and body size, optional response latency and wire size, selected request-header presence, and graph metadata. It profiles numeric path IDs as one endpoint when no OpenAPI template is available. Header values are not used as features. Model scores are not probabilities. Time-of-day features are enabled only when training history covers at least a day.

Retraining orders eligible traffic chronologically, trains on the first 80%, and calibrates a default 5% false-positive target on the final 20%. It uses Isolation Forest until at least 20 reviewed anomalies are available in the training slice, then trains an Extra Trees classifier from reviewed anomalies and normal baseline traffic. The final validation slice is normal-only for threshold calibration. Set `target_fpr` in the retrain request to choose another value above 0 through 0.25. At least 32 normal training and 16 normal validation events are required. Pending and unreviewed predicted anomalies are excluded; explicit analyst labels override predictions. Failed retraining retains the old model. Model artifacts remain local trusted files because scikit-learn persistence uses pickle.

To label traffic, configure `SENTRY_REVIEW_TOKEN` and call `PUT /traffic/{request_id}/review` with `X-Review-Token` and `{"label":"normal"}` or `{"label":"anomaly"}`. Then call `POST /models/retrain`. The review endpoint is disabled until a token is configured.

Traffic events may include `response_time_ms` and `response_size_bytes`; older producers can omit them. Sentry persists them for retraining and restores them when retrying pending predictions.

```sh
# Explicit synthetic normal baseline, for model lifecycle demonstrations only.
.venv/bin/python anomaly-detector/seed_db.py --db traffic.db
SENTRY_DB_PATH="$PWD/traffic.db" .venv/bin/uvicorn app:app --app-dir anomaly-detector --port 5001
```

```sh
curl --fail -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:5001/models/retrain
```

This seeded database is clearly synthetic and must not be presented as real collected traffic.

## APIs

| Service | Interface | Purpose |
|---|---|---|
| Go | `GET /api/health`, `/api/overview`, `/api/specs` | Measured service status and inventory |
| Go | `GET /api/scans`, `/api/scans/{id}` | Paginated durable scan history |
| Go | `POST /api/scans`, `DELETE /api/scans/{id}` | Run or cancel real jobs |
| Go | `GET /api/findings`, `/api/findings/{id}` | Paginated findings and detailed evidence |
| Go | `GET /api/traffic`, `/api/anomalies` | Paginated observations (`limit`, `offset`) |
| Python | `POST /predict` | Per-event inventory and behavioral signals |
| Python | `GET /health`, `/models` | Detector state and model metadata |
| Python | `POST /models/retrain` | Train from an explicit optional `start`/`end` window |
| Python | `POST /models/{id}/activate` | Activate an existing compatible model |

The dashboard uses persisted records exclusively. It does not generate simulated findings or silently replace failed backend requests with a demo. Kafka connectivity is not directly measured by the dashboard; it reports stored observations rather than inventing a connected state.

## External dataset evaluation

The separate [evaluation workspace](evaluation/README.md) contains reproducible API scanning and labeled traffic evaluation scripts, pinned dataset revisions, and result summaries. The [supervisor brief](evaluation/SUPERVISOR_BRIEF.md) summarizes API-only, graph-only, and combined results. The current [zombie/shadow graph inventory result](evaluation/results/zombie-shadow-graph.json), [Isolation Forest train/test result](evaluation/results/isolation-forest-fur-api.json), [reviewed-label classifier result](evaluation/results/fur-api-reviewed-examples.json), [merged detector replay](evaluation/results/fur-api-enhanced.json), and [model feature comparison](evaluation/results/detector-feature-comparison.json) are linked directly. Reviewed traffic can now train a label-aware model: configure `SENTRY_REVIEW_TOKEN`, label requests through the protected review endpoint, then retrain. The service keeps Isolation Forest until at least 20 reviewed anomalies are available. The older crAPI, Nicefish, and Train Ticket reports are from the pre-PR scanner; `evaluation/run_api.py` now targets this architecture's `scan-spec` workflow.

## Research and verification

```sh
./research/run.sh
```

This starts resettable local HTTP testbeds, gathers real requests against those fixtures, executes the production Go scanner, and evaluates five seeds. It produces separate event and endpoint metrics, component ablations, held-out application evaluation, raw reports, confidence intervals, latency measurements, and exportable plots in `research/results/`.

```sh
go test -race ./...
.venv/bin/python -m pytest -q tests
./scripts/integration.sh
```

The integration check starts isolated Memgraph, Kafka, and Redis, verifies the real pipeline and browser, and stops only those test containers. See [the research protocol](research/README.md), [the manuscript draft](research/paper.md), and [the implementation decisions](docs/decisions.md).

The local testbeds are controlled evaluation fixtures, not evidence of production generalization. The benchmark keeps failed generalization results. No downstream service topology or blast-radius claim is made.

## See the entire project running

The local launcher runs the Go and Python services directly and uses Docker for Memgraph, Kafka, and Redis. It keeps data under `.local-data/` on the project partition and reuses cached dependency images when available.

```sh
./scripts/run-local.sh
```

Open **http://127.0.0.1:8088**. Startup trains a baseline from normal requests to the local fixtures, starts continuous real HTTP traffic through Kafka, and submits an initial real scan. Fixtures are intentionally vulnerable local APIs, not production traffic.

Click **New scan**, select **resource · 1**, and enter `http://127.0.0.1:9001`. Add an `Authorization` header with value `Bearer fixture`. Preview the request plan, leave Dry run unchecked, and click Start scan. Use Endpoints, Scans, Findings, Traffic, and System health to inspect the results. The other fixtures are `versioned` on 9002 and `gateway` on 9003.

The detector's interactive API documentation is at **http://127.0.0.1:5001/docs**. Service logs and persistent history are in `.local-data/app/`.

Stop with Ctrl+C in the launcher terminal, or from another terminal:

```sh
./scripts/run-local.sh --stop
```


## Investigate one endpoint

Select an API and target in the header, then open **Scans** and choose a run. The request explorer filters by originating operation, actual method/path, strategy, result, HTTP status, authentication context, and baseline controls. Sorting and pagination apply to the complete dataset; exports use the same filters.

Opening a request shows readable response evidence and related baseline/authenticated comparisons. Older scans retain their findings and explicitly report that request history was not recorded. The Endpoints screen can launch a scan limited to one operation and its related checks; unrelated shadow guesses are excluded.

The new `/api/explorer/{endpoints,scans,findings,traffic}` endpoints return `items`, matching `total`, pagination, and a snapshot bound. `/api/scans/{id}/requests` and `/api/requests/{id}` expose sanitized request history. Existing list APIs remain available for compatibility. Passive traffic without a recorded target remains separate from target-filtered observations.

Browser acceptance checks against the running local demo:

```sh
.venv/bin/python research/browser_explorer.py
```
