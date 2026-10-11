# Sentry

Sentry compares API specifications, observed traffic, and active HTTP responses to identify inventory discrepancies and suspicious behavior. It retains the original five strategies: deprecated endpoints, alternate versions, undocumented methods, shadow paths, and authentication verification.

A reachable deprecated endpoint is a lifecycle finding. It is not automatically a critical vulnerability or proof of overdue retirement. Behavioral novelty is reported separately from inventory evidence.

## Run locally

Requires Go matching `go.mod`, Python with PyTorch/Transformers, a local Jevlet source checkout and trained checkpoint, and Docker Compose for the complete pipeline. Native CUDA inference is the default; explicitly choose `SENTRY_JEVLET_DEVICE=cpu` when GPU inference is unavailable.

```sh
go build -o bin/sentry ./cmd/sentry
uv venv --python 3.11 .venv
uv pip install --python .venv/bin/python --require-hashes -r research/requirements.lock
uv pip install --python .venv/bin/python -r anomaly-detector/requirements-jevlet.txt
export SENTRY_JEVLET_REPO=/absolute/path/to/jevlet
export SENTRY_JEVLET_CHECKPOINT=/absolute/path/to/trained/seed-42
```

The complete container environment uses Memgraph, a Kafka-compatible Redpanda broker, Redis, the Python detector, three local testbeds, the consumer, and dashboard. It mounts the configured local source and checkpoint directories and uses CPU inference. Use the native launcher below for CUDA inference; model training requires CUDA. Checkpoints are local artifacts and are not shipped in Git:

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

The active Python detector uses Jevlet for request-anomaly classification. It receives bounded captured request/response text, method, path, query, status, available latency and wire size, header names, and normal-baseline size/latency changes. Request identities, labels, and header values are excluded. Its classification score is not a calibrated probability of an attack. Graph inventory signals stay separate from the learned behavioral verdict. The separate body-size alert rule is disabled. Isolation Forest and its offline evaluation code remain in `anomaly-detector/detector.py`; its HTTP routes are removed.

Explicit Jevlet retraining uses CUDA and reviewed labels only, requiring at least 160 normal events and 20 anomalies. Earlier traffic is split into training/selection with both labels; a later normal window calibrates the default 5% false-positive target. The checkpoint selected by validation loss is saved before activation. Failed training retains the previous active model. No scheduled forest training runs in the active service. Set `target_fpr` above 0 through 0.25 and optional timezone-aware `start`/`end` timestamps. Model directories and preprocessing pickles must come from a trusted local run. The Jevlet registry is separate from the legacy forest registry.

A checkpoint containing the trained failure head also exposes `POST /jevlet/service-failure` with `{"telemetry_text":"..."}`. This classifies a prepared service telemetry window separately from a suspicious request. Kafka currently provides individual HTTP events; it does not aggregate telemetry windows automatically. Retraining the request encoder requires retraining a matching failure head before this output can be used again.

To label traffic, configure `SENTRY_REVIEW_TOKEN` and call `PUT /traffic/{request_id}/review` with `X-Review-Token` and `{"label":"normal"}` or `{"label":"anomaly"}`. Then call `POST /jevlet/models/retrain`. The review endpoint is disabled until a token is configured.

Traffic events may include `response_time_ms` and `response_size_bytes`; older producers can omit them. Sentry persists them for retraining and restores them when retrying pending predictions.

```sh
# Configure a previously trained Jevlet checkpoint first.
SENTRY_DB_PATH="$PWD/traffic.db" .venv/bin/uvicorn app:app --app-dir anomaly-detector --port 5001
```

```sh
curl --fail -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:5001/jevlet/models/retrain
```

The retraining route requires reviewed traffic; demo fixture traffic is not automatically labelled.

Validated application adapters can use a separate request-only Jevlet head and a
normal-data threshold for explicitly configured path scopes. Other requests keep
the original Jevlet head. See [the adaptation results](evaluation/JEVLET_DOMAIN_ADAPTATION.md)
for scope, evaluation counts and the remaining ownership-detection limitation.

To activate a trusted, already trained checkpoint while the detector is stopped:

```sh
python research/activate_jevlet.py --db .local-data/app/traffic.db \
  --checkpoint /absolute/path/to/validated/checkpoint --repo /absolute/path/to/jevlet
```

For a running detector, add `--detector-url http://127.0.0.1:5001` and use the same
database as that detector. Registration validates the checkpoint before the
existing activation endpoint switches models. Activation persists across restarts.
CUDA is the default; `--device cpu` explicitly selects CPU inference. Checkpoints
remain local and must be provisioned separately from a Git checkout.

## APIs

| Service | Interface | Purpose |
|---|---|---|
| Go | `GET /api/health`, `/api/overview`, `/api/specs` | Measured service status and inventory |
| Go | `GET /api/scans`, `/api/scans/{id}` | Paginated durable scan history |
| Go | `POST /api/scans`, `DELETE /api/scans/{id}` | Run or cancel real jobs |
| Go | `GET /api/findings`, `/api/findings/{id}` | Paginated findings and detailed evidence |
| Go | `GET /api/traffic`, `/api/anomalies` | Paginated observations (`limit`, `offset`) |
| Python | `POST /jevlet/predict` | Per-event inventory and Jevlet behavioral signals |
| Python | `GET /health`, `/jevlet/models` | Detector state and model metadata |
| Python | `POST /jevlet/models/retrain` | Train Jevlet on CUDA from reviewed events |
| Python | `POST /jevlet/models/{id}/activate` | Activate a registered Jevlet checkpoint |
| Python | `POST /jevlet/service-failure` | Classify a supplied telemetry window using a matching failure head |

The dashboard uses persisted records exclusively. It does not generate simulated findings or silently replace failed backend requests with a demo. Kafka connectivity is not directly measured by the dashboard; it reports stored observations rather than inventing a connected state.

## External dataset evaluation

The separate [evaluation workspace](evaluation/README.md) contains reproducible API scanning and labelled traffic evaluation scripts, pinned dataset revisions, and historical result summaries. The [supervisor brief](evaluation/SUPERVISOR_BRIEF.md) summarizes API-only, graph-only, and combined results. Historical [graph inventory](evaluation/results/zombie-shadow-graph.json), [Isolation Forest](evaluation/results/isolation-forest-fur-api.json), [reviewed-label classifier](evaluation/results/fur-api-reviewed-examples.json), and [feature comparison](evaluation/results/detector-feature-comparison.json) results remain available. The active service now uses Jevlet; see [live integration evaluation](evaluation/JEVLET_INTEGRATION.md). The older crAPI, Nicefish, and Train Ticket reports are from the pre-PR scanner; `evaluation/run_api.py` now targets this architecture's `scan-spec` workflow.

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

Open **http://127.0.0.1:8088**. Startup loads the configured Jevlet checkpoint, starts continuous real HTTP traffic through Kafka, and submits an initial real scan. Fixtures are intentionally vulnerable local APIs, not production traffic. A model trained on FUR-API has not been calibrated to these fixtures; use a labelled held-out dataset to measure classifier accuracy.

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
