# Evaluation

This directory contains local, reproducible evaluation scripts and result summaries for Sentry. Downloaded upstream repositories, runtime databases, logs, and binaries are ignored by Git.

For a concise, presentation-ready summary of API-only, graph-only, and combined findings, see the [supervisor brief](SUPERVISOR_BRIEF.md).

## Current evaluation results

The result summaries are saved under `results/` and linked here for quick access.

| Evaluation | Result | Report |
|---|---|---|
| Zombie and shadow API inventory detection | Graph-backed active scan: precision 83.3%, recall 83.3%, F1 0.833. Graph inventory plus held-out passive candidates: precision 85.7%, recall 100%, F1 0.923 across three controlled APIs. | [zombie-shadow-graph.json](results/zombie-shadow-graph.json) |
| Isolation Forest only | FUR-API held-out test: precision 30.2%, recall 8.7%, F1 0.135, average precision 0.273. At the default 5% validation FPR it found 13/150 anomalies and flagged 30/999 normal requests. | [isolation-forest-fur-api.json](results/isolation-forest-fur-api.json) |
| Reviewed-label classifier | Extra Trees trained on 52 labeled anomalies from the training split: precision 65.7%, recall 46.0%, F1 0.541, average precision 0.567. It found 69/150 anomalies and flagged 36/999 normal requests, versus 13/150 and 30/999 for Isolation Forest on the same split. | [fur-api-reviewed-examples.json](results/fur-api-reviewed-examples.json) |
| Current detector replay | FUR-API held-out test: precision 39.1%, recall 22.7%, F1 0.287; 34 true positives, 53 false positives. This uses expanded features, graph-enabled model slots (unknown graph context for FUR), and the endpoint-size rule. | [fur-api-enhanced.json](results/fur-api-enhanced.json) |
| Feature comparison | Expanded route, payload, response-size, and latency features. The controlled testbeds report full-model F1 averages of 0.88 without graph context and 0.86 with it; the size rule alone scored 1.0 in-domain. Held-out means were 0 without graph context and 0.144 with inventory context. | [detector-feature-comparison.json](results/detector-feature-comparison.json) |

With passive candidates, the zombie subset scored precision 100% and recall 100% (12/12 endpoints); the shadow subset scored precision 66.7% and recall 100% (6/6). Active-only scanning found all zombies, while shadow recall was 50%. The three false positives were shadow-path findings.

The graph report separates zombie and shadow results and includes per-application findings, scan request counts, and Memgraph spec-ingestion evidence. Run it with the controlled fixtures and a local Memgraph service:

```sh
CGO_ENABLED=0 go build -o evaluation/bin/sentry ./cmd/sentry  # if evaluation/bin/sentry does not exist
python3 evaluation/run_graph_inventory.py --memgraph-uri bolt://127.0.0.1:7688
```

The Isolation Forest report strictly measures that component: graph features and the detector's endpoint-relative size rule are disabled. Reproduce it with:

```sh
python3 evaluation/evaluate_isolation_forest.py
```

FUR-API also provides a small set of labeled anomalies in its training split. The reviewed-label experiment uses those examples to train an Extra Trees classifier, while keeping endpoint baselines normal-only and calibrating the decision threshold on a later normal validation window. Its validation average precision was 0.162 versus 0.013 for Isolation Forest; on the held-out test it reached 0.541 F1 and 0.567 average precision versus 0.135 F1 and 0.273 average precision. It found 69/150 anomalies and flagged 36/999 normal requests. Reproduce it with:

```sh
python3 evaluation/evaluate_reviewed_fur.py
```

The running service can now use reviewed labels. Set `SENTRY_REVIEW_TOKEN`, label requests with `PUT /traffic/{request_id}/review` and `X-Review-Token`, then call `POST /models/retrain`. Labels override automatic predictions during training; after at least 20 reviewed anomalies fall in the training window, retraining selects the Extra Trees model. With fewer examples it keeps the normal-only Isolation Forest. Only eight labeled anomalies remain in this dataset's validation window, so confirm the result on another labeled dataset before presenting it as general performance.

Example review and retrain calls:

```sh
curl -X PUT http://127.0.0.1:5001/traffic/REQUEST_ID/review \
  -H "X-Review-Token: $SENTRY_REVIEW_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"label":"anomaly"}'
curl -X POST http://127.0.0.1:5001/models/retrain \
  -H 'Content-Type: application/json' -d '{"target_fpr":0.05}'
```

These are controlled fixture and dataset results, not evidence of production generalization. The graph testbeds contain API inventory/lifecycle labels, but the current graph does not encode service-to-service call topology, so these measurements do not estimate downstream service risk or blast radius.

## Feature comparison: graph context and endpoint-size rule

`evaluate_isolation_forest.py` measures five FUR-API variants on the same chronological split: Isolation Forest only, graph feature slots with Isolation Forest, endpoint-size rule only, Isolation Forest plus the size rule, and all three enabled. FUR-API supplies no API spec or graph, so graph-enabled FUR runs have unknown graph features; they cannot tell us whether real graph context helps. At a 5% validation FPR, Isolation Forest alone finds 13/150 anomalies with 30 false positives. The endpoint-size rule alone finds 4/150 with 25 false positives; the current detector configuration finds 34/150 with 53 false positives.

The earlier merged-detector FUR report found 1/150 anomalies with 4 false positives at a 1% validation target. The current result finds 34/150, with 53 false positives at a 5% target. This trades more alerts for higher recall; the threshold is configurable and the included report contains the 1%, 2.5%, 5%, and 10% operating points.

The controlled API benchmark provides actual inventory context. Across 15 app/seed runs, the full model averaged F1 0.88 without graph context and 0.86 with it; the size rule alone scored 1.0 because the fixture anomaly is a deliberately oversized response. When each API was held out from training, graph-off F1 averaged 0 and graph-aware F1 averaged 0.144, with wide uncertainty. These small synthetic results suggest graph context may help transfer slightly, but do not establish generalization.

The combined report is regenerated from the FUR evaluation and the controlled benchmark outputs:

```sh
python3 research/benchmark.py --output evaluation/results/graph-inventory-raw --binary evaluation/bin/sentry
python3 evaluation/evaluate_isolation_forest.py
python3 evaluation/replay_fur.py
python3 evaluation/summarize_feature_comparison.py
```

Build `evaluation/bin/sentry` first if it is missing. The benchmark uses five seeds across the three controlled API fixtures and writes intermediate data to the ignored `graph-inventory-raw` directory.

## Current detector result: FUR-API

`replay_fur.py` trains the merged detector using valid normal training requests, then scores valid held-out test requests. It excludes malformed HTTP status rows, uses the chronological train/validation split to calibrate a 5% threshold, and does not tune against test labels.

Run from the repository root:

```sh
python3 evaluation/replay_fur.py
```

Latest enhanced run on the PR architecture (`sentry_revision` is recorded in [fur-api-enhanced.json](results/fur-api-enhanced.json)):

| Measure | Result |
|---|---:|
| Training rows | 19,988 normal requests |
| Test rows | 1,149 (999 normal, 150 anomalous) |
| True positives / false negatives | 34 / 116 |
| True negatives / false positives | 946 / 53 |
| Precision / recall / F1 | 39.1% / 22.7% / 28.7% |
| Specificity / balanced accuracy | 94.7% / 58.7% |
| Prediction throughput | 149.4 events/s |

The expanded detector improves recall, but still misses most labeled anomalies. The 5% threshold yields more false positives than the earlier 1% run. Features now include request shape and attack-pattern markers, response latency and size when supplied, and selected header-name presence. Raw header values are not modeled, and FUR-API still supplies no API graph.

`results/fur-api-pre-pr-architecture.json` preserves the earlier detector result for comparison. That version marked unfamiliar endpoints as anomalies and reached 37.3% recall, but with 47.4% false positives among normal rows. These two reports represent different detector behavior and should not be combined into one score.

## API scans

The saved crAPI, Nicefish, and Train Ticket Station reports are the local API scans run before PR #1 was merged. They document that architecture's findings and the fixes made to reduce false positives. They are historical results, not measurements of the merged scanner.

`run_api.py` has been updated to invoke the merged architecture's `scan-spec` path, which parses a supplied spec and scans a loopback target without requiring Memgraph. Build the current binary, then run it against a locally started target:

```sh
CGO_ENABLED=0 go build -o evaluation/bin/sentry ./cmd/sentry
python3 evaluation/run_api.py \
  --name crapi-current \
  --spec evaluation/upstream/crAPI/openapi-spec/crapi-openapi-spec.json \
  --source evaluation/upstream/crAPI \
  --target http://127.0.0.1:8888 \
  --binary evaluation/bin/sentry
```

The runner rejects non-loopback targets, records the target's initial HTTP status, scan configuration, source commit, spec hash, timing, findings, and a full JSON scan report. The merged scanner's safe default omits mutating probes; use `--allow-mutating` only by invoking `scan-spec` directly against a resettable local target.

| Target | Upstream revision | API operations | Historical probes | Historical findings |
|---|---|---:|---:|---:|
| crAPI | `b5fc307f3e5f875809b095b771108ef342a33724` | 44 | 287 | 6 |
| Nicefish backend | `df2a0a7e00ef157a21dc69487c46edb9956ae96e` | 19 | 61 | 1 |
| Train Ticket station service | `6313886e99befb94be6cd45f085c98e0019f59829` | 20 | 105 | 1 |

Train Ticket's full Compose deployment contains dozens of services; this run covered the station service only. Its Swagger definition needed one schema-name normalization before parsing.

## Other listed datasets

- [FUR-API](https://github.com/yijunL/FUR-API): request-level labeled train/test data, included under `datasets/FUR-API/dataset/` and used by the replay scripts.
- [Vichalana](https://github.com/Vichalana/vichalana-anomaly-benchmark): aggregate host/resource time series without per-request HTTP routes, methods, or response codes. Its CSV data is included under `datasets/vichalana-anomaly-benchmark/`; it is not directly compatible with the current request-level detector.
- [LO2](https://zenodo.org/records/14938118): microservice logs and aggregated metrics. No LO2 files are included. The local sample archive was incomplete, and the full dataset is approximately 450 GB uncompressed.

## Result files

- `results/fur-api-enhanced.json`: current merged-detector evaluation with expanded features.
- `results/isolation-forest-fur-api.json`: current Isolation Forest-only feature and threshold evaluation.
- `results/detector-feature-comparison.json`: FUR-API and controlled-testbed feature comparison.
- `results/fur-api.json`: earlier FUR-API detector evaluation before the feature and threshold changes.
- `results/fur-api-pre-pr-architecture.json`: preserved pre-PR detector evaluation.
- `results/crapi-filtered.json`, `results/nicefish-filtered.json`, and `results/train-ticket-station-final.json`: historical pre-PR API scan summaries.
- `results/*-swagger*.json`: captured or normalized API specifications used by the historical scans.
