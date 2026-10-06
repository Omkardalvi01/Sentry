# Research protocol

Research question: does specification context plus passive discovery plus active verification improve inventory-discrepancy detection at a fixed scan configuration?

Run `./research/run.sh` from the repository root. The default seeds are 11, 22, 33, 44, and 55. Each of three local HTTP applications contributes 320 collected events per seed: 160 training, 40 validation, and 120 held-out test events. Labels live in a separate JSONL file and never enter model features. Specifications are prior inventory knowledge, not labels inferred from test outcomes.

Active variants share a total budget of 250 requests (including baselines), five workers, and 1,000 requests/second. Actual request counts are reported; unused budget is not filled with meaningless probes.

Each run records specs, ground truth, traffic events, model metadata, scanner reports, false positives, CSV metrics, configuration metadata, and SVG/PNG plots under `research/results/`. The scanner binary digest identifies the implementation. Dependency locks include hashes. Fixture state can be reset through `POST /__reset`; every benchmark run starts fresh server instances on ephemeral ports.

## Comparisons

Inventory detection compares a status-only decision rule, passive inventory comparison, improved active scanning, and the full passive-to-active hybrid. Ablations remove schema evidence, catch-all suppression, or passive candidates. All operations not enumerated as positive in the truth manifest are negative under this controlled benchmark definition, including the intentionally available documentation route. Endpoint positives are actionable inventory/lifecycle discrepancies; authentication exposure is reported separately. Low-confidence response-mismatch candidates are excluded from verified inventory metrics, but retained in raw reports.

The status-only comparator uses observed responses for the same test operations and does not claim a discovery capability or comparable request cost. Passive-only findings are candidates; precision uses the same endpoint truth to evaluate whether those candidates are actionable. Fixed shadow guesses can surface additional routes, and those false positives count.

Behavioral evaluation compares robust body-size checks with Isolation Forest, traffic versus inventory features, Isolation Forest alone, and removal of ML. It measures behavioral labels only; inventory alerts do not inflate behavioral metrics. Leave-one-application-out models train and calibrate solely on the other two applications.

## Metrics and limits

Endpoint metrics: precision, recall, F1, false positives, false negatives, total scanner request count, and scan duration. Scan duration is an upper bound for batch verification delay, not a measured Kafka alert delay.

Event metrics: precision, recall, F1, PR-AUC, local inference p50/p95 latency and throughput. `max_rss_kib` is the peak memory of the entire Python benchmark process; it is not isolated detector service memory.

95% intervals use 2,000 bootstrap resamples of application/seed F1 values with seed 42. The fixtures reuse scenario structure, so these intervals summarize fixture repetition, not independent real-world population uncertainty. Degenerate intervals are expected when inventory scenarios do not vary between seeds.

This is an initial reproducible benchmark, not a sufficient standalone production study. The applications share routes and logic. Synthetic anomalous payloads are extreme, which can make in-application results optimistic. Held-out application results must remain in the paper even when worse. Add independent applications and realistic authorized traces before making broad claims.

## Supplementary ZAP comparison

Run the published ZAP API-scan image against each fixture specification and retain its JSON report. Compare only overlapping inventory/authentication evidence and report unsupported categories as unsupported. Do not compare total vulnerability counts to Sentry's inventory findings. ZAP is supplementary; the reproducible within-system baselines isolate the proposed fusion method more directly.

## Live integration

`./scripts/integration.sh` starts disposable services, builds Sentry, checks the scoped live graph, replays collected events through Kafka, evaluates them through the real Python API, verifies passive-to-active findings, checks a zero-request dry run, reopens dashboard history, and checks duplicate replay. Chromium validates desktop/mobile rendering, real scan submission, and evidence dialogs. It uses ports 7689, 19093, 6389, 5009, and 8099 and never touches the main Compose volumes.

The executable supplementary runner is `./research/zap.sh SPEC_FILE TARGET_BASE_URL`. It writes ZAP's original JSON and HTML reports; ZAP's nonzero alert exit code is preserved. The reported evaluation tables do not claim this external run has been completed.
