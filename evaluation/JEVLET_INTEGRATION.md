# Active Jevlet integration

The Kafka consumer sends each captured event to `POST /jevlet/predict`. Jevlet supplies the behavioral score and decision, while the existing graph inventory rules supply shadow/deprecated observations. Results keep the durable prediction contract, with `model_kind=jevlet` and a content-derived model version. `GET /health` powers the dashboard. Legacy `/predict` and `/models` routes are removed; Isolation Forest code and its registry remain available for offline comparisons.

The initial local checkpoint is the previously trained seed-42 request model with its matching RCAEval service-failure head. It was chosen before the integration test. Security inference uses FP32 on CUDA, with the original normal-calibrated threshold. No test labels or request identities reach the classifier. The score is not an independently calibrated probability of attack. The original numeric preprocessing pickle is retained; no forest estimator runs in this serving path.

The model source and weights are trusted local files. Configure `SENTRY_JEVLET_REPO`, `SENTRY_JEVLET_CHECKPOINT`, and optionally `SENTRY_JEVLET_MODEL_DIR`. An existing registered model takes precedence over the initial checkpoint setting; activate registered versions with `POST /jevlet/models/{id}/activate`. Checkpoints, runtime data and accuracy reports are ignored by Git. Nothing is committed or pushed automatically.

`scripts/integration.sh` also requires these model paths and a suitable Python runtime; a fresh CI checkout does not contain the local trained checkpoint. The full container image and isolated browser integration have not been rebuilt in this local run. The native GPU pipeline, API checks and consumer/dashboard tests were exercised instead.

## Checkpoint setup and activation

Configure `SENTRY_JEVLET_REPO` to a local Jevlet source checkout and
`SENTRY_JEVLET_CHECKPOINT` to a trusted trained checkpoint. Install the base
service requirements and `anomaly-detector/requirements-jevlet.txt` in the
Python environment used by the launcher. Native inference defaults to CUDA.

Use `research/activate_jevlet.py --db PATH --checkpoint PATH --repo PATH` with
the detector stopped, or add `--detector-url http://127.0.0.1:5001` for a
running detector using the same database. Registration validates the model;
activation updates the existing registry and persists across restarts.

The improved local candidate is now active as
`jevlet-8f0fb4b963d40c5e3623`. Its scoped request adapter and nonlinear
service-failure head are documented in [the adaptation report](JEVLET_DOMAIN_ADAPTATION.md).
Scanner, dashboard, graph and storage functionality is unchanged.

## Accuracy evaluation

With the complete local demo running:

```powershell
& C:\Users\Jay\miniconda3\python.exe evaluation/evaluate_live_jevlet.py --db .local-data/app/traffic.db --output .local-data/jevlet-integration/new-run
```

This sends the 1,140 runtime-valid labelled FUR-API test events through actual Kafka, the Go consumer, graph enrichment, Jevlet HTTP inference and SQLite persistence. One invalid status and nine non-absolute paths are excluded explicitly. Truth labels stay in the evaluator. It checks that every result came from the same Jevlet version, and separately evaluates the service-failure HTTP output on held-out RCAEval windows. Omitting `--db` measures the HTTP route directly instead. Results include raw persisted predictions, hashes, confusion counts, precision, recall, F1, accuracy and false-positive rate.

Inventory findings are separate from request-anomaly accuracy. An official held-out-row split with repeated evidence and overlapping dates does not prove future-time or production generalization. The local fixture traffic has no human security labels, so it is used to verify plumbing and scanning rather than claim classifier accuracy.

## Service failures and model updates

`POST /jevlet/service-failure` accepts `{"telemetry_text":"..."}` and returns a separate fault-exposure score when the active checkpoint has a matching failure head. Its inputs must be prepared service telemetry windows; individual Kafka HTTP events do not supply that context. Automatic telemetry aggregation and root-cause identification are not implemented. RCAEval injected-fault labels describe exposure windows, not proof that every request failed.

`POST /jevlet/models/retrain` requires CUDA and reviewed labels, with at least 160 normals and 20 anomalies. It trains from the earlier window, selects using reviewed validation loss, calibrates on later normal data and activates only a successfully loaded checkpoint. Failure retains the previous model. The optional dates must include timezones. Retraining a request encoder invalidates an old failure head, so a newly trained security-only checkpoint reports that service-failure classification is unavailable until a matching head is trained. There is no automatic forest retraining or fallback.

Drift monitoring is not yet implemented. A future monitor should compare incoming request features and scores with a representative reference for each API/version, and separately track model performance after reviewed labels arrive. A distribution change is a warning, not proof of concept drift. Retesting, threshold calibration and reviewed retraining should follow a confirmed performance decline; incoming predictions must not become their own truth labels.
