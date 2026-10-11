# Jevlet accuracy investigation and local improvements

Measured locally on 11 October 2026. Both new heads trained on the NVIDIA RTX 4060 Laptop GPU. No commit, push or main-demo model activation was performed.

## What caused the low accuracy

1. **Application shift and scarce labels.** The original FUR-API training partition contained only 42 labelled attack examples. None of the 120 station or 160 crAPI diagnostic requests matched its known training endpoints. Their normal requests, bodies and responses differ from the FUR traffic.
2. **The threshold did not transfer.** Its fixed 0.006829 threshold was calibrated on FUR normal traffic. Calibrating that same original classifier on fresh local normal traffic raises crAPI accuracy to 75%, but detects only 5/30 labelled attempts. Raising the threshold alone therefore loses too many attacks.
3. **Response and timing context can distract request classification.** The original input contains response bodies, status, latency and baseline size changes. The new request head excludes these and learns from request method, path, query and body. This prevents response errors and collection timing from serving as label shortcuts. The experiment changes both representation and training data, so it does not quantify their separate contributions.
4. **Ownership context is absent.** A valid vehicle identifier does not reveal whether the authenticated caller owns it. After identifier normalization, the own-vehicle and cross-account request inputs in the fresh test are identical. A request-only classifier cannot distinguish them without trusted identity/ownership evidence.
5. **The failure head was restrictive.** Its original linear classifier detected 19/42 Train Ticket fault-exposed windows. A small nonlinear head, chosen by validation loss, detects 22/42 at a separately calibrated normal-data threshold.

Context truncation was checked: none of the previous 280 diagnostic requests was truncated. These tests do not identify Windows or GPU availability as a cause of the low accuracy.

## Fresh held-out request results: before and after

The baseline and candidate scored the same fresh captured requests. Training/selection and test injection templates differ. Normal routes recur across splits. The combined candidate was then run through actual Kafka, the production Go consumer, graph enrichment, the Jevlet HTTP backend and SQLite.

| Scope | Requests | Baseline accuracy | Improved accuracy | Baseline TP / FP / FN / TN | Improved TP / FP / FN / TN |
|---|---:|---:|---:|---|---|
| Train Ticket station | 80 | 86.25% | 97.50% | 10 / 1 / 10 / 59 | 20 / 2 / 0 / 58 |
| crAPI including ownership checks | 100 | 45.00% | 87.00% | 15 / 40 / 15 / 30 | 20 / 3 / 10 / 67 |

TP = detected attempts; FP = false alarms; FN = missed attempts; TN = correctly accepted normal requests.

Station attack recall improved from 50% to 100%; false alarms increased from 1/60 to 2/60 on this fresh workload. crAPI overall recall improved from 50% to 66.67%; false alarms fell from 40/70 to 3/70.

The crAPI request-content subgroup, excluding the 20 ownership checks, improved from 40% to 96.25% accuracy: 20/20 injection attempts detected, with 3/60 normal false alarms. Both applications supplied only ten distinct held-out injection templates, each repeated twice. The 20 attempts per application are not 20 independent attack types.

**Ownership limitation and regression:** the adapted request head accepted all ten owner controls and missed all ten cross-account reads. The original model flagged all ten cross-account reads but also seven owner controls in this fresh test. Overall crAPI accuracy includes every ownership miss; the larger request-content figure must not be used as total crAPI accuracy. Fresh cross-account responses returned a different test owner name, and all twenty ownership responses were HTTP 200. Distinct owner names and identical model-visible request inputs are recorded in evidence-audit.json.

## Previously inspected diagnostic traffic

These older requests were used to investigate errors, not fitted by the adapter. Because the workload was already inspected, the following retests are diagnostic results, not a newly blind evaluation.

| Previous workload | Previous accuracy | Adapted checkpoint retest | False alarms before → after |
|---|---:|---:|---:|
| Train Ticket station, 120 records | 52.50% | 100.00% | 24 → 0 |
| crAPI, 160 records including ownership | 65.00% | 87.50% | 44 → 0 |

The crAPI retest still missed all twenty cross-account reads. No verified ownership detector has been implemented.

## Separate service-failure results

The nonlinear head uses frozen Jevlet CLS/context-mean features, followed by 1536 → 64 → 2 layers. Whole incidents remain separate across training, selection, calibration and test. Application/class weights reduce dominance by a single application. The head was selected using validation loss: 0.2901 for the old head versus 0.2354 for the new head. The test labels did not select the head or its threshold.

| Failure workload | Windows / incidents | Accuracy before → after | Recall before → after | Detected faults before → after | False alarms |
|---|---|---:|---:|---:|---:|
| Train Ticket | 75 / 3 | 69.33% → 73.33% | 45.24% → 52.38% | 19/42 → 22/42 | 0/33 → 0/33 |
| All three RCAEval applications | 189 / 9 | 76.19% → 78.84% | 58.33% → 62.96% | 63/108 → 68/108 | 0/81 → 0/81 |

The Train Ticket result was freshly verified through the backend service-failure endpoint. These are previously inspected held-out incidents, not new failure data. Windows within an incident are correlated, and their labels indicate exposure to an injected fault rather than proof that every request failed. The new head still misses 20/42 Train Ticket fault-exposed windows. No labelled crAPI service-failure test was available.

## Training and calibration

- Request adaptation: 360 training records, 136 selection records, 192 normal calibration records, 180 test records. Training contains 143 distinct model-visible request inputs, including 60 attack inputs. Test contains 76 distinct inputs, including 21 labelled attack inputs; the extra attack input is the ownership request also shared by its normal control.
- Request architecture: frozen Jevlet encoder → CLS and context-mean features → 1536 → 128 → 2 head. Seed 42; dropout 0.1; CUDA AdamW. Normalization is fitted on training features. Balanced validation loss across applications/classes chooses the epoch.
- Request thresholds target 5% false positives on 96 separate calibration normals per application: station 0.0002147777, crAPI 0.0610144585. Test labels were not used for thresholds.
- Scope is explicit: /api/v1/stationservice/ for station, and /identity/, /community/, /workshop/ for crAPI. Other paths use the original Jevlet request head and threshold. The gains do not establish accuracy on arbitrary websites.
- Failure fitting: 1,125 windows from 54 incidents; selection 375/18; calibration 187/9; test 189/9. The failure threshold is 0.7788046598, targeting 5% false positives on normal calibration windows.
- Encoder weights stay frozen. Head training took approximately 0.52 seconds for request adaptation and 0.85 seconds for failure adaptation, excluding feature extraction, loading, capture and evaluation. This is head training, not a full encoder retrain.
- CPU preparation and metrics are separate from CUDA feature extraction and model training. No training fell back to CPU.

## Regression checks and backend verification

- FUR-API: all 1,149 valid-status official test records were freshly scored by both original and adapted request models. Scores and decisions were identical: 92.43% accuracy, 120 TP, 57 FP, 30 FN and 942 TN. One invalid-status row was excluded. This larger offline set differs from the earlier 1,140-event backend-valid subset, which gave 92.46%.
- The final combined checkpoint retains byte-identical original encoder, original models.json and baseline.pkl, and byte-identical validated request-adapter files. The improved failure head is the intentional additional change.
- All 180 fresh request records were acknowledged by Kafka and durably evaluated in the isolated SQLite database. All graph contexts resolved; zero inventory alerts. Every backend decision matched the saved adapter decision. Maximum score drift from batch versus single-event CUDA execution was approximately 0.0000034.
- All 75 Train Ticket failure windows were freshly scored through the final combined backend. Request decisions stayed unchanged while the improved failure head was available.
- 21 affected tests passed. The initial sandbox-only API test run stalled; running the same tests with local execution permissions completed successfully. A temporary report serialization error was corrected and regression checks rerun.
- The isolated test backend and Go consumer were stopped after verification. Evaluation containers were stopped afterward; original Sentry dependency containers were retained. The candidate was registered only in its isolated test database. Main model activation was not changed.

## Files and reproduction

- evaluation/jevlet_request_adapter.py: bounded request serializer, frozen feature extraction, request head and scoped checkpoint loader.
- evaluation/adapt_jevlet_requests.py: audited data splits, CUDA training, validation selection, normal-only calibration and held-out reporting.
- evaluation/local_models.py: optional adapter routing, per-application threshold and original-model fallback.
- anomaly-detector/jevlet_service.py: includes adapter weights and configuration in model identity, preventing silent changes to an activated checkpoint.
- evaluation/jevlet_failures.py: backward-compatible loading for both the old linear head and the new nonlinear head.
- evaluation/adapt_jevlet_failures.py: whole-incident checks, CUDA failure-head adaptation and independent calibration.
- tests/test_jevlet_request_adapter.py and tests/test_jevlet_service.py: evidence exclusion, scope/fallback behavior, encoder compatibility and immutable checkpoint identity.

Final tested candidate: `E:\clg\fyp\Sentry\.local-data\api-evaluation\adaptation-20261011\failure-run-42\checkpoint`
Candidate version: `jevlet-8f0fb4b963d40c5e3623`

Local evidence under .local-data/api-evaluation/adaptation-20261011:
- protocol.json, data.json: fixed workload protocol and raw captured exchanges; labelled evaluator metadata is separate from events sent to Kafka.
- run-42/: request-head training, before/after test predictions, calibration-only comparison, evidence audit and FUR/failure regression checks.
- failure-run-42/: combined checkpoint, failure-head training, all failure test predictions, final pipeline report, SQLite predictions, logs and file-hash verification.json.
- ../capture_adaptation.py, ../verify_adaptation.py, ../replay_adaptation.py: local capture and independent checks. replay_adaptation.py --combined uses an isolated database and temporary backend.

Checkpoint weights, target source checkouts, labelled captures and evaluation databases remain local and ignored by Git. Isolation Forest source remains intact. No endpoint was restored to Isolation Forest.

## Remaining work

The request gains are limited to small generated workloads on known applications. Wider unseen endpoints, payload families, benign text resembling attack syntax and real production traffic require separate validation. Ownership detection needs a trusted authenticated caller and resource-access relationship from the gateway or application; adding the evaluator's ownership labels to model inputs would be leakage. Service-failure recall remains limited, and automatic telemetry window aggregation and drift monitoring have not been added by this change.

## Activation after review

Following user approval, the combined candidate was copied to the stable local
directory `.local-data/jevlet-models/jevlet-8f0fb4b963d40c5e3623`, with every
runtime file checked against the evaluated artifact hashes. The main model
registry now activates `jevlet-8f0fb4b963d40c5e3623` across restarts.

The existing local system was started with CUDA FP32 inference. Dashboard
health and the latest 100 persisted Kafka predictions confirmed the active
version. Sample normal/injection requests exercised both application adapters;
the matching nonlinear service-failure head was also checked through its live
endpoint. Local activation evidence is in
`.local-data/jevlet-models/live-activation-verification.json`.

Scanner strategies, dashboard behaviour, graph inventory, storage schemas,
Kafka retry/offset handling and the retained Isolation Forest source are
unchanged. The earlier evaluation sections describe the model before this
activation; their data partitions and accuracy figures have not been revised.
