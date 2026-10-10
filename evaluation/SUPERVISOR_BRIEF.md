# Sentry Evaluation Brief

## Executive summary

Sentry has two evaluated detection paths: request-behavior anomaly detection and graph-backed API inventory detection. Each performs well on some measured cases, but the results come from different datasets and should be reported separately. A small controlled benchmark also measured both behavior features and graph context together; it does not yet establish a general end-to-end production score.

| Mode | Evaluation set | Main result |
|---|---|---|
| API behavior only | FUR-API held-out request traces | Reviewed-label Extra Trees: **F1 0.541**, precision 65.7%, recall 46.0%; 69/150 anomalies found, 36 false positives among 999 normal requests. |
| Graph inventory only | Three controlled local APIs | Graph inventory plus passive candidates: **F1 0.923**, precision 85.7%, recall 100%; 18 true positives, 3 false positives, no misses. |
| Combined graph context and behavior | Controlled API fixtures, five seeds | In-domain mean F1: **0.860** with graph context versus 0.880 without; held-out-app F1: **0.144** with inventory context versus 0 without. Results are synthetic and have wide uncertainty. |

## Data used

| Data | Contents and size | Used for |
|---|---|---|
| [FUR-API](https://github.com/yijunL/FUR-API) | Request-level HTTP traces with normal/anomaly labels. Raw `train.csv`: 20,060 rows (20,000 normal, 60 anomalous); raw `test.csv`: 1,150 rows (1,000 normal, 150 anomalous). Invalid HTTP status rows were excluded, leaving 20,048 train and 1,149 test rows. | API-only behavior results. The reviewed classifier used 15,953 normal and 52 anomalous training examples; validation had 4,035 normal and 8 anomalous examples; held-out test had 999 normal and 150 anomalous examples. |
| Controlled graph inventory APIs | Three resettable local fixtures: `resource`, `versioned`, and `gateway`. Each has a 12-operation OpenAPI spec and six labeled inventory discrepancies (four zombies and two shadows), plus negative endpoints. | Graph-only active scans, then graph inventory checks supplemented with observed passive candidates. The passive candidates come from held-out fixture traffic. |
| Controlled behavior testbeds | The same three local API fixtures, with 320 generated request records per app and seed over five seeds (4,800 generated records total). Each run uses 160 train, 40 validation, and 120 test records. | Combined graph-context and behavior ablation. The behavioral attack is a `payload=large` request that causes a 100 KB response and HTTP 500. |

The latest crAPI, Nicefish, and Train Ticket code scans are historical pre-architecture results; they are not part of the headline graph or behavior metrics above. Vichalana data is host/resource telemetry rather than request-level API traffic, and the downloaded LO2 archive was incomplete, so neither contributes to these figures.

## 1. API behavior only

This measures whether request/response behavior is anomalous. FUR-API provides labeled traffic but no API specification or service topology, so this section uses no graph evidence.

The strongest measured setting uses 52 labeled anomalies from the FUR-API training period to train an Extra Trees classifier. Its decision threshold is calibrated on a later normal-only validation period at a 5% target false-positive rate. On 1,149 held-out requests (999 normal, 150 anomalous), it achieved:

- **69 true positives**, 81 false negatives, 36 false positives, and 963 true negatives.
- **Precision 65.7%, recall 46.0%, F1 0.541**, average precision 0.567.
- Isolation Forest alone on the same split found 13 anomalies, with 30 false positives: F1 0.135 and average precision 0.273.

The normal-only current detector replay found 34 anomalies with 53 false positives (F1 0.287). That run includes the endpoint-size rule and expanded features; its graph slots are unknown on FUR-API. The reviewed-label result is the best measured request detector, but needs confirmed incident labels to train. Only eight labeled anomalies appear in its validation window, so more independent validation is needed.

Reports: [reviewed-label result](results/fur-api-reviewed-examples.json), [Isolation Forest baseline](results/isolation-forest-fur-api.json), [normal-only detector replay](results/fur-api-enhanced.json).

## 2. Graph inventory only

This evaluates API lifecycle/inventory discrepancies on three controlled local API fixtures. A graph built from each API specification is compared with active scan results and observed passive traffic.

| Mode | Precision | Recall | F1 | Counts |
|---|---:|---:|---:|---|
| Graph-backed active scan | 83.3% | 83.3% | 0.833 | 15 TP, 3 FP, 3 FN; 594 probes |
| Graph plus passive inventory candidates | 85.7% | 100% | 0.923 | 18 TP, 3 FP, 0 FN; 612 probes |

Zombie API results were 12/12 found with no false positives. Shadow API recall rose from 3/6 in active-only scanning to 6/6 when passive candidates were included; shadow precision was 66.7%, with the three false positives all in this category.

This is a controlled fixture result. Passive candidates were taken from held-out fixture traffic, so it measures verifying observed candidates, not discovering arbitrary hidden APIs. The graph currently models API specifications and operations; this experiment does not measure downstream service risk or blast radius.

Report: [graph inventory result](results/zombie-shadow-graph.json).

## 3. Both: graph context and behavior

The controlled feature benchmark combines behavior scoring with graph/inventory context across 15 app/seed runs (three fixtures, five seeds):

- In-domain mean F1 was **0.880** for traffic behavior and **0.860** for inventory-aware behavior.
- When an application was held out from training, mean F1 was **0.000** without inventory context and **0.144** with it; held-out precision and recall with context were 12.2% and 20.0%.
- The synthetic anomaly was a 100 KB response on an otherwise normal endpoint. The endpoint-size rule alone scored F1 1.0 in-domain because the fixture was designed around that signal.

The results show that both paths can be exercised together, but graph features did not improve in-domain F1 and held-out performance remained weak. FUR-API has no graph topology, while the graph fixtures do not contain representative labeled behavioral attacks. **There is no single combined F1 for the full system that is supported by a shared, representative ground-truth dataset.** Do not add or average the API and graph F1 values.

Report: [controlled feature comparison](results/detector-feature-comparison.json).

## Points to tell the supervisor

1. **The strongest behavioral result requires reviewed examples:** FUR-API’s label-aware detector raises held-out F1 from 0.135 for Isolation Forest to 0.541, finding 69 rather than 13 of 150 attacks, with 36 rather than 30 false alarms.
2. **Passive traffic improves graph inventory recall:** on the three controlled APIs, graph plus passive candidates found all labeled zombies and shadows (18/18), with three false shadow candidates.
3. **Generalization is the main open issue:** the combined held-out fixture score is only F1 0.144, and the current benchmark is synthetic. Real independent APIs and labeled operational traffic are needed before claiming deployment accuracy.
4. **Present API and graph results separately:** their labels and test sets differ. The project has a combined pipeline, but no fair shared end-to-end score yet.

## Suggested spoken summary

> “On FUR-API, using 52 reviewed attack examples improved request anomaly F1 from 0.135 to 0.541 on a held-out test set, finding 69 of 150 attacks with 36 false alarms among 999 normal requests. Separately, graph inventory plus passive traffic found all 18 zombie and shadow endpoints across three controlled APIs, with three false positives. The combined benchmark is still synthetic and generalizes weakly to an unseen fixture, so we are treating these as promising component results rather than production accuracy.”

## Reproduction

```sh
python3 evaluation/evaluate_reviewed_fur.py
python3 evaluation/evaluate_isolation_forest.py
python3 evaluation/replay_fur.py
python3 evaluation/summarize_feature_comparison.py
```

The graph inventory report is reproduced using the controlled fixtures and a local Memgraph instance; see [the evaluation guide](README.md) for its command. Reports include their split protocol and limitations.
