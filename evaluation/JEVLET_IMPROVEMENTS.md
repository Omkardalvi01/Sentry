# Jevlet: more data and faster prediction

The existing request-anomaly experiment uses FUR-API. The additional local
experiment adds a separate service-failure classifier using RCAEval RE3. These
are different tasks: a service failure does not establish a malicious request.

## Data sources reviewed

| Source | Useful task | Local use |
|---|---|---|
| [APISENSOR](https://arxiv.org/html/2603.23852v1) | API endpoint discovery and robustness to mixed traffic | Paper reviewed. It promises a replication package; no downloadable dataset was found in the paper or author sources checked. Its endpoint annotations are not attack labels. |
| [RCAEval](https://zenodo.org/records/14590730) | Service-failure detection and root-cause evaluation | Downloaded RE3 logs and metrics for all 90 code-fault incidents using the [author-maintained Parquet mirror](https://huggingface.co/datasets/phamquiluan/RCAEval), pinned to revision `afeacb11bcc94dadfd1c8f483ee4377b2b8b614e`. |
| [FastFI](https://github.com/TanYuzhen/TOSEM-FastFI-Code) | Fault-injection scenarios and resilience testing | Repository inventory and an example published log reviewed. The inspected log lists service injection plans, rather than labelled HTTP request/response examples. Generating new runtime examples would require deploying its benchmark infrastructure and collecting telemetry. |

RCAEval preparation downloaded approximately 85 MB, not the complete archive.
The source files, revision, and SHA-256 hashes are recorded locally. External
benchmark scripts were not executed.

## Added capability

The failure classifier uses Jevlet's frozen text encoder, with a separate
trainable classifier. Encoder feature extraction and classifier training run
on CUDA. The original request detector weights and threshold are copied
unchanged, so the new task does not overwrite its learned behavior.

Training uses 1,125 telemetry windows from 54 incidents. Checkpoint selection
uses 18 incidents, normal-only threshold calibration uses nine, and the final
test uses nine separate incidents: 81 normal and 108 fault-exposed windows.
Every window from an incident stays in one partition. Exact duplicate and
ambiguous evidence is removed. Three classifier seeds are evaluated.

Windows summarize 60 seconds of logs and metric departures from an earlier
three-minute normal baseline. Fault timestamps are used only to assign labels
and exclude transition windows. Case names, fault types, injection timestamps,
and root-cause annotations are excluded from model text.

These are labels of exposure to a synthetic code fault. They do not establish
that every request in the window failed. The test contains familiar application
types, and windows from an incident are correlated. Additional real incidents
and an unseen-application test are needed for stronger evidence.

The local wrapper `JevletWithFailures.load(...)` offers request-anomaly
prediction and service-window prediction as separate outputs. A telemetry
window must be supplied for the latter. This experiment does not activate a
model or install a telemetry aggregator in the running Sentry service.

## Prediction speed

The original approximately 70 ms request benchmark was on CPU. A new warmed
GPU experiment checks all 1,149 request examples for each of three existing
checkpoints, using their original alert thresholds:

| Request prediction mode | Mean seed median latency | Classification result |
|---|---:|---|
| GPU FP32 | 10.96 ms/request | Reference decisions reproduced |
| GPU FP16 | 4.63 ms/request | Three changed decisions across 3,447 comparisons; mean F1 rounds to 0.748 for both modes |
| GPU FP16, batches of 16 | 33.63 ms/batch; 2.08 ms/event processing average | Same three changed decisions |

Batch processing time per event describes throughput; it is not an individual
request's response time. Queue delay is excluded. Models are loaded once and
warmed, and the timings include event preparation and device transfers. The
service-window task has its own latency measurement and longer inputs.

Reduced precision is available as an opt-in experiment on the local failure
wrapper, using `fp16=True`. Recalibrate thresholds using normal calibration
traffic and recheck decisions before adopting a changed inference precision.
The [PyTorch inference API](https://docs.pytorch.org/docs/stable/generated/torch.autograd.grad_mode.inference_mode.html)
was already used by the original predictor. An additional future option is
[ONNX Runtime transformer optimization](https://onnxruntime.ai/docs/performance/transformers-optimization.html);
it has not been benchmarked here.

## Reproduce locally

Use the existing CUDA-capable Conda environment. Choose new output paths to
preserve completed runs. No command commits or pushes changes.

```powershell
cd E:\clg\fyp\Sentry
$env:PYTHONUTF8 = '1'
$env:HF_HOME = 'E:\clg\DL\mini_proj\jevlet\.cache\huggingface'
& C:\Users\Jay\miniconda3\python.exe evaluation\benchmark_jevlet_inference.py `
  --run .local-data\model-comparison\gpu-20261011 `
  --output .local-data\model-comparison\new-speed-run

& C:\Users\Jay\miniconda3\python.exe evaluation\prepare_jevlet_failures.py `
  --data .local-data\external-datasets\RCAEval-afeacb11 `
  --output .local-data\external-dataset-review\new-failure-windows.json

& C:\Users\Jay\miniconda3\python.exe evaluation\jevlet_failures.py `
  --data .local-data\external-dataset-review\new-failure-windows.json `
  --security-checkpoint .local-data\model-comparison\gpu-20261011\seed-42 `
  --output .local-data\model-comparison\new-failure-run
```

Completed reports are under `.local-data/model-comparison/inference-20261011-v2`
and `.local-data/model-comparison/jevlet-failures-20261011`. Source downloads,
generated windows, checkpoints and results stay in Git-ignored local storage.
Only trusted locally generated pickle checkpoints should be loaded.

For better request classification, the current bottleneck remains the 42
distinct anomaly examples in the FUR-API training partition. RCAEval adds
failure examples to the new task; it does not solve that attack-label shortage.
Further request training needs independently labelled request evidence,
reviewed false alarms and missed anomalies, and a new untouched final test.
