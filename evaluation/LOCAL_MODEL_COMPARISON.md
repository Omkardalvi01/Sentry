# Local comparison: Jevlet, Isolation Forest, and CatBoost

This experiment fits three interchangeable event scorers without changing the
running detector or its database. It uses the included FUR-API request dataset.
No command in this workflow commits or pushes changes.

## What is compared

- **Isolation Forest:** normal-only learning using Sentry's current numerical
  features. The endpoint-size alert rule and graph inventory alerts are disabled.
- **CatBoost:** the same numerical features and normal-only endpoint baselines,
  trained with labelled normal/anomaly examples and balanced class weights.
- **Jevlet:** its actual shared encoder and choice head, initialized from cached
  pretrained DistilBERT and trained for `normal` versus `anomalous`. Inputs contain
  request/response evidence and endpoint-relative size/latency changes. Banking
  and sentiment task checkpoints are not used for security training.

Jevlet uses bounded text while the other two use numerical features. This is a
comparison of practical detector candidates, not an experiment holding the input
representation identical. All see evidence from the same request rows.

The CSV files only contain binary labels. They cannot support an honest score
for individual attack categories. An anomaly label also does not establish a
verified vulnerability.

## Data separation

The later 20% of normal training timestamps is reserved for threshold
calibration, keeping boundary minutes intact. The earlier window is split 80/20
into training and checkpoint selection with a fixed stratified seed of 42.
Stratification is needed because a purely chronological selection slice has no
anomalies. With the currently included dataset:

| Partition | Normal | Anomalous |
|---|---:|---:|
| Training | 12,762 | 42 |
| Checkpoint selection | 3,191 | 10 |
| Calibration | 4,035 | 8 |
| Official held-out test | 999 | 150 |

The eight calibration anomalies are not used to set thresholds. Each threshold
targets at most 5% false alarms on the normal calibration rows. Test labels never
choose the checkpoint or threshold. The source's official test timestamps
overlap the training dates; this is not a future-time generalization test.

Jevlet draws 4,096 balanced training samples per epoch for six epochs. This
oversamples scarce training anomalies and does not create new independent attack
examples. CatBoost uses class weights; Isolation Forest sees normal rows only.
The three model seeds are 42, 43, and 44, with identical partitions in every run.

## Run on Windows

Use a Python environment with `torch`, `transformers`, `scikit-learn`, `catboost`,
`numpy`, `psutil`, `safetensors`, `datasets`, and `matplotlib`. The existing local
Conda Python has these dependencies and CUDA support. The cached base encoder
must exist in the Jevlet repository's `.cache/huggingface` directory; loading is
offline by default.

```powershell
cd E:\clg\fyp\Sentry
$env:PYTHONUTF8 = '1'
& C:\Users\Jay\miniconda3\python.exe evaluation\compare_local_models.py `
  --jevlet-repo E:\clg\DL\mini_proj\jevlet `
  --output .local-data\model-comparison\my-run `
  --training-device cuda `
  --seeds 42 43 44
```

GPU training is now the default; `--training-device cuda` makes it explicit.
This uses an experimental PyTorch implementation of Isolation Forest, which
is evaluated separately from the existing scikit-learn estimator. CatBoost
uses its supported GPU training mode and Jevlet uses CUDA. CSV processing
and normal-baseline statistics still run on CPU. GPU mode fails explicitly
if CUDA is unavailable; it does not silently switch model training to CPU.
The earlier scikit-learn/CPU tree comparison remains available with
`--training-device mixed`.

An already completed matching Jevlet CUDA run can be reused with
`--reuse-completed-jevlet PATH`. Only checkpoints with matching data hashes,
partitions, sequence length, sample counts, and completed epochs are reused.

Choose a fresh output directory for each run. Existing results are protected
against accidental overwrite. GPU availability is detected automatically for
Jevlet training; the CPU is used otherwise. Single-request latency is measured
on CPU for all models, including input preparation. Batch scoring uses the
available device and is reported separately.

## Results and reuse

Each run saves `REPORT.md`, `comparison.json`, `comparison.csv`, dataset hashes,
partition details, per-request predictions, and per-seed model checkpoints.
Everything under `.local-data/` is ignored by Git. The implementation and its
tests remain ordinary uncommitted source files for local review.

Finish a run with `python evaluation/summarize_local_comparison.py RUN_DIRECTORY
--benchmark-cpu` to audit saved predictions, measure all single-request CPU
timings with four PyTorch threads, and render the comparison chart.

Load any fitted model through `LocalDetector.load(...)`, or score an existing
event JSON file using:

```powershell
& C:\Users\Jay\miniconda3\python.exe evaluation\compare_local_models.py `
  --predict-event .local-data\model-comparison\example-event.json `
  --model jevlet `
  --checkpoint .local-data\model-comparison\my-run\seed-42 `
  --jevlet-repo E:\clg\DL\mini_proj\jevlet
```

`--model` also accepts `catboost` and `isolation_forest`. Pickle checkpoints must
only be loaded from this trusted local workflow. The scorer returns the model,
anomaly score, threshold, and anomaly decision; it does not activate the model
in the Sentry service.

Compare precision, recall, F1, average precision, missed anomalies, false alarms,
CPU latency, training time, and checkpoint size. Process memory measurements
come from a shared process and cannot be treated as isolated per-model memory.
Classifier scores are model outputs, not calibrated estimates of real-world
security risk. The alert threshold is selected from normal calibration traffic.
Confirm any winner on another independently labelled dataset before replacing
the running detector.

## Implementation references

- [Original Isolation Forest paper](https://cs.nju.edu.cn/zhouzh/zhouzh.files/publication/icdm08b.pdf): isolation-tree construction and expected-path-length anomaly score.
- [CatBoost GPU training](https://catboost.ai/docs/en/features/training-on-gpu): supported GPU settings and the floating-point nondeterminism of GPU training.
- [scikit-learn Isolation Forest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html): existing Sentry baseline implementation.
