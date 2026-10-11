"""Train and compare Isolation Forest, CatBoost, and Jevlet on local FUR-API.

Never connects to a target API or pushes to Git. All models use the same
chronological partitions and official held-out test. Output is ignored by Git.
"""

import argparse
from collections import Counter
import csv
import datetime as dt
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import pickle
import subprocess
import sys
import time

os.environ.setdefault('USE_TF', '0')
os.environ.setdefault('TOKENIZERS_PARALLELISM', 'false')
os.environ.setdefault('HF_HUB_OFFLINE', '1')
os.environ.setdefault('TRANSFORMERS_OFFLINE', '1')

import numpy as np
from sklearn.metrics import (accuracy_score, average_precision_score,
                             balanced_accuracy_score, confusion_matrix,
                             precision_recall_fscore_support, roc_auc_score)
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'anomaly-detector'))
from detector import fit_model  # noqa: E402
from replay_fur import event_from_row, valid_status  # noqa: E402
from local_models import LocalDetector, event_text, matrix, normal_baseline, questions, threshold_at_fpr  # noqa: E402


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n', encoding='utf-8')


def timestamp(row):
    return dt.datetime.strptime(row['timestamp'].strip(), '%Y/%m/%d %H:%M')


def read_rows(path):
    with Path(path).open(newline='', encoding='utf-8-sig') as stream:
        original = list(csv.DictReader(stream))
    if {r['type'].strip() for r in original} != {'normal', 'anomaly'}:
        raise ValueError('Expected normal/anomaly labels')
    return [r for r in original if valid_status(r)], sum(not valid_status(r) for r in original)


def split_rows(rows):
    """Later normal window calibrates thresholds; earlier labels select models."""
    rows = sorted(rows, key=timestamp)
    normal = [r for r in rows if r['type'].strip() == 'normal']
    boundary = timestamp(normal[int(len(normal) * 0.8)])
    earlier, calibration = [], []
    for row in rows:
        (earlier if timestamp(row) < boundary else calibration).append(row)
    training, selection = train_test_split(earlier, test_size=0.2, random_state=42,
                                           stratify=[r['type'].strip() for r in earlier])
    parts = {'train': sorted(training, key=timestamp), 'selection': sorted(selection, key=timestamp),
             'calibration': calibration}
    if not all(parts.values()):
        raise ValueError('Chronological split has an empty partition')
    return parts


def labels(rows):
    return np.asarray([r['type'].strip() == 'anomaly' for r in rows])


def metrics(y, scores, threshold):
    prediction = np.asarray(scores) >= threshold
    tn, fp, fn, tp = confusion_matrix(y, prediction, labels=[False, True]).ravel()
    precision, recall, f1, _ = precision_recall_fscore_support(y, prediction, average='binary', zero_division=0)
    return {'accuracy': float(accuracy_score(y, prediction)),
            'balanced_accuracy': float(balanced_accuracy_score(y, prediction)),
            'precision': float(precision), 'recall': float(recall), 'f1': float(f1),
            'average_precision': float(average_precision_score(y, scores)),
            'roc_auc': float(roc_auc_score(y, scores)),
            'true_positive': int(tp), 'false_positive': int(fp),
            'true_negative': int(tn), 'false_negative': int(fn),
            'false_positive_rate': float(fp / (fp + tn)), 'threshold': float(threshold)}


def evidence_key(event):
    # Timestamp/identity are excluded because they are not text evidence.
    values = {k: v for k, v in event.items() if k not in ('request_id', 'timestamp', 'client_id')}
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


def prepare(args):
    train_path, test_path = (args.source / 'dataset' / name for name in ('train.csv', 'test.csv'))
    rows, excluded_train = read_rows(train_path)
    test, excluded_test = read_rows(test_path)
    parts = split_rows(rows) | {'test': test}
    events = {name: [event_from_row(row, f'{name}-{i}') for i, row in enumerate(group)]
              for name, group in parts.items()}
    y = {name: labels(group) for name, group in parts.items()}
    if any(len(np.unique(y[name])) < 2 for name in ('train', 'selection', 'test')):
        raise ValueError('Training, selection, and test partitions must contain both labels')
    train_keys = {evidence_key(e) for e in events['train']}
    overlap = {name: sum(evidence_key(e) in train_keys for e in group)
               for name, group in events.items() if name != 'train'}
    manifest = {'dataset': 'FUR-API', 'task': 'binary normal/anomaly classification',
                'split_policy': 'Earlier 80% normal-row window: stratified 80/20 train/selection, seed 42; later 20%: threshold calibration, minute boundary intact; official test.csv',
                'partitions': {name: {'rows': len(group), 'labels': dict(Counter(r['type'].strip() for r in group)),
                                     'earliest': str(min(map(timestamp, group))),
                                     'latest': str(max(map(timestamp, group)))} for name, group in parts.items()},
                'excluded_invalid_status': {'train': excluded_train, 'test': excluded_test},
                'exact_evidence_overlap_with_train': overlap,
                'sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in (train_path, test_path)},
                'seeds': args.seeds, 'target_calibration_fpr': args.target_fpr,
                'jevlet_epochs': args.epochs, 'jevlet_samples_per_epoch': args.samples_per_epoch,
                'training_device': args.training_device,
                'isolation_forest_implementation': ('experimental PyTorch CUDA isolation trees' if args.training_device == 'cuda' else 'scikit-learn'),
                'input_policy': 'Common captured event fields; IF/CatBoost use Sentry v2 numeric features; Jevlet uses bounded event text plus normal-baseline size/latency changes. No identities, header values, or labels in inputs.',
                'notes': ['Isolation Forest receives normal training rows only; supervised models also receive labelled anomalies.',
                          'API graph and endpoint-size alert rule are disabled for all models.',
                          'No attack-category labels exist in these CSVs.',
                          'Official test dates overlap training dates; this is a held-out-row test, not a future-time test.',
                          'Selection is stratified within the earlier window because a purely chronological selection slice contains no anomalies; later normal-only calibration chooses thresholds.',
                          'One dataset, three fixed seeds; this does not establish production performance.',
                          'The supplied dataset is extremely imbalanced and may have repeated evidence; overlap is reported, not silently removed.'],
                'versions': {name: importlib.metadata.version(name) for name in
                             ('torch', 'transformers', 'scikit-learn', 'catboost', 'numpy')},
                'sentry_revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                'jevlet_revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=args.jevlet_repo, text=True).strip()}
    return events, y, manifest


def train_jevlet(args, directory, baseline, events, y, seed):
    import torch
    from torch.utils.data import DataLoader, WeightedRandomSampler
    from transformers import get_linear_schedule_with_warmup
    from jevlet.config import seed_all
    from jevlet.data import collate, packed_items
    from jevlet.model import Jevlet, training_loss
    from functools import partial

    seed_all(seed, 4)
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    cfg = {'model': args.base_model, 'model_revision': 'main', 'max_length': args.max_length}
    model = Jevlet.pretrained(cfg).to(device)
    training = [{'text': event_text(e, baseline), 'questions': questions(target)}
                for e, target in zip(events['train'], y['train'])]
    selection = [{'text': event_text(e, baseline), 'questions': questions(target)}
                 for e, target in zip(events['selection'], y['selection'])]
    items = packed_items(model.tokenizer, training, model.max_length)
    selection_items = packed_items(model.tokenizer, selection, model.max_length)
    counts = np.bincount(y['train'].astype(int), minlength=2)
    weights = 1 / counts[y['train'].astype(int)]
    selection_counts = np.bincount(y['selection'].astype(int), minlength=2)
    if min(counts) == 0 or min(selection_counts) == 0:
        raise ValueError('Jevlet training and selection need both labels')
    collator = partial(collate, pad_id=model.tokenizer.pad_token_id)
    optimizer = torch.optim.AdamW(model.parameters(), lr=3e-5, weight_decay=0.01)
    steps = int(np.ceil(args.samples_per_epoch / args.batch_size)) * args.epochs
    scheduler = get_linear_schedule_with_warmup(optimizer, int(steps * 0.1), steps)
    amp = device == 'cuda'
    dtype = torch.bfloat16 if amp and torch.cuda.is_bf16_supported() else torch.float16
    scaler = torch.amp.GradScaler('cuda', enabled=amp and dtype == torch.float16)
    if amp:
        torch.cuda.reset_peak_memory_stats()
    def move(batch):
        return {k: value.to(device) if torch.is_tensor(value) else value for k, value in batch.items()}
    best, history = float('inf'), []
    started = time.perf_counter()
    for epoch in range(args.epochs):
        sampler = WeightedRandomSampler(torch.as_tensor(weights, dtype=torch.double), args.samples_per_epoch,
                    replacement=True, generator=torch.Generator().manual_seed(seed + epoch))
        loader = DataLoader(items, batch_size=args.batch_size, sampler=sampler, collate_fn=collator)
        model.train()
        train_loss = 0.0
        for batch in loader:
            batch = move(batch)
            optimizer.zero_grad(set_to_none=True)
            with torch.autocast(device_type=device, dtype=dtype, enabled=amp):
                loss = training_loss(model, model(batch), batch, 0.5)
            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            scaler.step(optimizer)
            scaler.update()
            scheduler.step()
            train_loss += float(loss.detach())
        model.eval()
        class_losses = [[], []]
        with torch.inference_mode():
            for batch in DataLoader(selection_items, batch_size=args.batch_size * 2, collate_fn=collator):
                batch = move(batch)
                probabilities = model.probabilities(model(batch), batch['omask'], calibrated=False)['choice'][:, 0, :2]
                for p, item in zip(probabilities, batch['items']):
                    target = item['request']['questions'][0]['target']
                    class_losses[target].append(float(-p[target].clamp_min(1e-8).log()))
        selection_loss = float(np.mean([np.mean(values) for values in class_losses]))
        if not np.isfinite(selection_loss):
            raise RuntimeError('Nonfinite Jevlet selection loss')
        history.append({'epoch': epoch + 1, 'train_loss': train_loss / len(loader),
                        'balanced_selection_log_loss': selection_loss})
        print(f'Jevlet seed {seed} epoch {epoch+1}/{args.epochs}: selection loss {selection_loss:.4f}', flush=True)
        if selection_loss < best:
            best = selection_loss
            model.save(directory / 'jevlet')
    training_seconds = time.perf_counter() - started
    peak = int(torch.cuda.max_memory_allocated()) if amp else None
    dropped = [item['context_tokens_dropped'] for item in items]
    detail = {'history': history, 'train_seconds': training_seconds, 'device': device,
              'peak_training_gpu_bytes': peak, 'base_model_revision': model.source_revision,
              'balanced_sampling': True, 'available_training_rows': len(items),
              'samples_per_epoch': args.samples_per_epoch, 'max_length': args.max_length,
              'training_context_truncation_fraction': float(np.mean(np.asarray(dropped) > 0))}
    write_json(directory / 'jevlet-training.json', detail)
    del model, optimizer, scheduler
    if amp:
        torch.cuda.empty_cache()
    return Jevlet.load(directory / 'jevlet', device), detail


def evaluate(detector, events, y, calibration, directory, seed):
    import psutil
    score_start = time.perf_counter()
    scores = detector.score(events)
    seconds = time.perf_counter() - score_start
    result = metrics(y, scores, detector.threshold)
    result['batch_prediction_seconds'] = seconds
    result['batch_events_per_second'] = len(events) / seconds
    result['normal_calibration_fpr'] = float(np.mean(calibration >= detector.threshold))
    # Comparable single-event CPU timings, including serialization and tensor preparation.
    gpu = None
    if detector.kind == 'jevlet':
        gpu = str(next(detector.model.parameters()).device)
        detector.to('cpu')
    elif hasattr(detector.model, 'device') and detector.kind == 'isolation_forest':
        gpu = str(detector.model.device)
        detector.model.to('cpu')
    subset = events[:min(128, len(events))]
    for event in subset[:5]:
        detector.predict(event)
    durations = []
    for event in subset:
        started = time.perf_counter()
        detector.predict(event)
        durations.append((time.perf_counter() - started) * 1000)
    result['single_event_cpu_p50_ms'] = float(np.percentile(durations, 50))
    result['single_event_cpu_p95_ms'] = float(np.percentile(durations, 95))
    result['single_event_cpu_samples'] = len(durations)
    result['process_rss_bytes_after_scoring'] = psutil.Process().memory_info().rss
    result['memory_note'] = 'Shared experiment-process RSS, not isolated model memory; compare checkpoint sizes instead.'
    if gpu:
        if detector.kind == 'jevlet':
            detector.to(gpu)
        else:
            detector.model.to(gpu)
    rows = [{'request_id': event['request_id'], 'truth': bool(label), 'score': float(score),
             'prediction': bool(score >= detector.threshold)} for event, label, score in zip(events, y, scores)]
    write_json(directory / f'{detector.kind}-predictions.json', rows)
    result['seed'] = seed
    result['model'] = detector.kind
    return result, scores


def report(output, manifest, rows):
    summary = {}
    for name in ('isolation_forest', 'catboost', 'jevlet'):
        selected = [row for row in rows if row['model'] == name]
        summary[name] = {key: {'mean': float(np.mean([r[key] for r in selected])),
                                'min': float(min(r[key] for r in selected)),
                                'max': float(max(r[key] for r in selected))}
                         for key in ('precision', 'recall', 'f1', 'average_precision', 'false_positive_rate',
                                     'single_event_cpu_p50_ms', 'train_seconds')}
    write_json(output / 'comparison.json', {'manifest': manifest, 'runs': rows, 'summary': summary})
    with (output / 'comparison.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    lines = ['# Local Sentry model comparison', '',
             'Fresh local training on FUR-API. No changes were pushed to Git.', '',
             '## Mean results across seeds', '',
             '| Model | Precision | Recall | F1 | Average precision | False alarms | CPU p50/event |',
             '|---|---:|---:|---:|---:|---:|---:|']
    for name, value in summary.items():
        lines.append('| %s | %.1f%% | %.1f%% | %.3f | %.3f | %.1f%% | %.1f ms |' %
                     (name, value['precision']['mean'] * 100, value['recall']['mean'] * 100,
                      value['f1']['mean'], value['average_precision']['mean'],
                      value['false_positive_rate']['mean'] * 100, value['single_event_cpu_p50_ms']['mean']))
    lines += ['', '## Individual runs', '',
              '| Seed | Model | Anomalies found | Anomalies missed | False alarms | F1 | Training seconds |',
              '|---|---|---:|---:|---:|---:|---:|']
    for row in rows:
        lines.append('| %s | %s | %d | %d | %d | %.3f | %.1f |' %
                     (row['seed'], row['model'], row['true_positive'], row['false_negative'],
                      row['false_positive'], row['f1'], row['train_seconds']))
    lines += ['', '## Method and limits', '',
              '- Later 20% of normal training timestamps is reserved for calibration, keeping the boundary minute intact. The earlier window is split 80/20 into training/selection with fixed stratification seed 42 so both labels are represented.',
              '- Thresholds target %.1f%% false positives on normal calibration requests. Test labels never choose models or thresholds.' % (manifest['target_calibration_fpr'] * 100),
              '- All candidates score the same official test requests. IF learns normal traffic; CatBoost and Jevlet also learn labelled training anomalies.',
              '- Official test dates overlap the training dates. The chronological calibration window prevents threshold leakage, but does not turn the official test into a future-time evaluation.',
              '- IF and CatBoost share Sentry v2 numerical features and normal-only endpoint baselines. Jevlet uses bounded request/response text and size/latency baseline changes.',
              '- Jevlet starts with the cached pretrained DistilBERT encoder and fresh Jevlet heads, then trains the choice head for normal/anomalous. It does not reuse banking or sentiment task weights.',
              '- Jevlet uses balanced sampling during training; CatBoost uses balanced class weights. Security labels are scarce, so results can vary substantially.',
              '- CPU latency includes preparation and scoring for one request; batch throughput may use GPU for Jevlet and is a separate measurement.',
              '- Graph inventory and the endpoint-size rule are disabled. This measures model behavior, not the whole Sentry system.',
              '- FUR-API provides binary labels only. These scores do not measure attack-type classification or verified vulnerability detection.',
              '- One dataset and a few seeds do not establish production accuracy. Inspect errors before selecting a replacement.',
              '- Exact evidence overlaps with training: ' + json.dumps(manifest['exact_evidence_overlap_with_train']) + '.',
              '', '## Data partitions', '', '```json', json.dumps(manifest['partitions'], indent=2), '```', '',
              'Detailed metrics, dataset hashes, per-request predictions, checkpoints, and run configuration are saved beside this report.', '']
    if manifest['training_device'] == 'cuda':
        lines += ['## GPU training', '',
                  'All three candidates fit on CUDA. Isolation Forest uses a separate experimental PyTorch implementation of axis-aligned isolation trees, not the scikit-learn estimator. CatBoost uses task_type=GPU; Jevlet uses CUDA PyTorch. Normal-baseline statistics and CSV preparation run on CPU.', '',
                  'The custom forest follows subsampling, random varying-feature splits, uniform thresholds, depth limits, and expected path-length scoring. Random-tree construction differs from scikit-learn, so these are separate results.', '',
                  'Jevlet checkpoints may be reused from a matching completed CUDA run; their original training durations are retained.', '']
    (output / 'REPORT.md').write_text('\n'.join(lines), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / 'evaluation/datasets/FUR-API')
    parser.add_argument('--jevlet-repo', type=Path, default=Path('E:/clg/DL/mini_proj/jevlet'))
    parser.add_argument('--output', type=Path, default=ROOT / '.local-data/model-comparison/full')
    parser.add_argument('--seeds', type=int, nargs='+', default=[42, 43, 44])
    parser.add_argument('--epochs', type=int, default=6)
    parser.add_argument('--samples-per-epoch', type=int, default=4096)
    parser.add_argument('--batch-size', type=int, default=16)
    parser.add_argument('--max-length', type=int, default=384)
    parser.add_argument('--target-fpr', type=float, default=0.05)
    parser.add_argument('--base-model', default='distilbert/distilbert-base-uncased')
    parser.add_argument('--training-device', choices=['mixed', 'cuda'], default='cuda')
    parser.add_argument('--reuse-completed-jevlet', type=Path,
                        help='Reuse matching complete CUDA Jevlet checkpoints from an earlier run')
    parser.add_argument('--predict-event', type=Path)
    parser.add_argument('--model', choices=['isolation_forest', 'catboost', 'jevlet'])
    parser.add_argument('--checkpoint', type=Path)
    args = parser.parse_args()
    if args.predict_event:
        if not args.model or not args.checkpoint:
            parser.error('Prediction requires --model and --checkpoint')
        detector = LocalDetector.load(args.checkpoint, args.model, args.jevlet_repo)
        print(json.dumps(detector.predict(json.loads(args.predict_event.read_text(encoding='utf-8'))), indent=2))
        return
    if min(args.epochs, args.samples_per_epoch, args.batch_size) < 1:
        parser.error('Training counts must be positive')
    if not 16 <= args.max_length <= 512:
        parser.error('max-length must be between 16 and 512')
    if not 0 < args.target_fpr <= 0.25:
        parser.error('target-fpr must be in (0, 0.25]')
    if len(set(args.seeds)) != len(args.seeds):
        parser.error('Seeds must be unique')
    if args.output.exists() and (args.output / 'manifest.json').exists():
        parser.error('Output already contains a run; choose a new directory to preserve it')
    args.output.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(args.jevlet_repo / 'src'))
    os.environ['HF_HOME'] = str(args.jevlet_repo / '.cache/huggingface')
    os.environ['MPLCONFIGDIR'] = str(ROOT / '.local-data/model-comparison/matplotlib')
    from catboost import CatBoostClassifier
    import torch
    torch.set_num_threads(4)
    if args.training_device == 'cuda' and not torch.cuda.is_available():
        parser.error('CUDA is unavailable; GPU mode does not fall back to CPU')
    events, y, manifest = prepare(args)
    write_json(args.output / 'manifest.json', manifest)
    print(json.dumps(manifest['partitions'], indent=2), flush=True)
    all_rows = []
    for seed in args.seeds:
        directory = args.output / f'seed-{seed}'
        directory.mkdir()
        normal_train = [e for e, target in zip(events['train'], y['train']) if not target]
        normal_cal = [e for e, target in zip(events['calibration'], y['calibration']) if not target]
        started = time.perf_counter()
        if args.training_device == 'cuda':
            from gpu_isolation_forest import TorchIsolationForest
            baseline = normal_baseline(normal_train)
            forest = TorchIsolationForest(seed=seed).fit(matrix(normal_train, baseline))
            torch.cuda.synchronize()
            forest.save(directory / 'isolation-forest-gpu.pt')
        else:
            baseline = fit_model(normal_train, normal_cal, graph=False, seed=seed, target_fpr=args.target_fpr)
            forest = baseline.ml_model
        if_seconds = time.perf_counter() - started
        with (directory / 'baseline.pkl').open('wb') as stream:
            pickle.dump(baseline, stream)
        x = {name: matrix(group, baseline) for name, group in events.items()}
        cb = CatBoostClassifier(iterations=1000, depth=6, learning_rate=0.05,
                               loss_function='Logloss', eval_metric='AUC', auto_class_weights='Balanced',
                               random_seed=seed, thread_count=4, allow_writing_files=False,
                               task_type='GPU' if args.training_device == 'cuda' else 'CPU', devices='0')
        started = time.perf_counter()
        cb.fit(x['train'], y['train'].astype(int), eval_set=(x['selection'], y['selection'].astype(int)),
               early_stopping_rounds=80, verbose=False)
        cb_seconds = time.perf_counter() - started
        cb.save_model(str(directory / 'catboost.cbm'))
        print(f'Seed {seed}: Isolation Forest and CatBoost trained; training Jevlet next.', flush=True)
        reused = False
        if args.reuse_completed_jevlet:
            source = args.reuse_completed_jevlet / f'seed-{seed}'
            detail_path = source / 'jevlet-training.json'
            if detail_path.exists():
                previous = json.loads((args.reuse_completed_jevlet / 'manifest.json').read_text(encoding='utf-8'))
                detail = json.loads(detail_path.read_text(encoding='utf-8'))
                if (len(detail['history']) == args.epochs and detail['device'] == 'cuda'
                        and previous['sha256'] == manifest['sha256']
                        and previous['partitions'] == manifest['partitions']
                        and detail['max_length'] == args.max_length
                        and detail['samples_per_epoch'] == args.samples_per_epoch):
                    import shutil
                    from jevlet.model import Jevlet
                    shutil.copytree(source / 'jevlet', directory / 'jevlet')
                    shutil.copy2(detail_path, directory / 'jevlet-training.json')
                    detail['reused_from'] = str(source.resolve())
                    write_json(directory / 'jevlet-training.json', detail)
                    jevlet = Jevlet.load(directory / 'jevlet', 'cuda')
                    reused = True
                    print(f'Jevlet seed {seed}: reusing completed matching CUDA training.', flush=True)
        if not reused:
            jevlet, detail = train_jevlet(args, directory, baseline, events, y, seed)
        candidates = {'isolation_forest': (forest, if_seconds),
                      'catboost': (cb, cb_seconds), 'jevlet': (jevlet, detail['train_seconds'])}
        models = {}
        score_cache = {}
        for kind, (model, training_seconds) in candidates.items():
            detector = LocalDetector(kind, model, baseline, 0)
            calibration = detector.score(normal_cal)
            detector.threshold = threshold_at_fpr(calibration, args.target_fpr)
            row, scores = evaluate(detector, events['test'], y['test'], calibration, directory, seed)
            row['train_seconds'] = training_seconds
            row['checkpoint_bytes'] = ((directory / 'catboost.cbm').stat().st_size if kind == 'catboost' else
                                       (directory / 'jevlet/model.safetensors').stat().st_size if kind == 'jevlet' else
                                       (directory / 'isolation-forest-gpu.pt').stat().st_size if args.training_device == 'cuda' else
                                       len(baseline.ml_model_bytes))
            row['training_device'] = ('cuda' if kind == 'jevlet' or args.training_device == 'cuda' else 'cpu')
            row['implementation'] = ('pytorch_isolation_forest_experimental' if kind == 'isolation_forest' and args.training_device == 'cuda' else kind)
            all_rows.append(row)
            score_cache[kind] = scores
            models[kind] = {'threshold': detector.threshold, 'metrics': row}
            print(f'{kind} seed {seed}: F1 {row["f1"]:.3f}, found {row["true_positive"]}/150, false alarms {row["false_positive"]}', flush=True)
        write_json(directory / 'models.json', models)
        write_json(directory / 'metrics.json', all_rows[-3:])
        report(args.output, manifest, all_rows)
        del jevlet, candidates
        import torch
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
    print('Results: ' + str(args.output / 'REPORT.md'), flush=True)


if __name__ == '__main__':
    main()
