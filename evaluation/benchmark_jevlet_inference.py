"""Profile existing local Jevlet checkpoints without retraining or changing them.

Measures warm event preparation + prediction; excludes model loading, Kafka,
network time and batch queue wait. Reduced precision is an opt-in experiment.
"""

import argparse
import json
import os
from pathlib import Path
import sys
import time

os.environ.setdefault('USE_TF', '0')
os.environ.setdefault('TOKENIZERS_PARALLELISM', 'false')
os.environ.setdefault('HF_HUB_OFFLINE', '1')
os.environ.setdefault('TRANSFORMERS_OFFLINE', '1')

import numpy as np
import torch

from compare_local_models import ROOT, labels, metrics, read_rows, write_json
from local_models import LocalDetector, event_text, questions
from replay_fur import event_from_row


@torch.inference_mode()
def batch_scores(detector, events, batch_size=16):
    """Use Jevlet's original safe packer, sharing encoder work across requests."""
    from jevlet.data import collate, packed_items
    model = detector.model
    device = next(model.parameters()).device
    scores = []
    for start in range(0, len(events), batch_size):
        requests = [{'text': event_text(e, detector.baseline), 'questions': questions()}
                    for e in events[start:start + batch_size]]
        items = packed_items(model.tokenizer, requests, model.max_length)
        batch = collate(items, model.tokenizer.pad_token_id)
        batch = {k: v.to(device) if torch.is_tensor(v) else v for k, v in batch.items()}
        probs = model.probabilities(model(batch), batch['omask'], calibrated=True)
        scores.extend(probs['choice'][:, 0, 1].cpu().tolist())
    return np.asarray(scores, dtype=float)


def synchronize(device):
    if device == 'cuda':
        torch.cuda.synchronize()


def timing(detector, events, device, batch_size):
    scorer = detector.score if batch_size == 1 else lambda group: batch_scores(detector, group, batch_size)
    for _ in range(5):
        scorer(events[:batch_size])
    synchronize(device)
    durations = []
    for start in range(0, len(events), batch_size):
        group = events[start:start + batch_size]
        synchronize(device)
        began = time.perf_counter()
        scorer(group)
        synchronize(device)
        durations.append((time.perf_counter() - began) * 1000)
    return {'batch_size': batch_size, 'events': len(events), 'batches': len(durations),
            'batch_p50_ms': float(np.percentile(durations, 50)),
            'batch_p95_ms': float(np.percentile(durations, 95)),
            'amortized_ms_per_event': float(sum(durations) / len(events)),
            'events_per_second': float(len(events) * 1000 / sum(durations))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--jevlet-repo', type=Path, default=Path('E:/clg/DL/mini_proj/jevlet'))
    parser.add_argument('--seeds', nargs='+', type=int, default=[42, 43, 44])
    parser.add_argument('--samples', type=int, default=128)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Choose a new output directory to preserve earlier results')
    if not torch.cuda.is_available():
        parser.error('CUDA required; this experiment never silently falls back to CPU')
    if not 1 <= args.samples <= 1149:
        parser.error('samples must be between 1 and 1149')
    sys.path.insert(0, str(args.jevlet_repo / 'src'))
    torch.set_num_threads(4)
    args.output.mkdir(parents=True)
    rows, _ = read_rows(ROOT / 'evaluation/datasets/FUR-API/dataset/test.csv')
    events = [event_from_row(row, f'test-{i}') for i, row in enumerate(rows)]
    truth = labels(rows)
    indices = np.random.default_rng(2026).permutation(len(events))[:args.samples]
    timed_events = [events[i] for i in indices]
    from jevlet.data import packed_items
    results = []
    token_lengths = []
    for seed in args.seeds:
        directory = args.run / f'seed-{seed}'
        saved = json.loads((directory / 'jevlet-predictions.json').read_text(encoding='utf-8'))
        if [r['request_id'] for r in saved] != [e['request_id'] for e in events]:
            raise ValueError('Saved reference and dataset request order differ')
        if [r['truth'] for r in saved] != truth.tolist():
            raise ValueError('Saved reference labels and dataset differ')
        reference = np.asarray([r['score'] for r in saved])
        modes = [('original_cpu_fp32', 'cpu', torch.float32, 1),
                 ('original_cuda_fp32', 'cuda', torch.float32, 1),
                 ('cuda_fp16', 'cuda', torch.float16, 1),
                 ('cuda_fp16_batch16', 'cuda', torch.float16, 16)]
        for name, device, dtype, batch_size in modes:
            detector = LocalDetector.load(directory, 'jevlet', args.jevlet_repo, device)
            detector.model.to(dtype=dtype)
            if device == 'cuda':
                torch.cuda.reset_peak_memory_stats()
            if not token_lengths:
                items = packed_items(detector.model.tokenizer,
                                     [{'text': event_text(e, detector.baseline), 'questions': questions()} for e in events],
                                     detector.model.max_length)
                token_lengths = [len(item['input_ids']) for item in items]
                dropped = [item['context_tokens_dropped'] for item in items]
            stats = timing(detector, timed_events, device, batch_size)
            # Validate every CUDA candidate on the fixed test, retaining the
            # original calibration threshold. No test-dependent retuning.
            if device == 'cuda':
                scorer = detector.score if batch_size == 1 else lambda group: batch_scores(detector, group, batch_size)
                scores = scorer(events)
                if not np.isfinite(scores).all():
                    raise ValueError('Non-finite prediction scores')
                quality = metrics(truth, scores, detector.threshold)
                changed = int(np.sum((scores >= detector.threshold) != (reference >= detector.threshold)))
                max_delta = float(np.max(np.abs(scores - reference)))
                write_json(args.output / f'{seed}-{name}-scores.json', scores.tolist())
            else:
                # CPU row is latency only; reference metrics are GPU FP32.
                quality, changed, max_delta = None, None, None
            result = {'seed': seed, 'mode': name, 'device': device, 'precision': str(dtype),
                      'latency': stats, 'metrics': quality,
                      'changed_decisions_vs_saved_cuda_fp32': changed,
                      'maximum_score_difference': max_delta,
                      'peak_cuda_allocated_bytes': int(torch.cuda.max_memory_allocated()) if device == 'cuda' else None}
            results.append(result)
            write_json(args.output / 'results.json', results)
            print(f'{seed} {name}: batch median {stats["batch_p50_ms"]:.2f} ms; '
                  f'amortized {stats["amortized_ms_per_event"]:.2f} ms/event; '
                  f'changed decisions {changed}', flush=True)
            del detector
            if device == 'cuda':
                torch.cuda.empty_cache()
    metadata = {'source_run': str(args.run.resolve()), 'gpu': torch.cuda.get_device_name(),
                'torch': torch.__version__, 'threads': torch.get_num_threads(),
                'latency_sample_indices': indices.tolist(),
                'token_lengths': {'p50': float(np.median(token_lengths)), 'p95': float(np.percentile(token_lengths, 95)),
                                  'maximum': max(token_lengths), 'truncated_requests': sum(n > 0 for n in dropped)},
                'note': 'Warm latency includes input preparation and device transfers, excludes loading, network, Kafka and queue wait. Batch amortization is throughput, not individual latency. All GPU decisions checked on fixed test at unchanged threshold.'}
    write_json(args.output / 'manifest.json', metadata)
    report = '# Jevlet prediction speed experiment\n\n'
    report += f'GPU: {metadata["gpu"]}. Existing trained checkpoints are unchanged. No retraining or Git push.\n\n'
    report += '| Mode | Mean seed median batch ms | Mean processing ms/event | Mean F1 | Changed decisions across seeds |\n|---|---:|---:|---:|---:|\n'
    for name, _, _, _ in modes:
        group = [row for row in results if row['mode'] == name]
        f1 = f'{np.mean([row["metrics"]["f1"] for row in group]):.3f}' if group[0]['metrics'] else 'Not measured'
        changed = str(sum(row['changed_decisions_vs_saved_cuda_fp32'] for row in group)) if group[0]['metrics'] else 'Not measured'
        report += f'| {name} | {np.mean([row["latency"]["batch_p50_ms"] for row in group]):.2f} | {np.mean([row["latency"]["amortized_ms_per_event"] for row in group]):.2f} | {f1} | {changed} |\n'
    report += '\n' + metadata['note'] + '\n\n'
    report += 'The earlier test has already been inspected in prior model comparisons. This is a regression check of existing checkpoints, not new evidence of generalization. Use a new untouched holdout when training on more data.\n\n'
    report += 'Reduced precision can change probabilities even if decisions remain the same here; recalibrate on normal calibration data before adopting it. Shortening the maximum length only helps inputs that exceed that cap and can remove security evidence.\n\n'
    report += f'Token lengths: {json.dumps(metadata["token_lengths"])}. Batch queue delay is not measured; choose batch size according to an explicit wait limit.\n'
    (args.output / 'REPORT.md').write_text(report, encoding='utf-8')
    print('Results: ' + str(args.output / 'REPORT.md'), flush=True)


if __name__ == '__main__':
    main()
