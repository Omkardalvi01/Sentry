"""Render completed local comparison metrics and audit saved predictions."""

import argparse
import json
import os
from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault('MPLCONFIGDIR', str(ROOT / '.local-data/model-comparison/matplotlib'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--benchmark-cpu', action='store_true')
    args = parser.parse_args()
    directory = args.directory
    data = json.loads((directory / 'comparison.json').read_text(encoding='utf-8'))
    names = ['isolation_forest', 'catboost', 'jevlet']
    display = ['Isolation Forest', 'CatBoost', 'Jevlet']
    rows = data['runs']
    summary = data['summary']
    seeds = data['manifest']['seeds']
    if len(rows) != 3 * len(seeds):
        raise ValueError('Run is incomplete; do not summarize it as a completed comparison')
    sys.path.insert(0, str(ROOT / 'evaluation'))
    from compare_local_models import metrics, read_rows, report
    import platform
    import torch
    torch.set_num_threads(4)
    hardware = {'cpu': platform.processor(), 'platform': platform.platform(),
                'python': sys.version, 'gpu': torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
                'cuda_runtime': torch.version.cuda}
    (directory / 'hardware.json').write_text(json.dumps(hardware, indent=2), encoding='utf-8')
    if data['manifest'].get('training_device') == 'cuda':
        from catboost import CatBoostClassifier
        from gpu_isolation_forest import TorchIsolationForest
        audit_devices = {}
        for seed in seeds:
            folder = directory / f'seed-{seed}'
            forest = TorchIsolationForest.load(folder / 'isolation-forest-gpu.pt', 'cpu')
            classifier = CatBoostClassifier()
            classifier.load_model(str(folder / 'catboost.cbm'))
            jevlet_training = json.loads((folder / 'jevlet-training.json').read_text(encoding='utf-8'))
            device_record = {'isolation_forest': forest.training_device,
                             'catboost': classifier.get_all_params()['task_type'],
                             'jevlet': jevlet_training['device']}
            assert device_record['isolation_forest'].startswith('cuda')
            assert device_record['catboost'] == 'GPU' and device_record['jevlet'] == 'cuda'
            audit_devices[str(seed)] = device_record
        (directory / 'training-device-audit.json').write_text(json.dumps(audit_devices, indent=2), encoding='utf-8')
    if args.benchmark_cpu:
        import time
        from local_models import LocalDetector
        from replay_fur import event_from_row
        test_rows, _ = read_rows(ROOT / 'evaluation/datasets/FUR-API/dataset/test.csv')
        events = [event_from_row(row, f'test-{i}') for i, row in enumerate(test_rows[:128])]
        for row in rows:
            detector = LocalDetector.load(directory / f'seed-{row["seed"]}', row['model'],
                                          Path('E:/clg/DL/mini_proj/jevlet'), 'cpu')
            for event in events[:5]:
                detector.predict(event)
            elapsed = []
            for event in events:
                start = time.perf_counter()
                detector.predict(event)
                elapsed.append((time.perf_counter() - start) * 1000)
            row['single_event_cpu_p50_ms'] = float(np.percentile(elapsed, 50))
            row['single_event_cpu_p95_ms'] = float(np.percentile(elapsed, 95))
            row['cpu_benchmark_threads'] = 4
            print(f'CPU benchmark {row["model"]} seed {row["seed"]}: {row["single_event_cpu_p50_ms"]:.2f} ms', flush=True)
            del detector
        for seed in seeds:
            folder = directory / f'seed-{seed}'
            selected = [row for row in rows if row['seed'] == seed]
            (folder / 'metrics.json').write_text(json.dumps(selected, indent=2), encoding='utf-8')
            models = json.loads((folder / 'models.json').read_text(encoding='utf-8'))
            for row in selected:
                models[row['model']]['metrics'] = row
            (folder / 'models.json').write_text(json.dumps(models, indent=2), encoding='utf-8')
        report(directory, data['manifest'], rows)
        data = json.loads((directory / 'comparison.json').read_text(encoding='utf-8'))
        summary = data['summary']
    # Independently recompute every saved confusion matrix and score metric.
    for row in rows:
        saved = json.loads((directory / f'seed-{row["seed"]}' /
                            f'{row["model"]}-predictions.json').read_text(encoding='utf-8'))
        audit = metrics(np.asarray([r['truth'] for r in saved]),
                        np.asarray([r['score'] for r in saved]), row['threshold'])
        for field in audit:
            if not np.isclose(audit[field], row[field]):
                raise AssertionError(f'Prediction audit mismatch: {row["model"]} {field}')
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 10})
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.8), layout='constrained')
    index = np.arange(3)
    colors = ['#2474a9', '#37936f', '#bc7543']
    for offset, metric in enumerate(['precision', 'recall', 'f1']):
        means = [summary[name][metric]['mean'] for name in names]
        low = [value - summary[name][metric]['min'] for value, name in zip(means, names)]
        high = [summary[name][metric]['max'] - value for value, name in zip(means, names)]
        axes[0].bar(index + (offset - 1) * .24, means, .22, label=metric.title(),
                    color=colors[offset], yerr=[low, high], capsize=3)
    axes[0].set(xticks=index, xticklabels=display, ylim=(0, 1), ylabel='Score',
                title='Detection quality · mean and seed range')
    axes[0].legend(loc='upper left', ncols=3, fontsize=8)
    axes[0].grid(axis='y', alpha=.15)
    latencies = [summary[name]['single_event_cpu_p50_ms']['mean'] for name in names]
    axes[1].bar(index, latencies, color=['#2474a9', '#37936f', '#bc7543'])
    axes[1].set(xticks=index, xticklabels=display, ylabel='Milliseconds per event (log scale)',
                yscale='log', title='CPU scoring time · preparation included')
    for x, value in zip(index, latencies):
        axes[1].annotate(f'{value:.1f} ms', (x, value), xytext=(0, 5),
                         textcoords='offset points', ha='center', fontsize=9)
    axes[1].set_ylim(min(latencies) * .5, max(latencies) * 2.5)
    axes[1].grid(axis='y', alpha=.15)
    fig.suptitle('Sentry · local FUR-API comparison', fontsize=15, fontweight='bold')
    implementation = ('experimental PyTorch CUDA forest' if data['manifest'].get('training_device') == 'cuda' else 'scikit-learn forest')
    fig.supxlabel(f'{len(seeds)} seeds · {data["manifest"]["partitions"]["test"]["rows"]:,} held-out requests · Isolation Forest: {implementation}', fontsize=9)
    fig.savefig(directory / 'comparison.png', dpi=180)
    fig.savefig(directory / 'comparison.svg')
    plt.close(fig)
    best = max(names, key=lambda name: summary[name]['f1']['mean'])
    report = directory / 'REPORT.md'
    text = report.read_text(encoding='utf-8').split('\n## Interpretation\n')[0]
    text += '\n## Interpretation\n\n'
    text += f'The highest mean F1 in this experiment was **{best}** '
    text += f'({summary[best]["f1"]["mean"]:.3f}). This is an observed result on FUR-API, not a general ranking.\n\n'
    text += 'Predicting every request as normal would achieve 86.9% accuracy while detecting none of the 150 anomalies. Use recall, false alarms, F1, and average precision to judge the candidates.\n\n'
    text += 'All saved per-request predictions were independently checked against the reported confusion matrices and score metrics.\n\n'
    text += 'The official test timestamps overlap the training dates; these results do not measure future-time generalization.\n\n'
    text += 'Classifier scores are not calibrated estimates of real-world security risk. Their alert thresholds are selected from normal calibration traffic.\n\n'
    # Inspect whether missing endpoint history contributes to false alarms.
    import pickle
    from detector import endpoint_key
    from replay_fur import event_from_row
    test_rows, _ = read_rows(ROOT / 'evaluation/datasets/FUR-API/dataset/test.csv')
    test_events = [event_from_row(row, f'test-{i}') for i, row in enumerate(test_rows)]
    breakdown = []
    for seed in seeds:
        with (directory / f'seed-{seed}/baseline.pkl').open('rb') as stream:
            baseline = pickle.load(stream)
        has_history = np.asarray([endpoint_key(event) in baseline.profiles for event in test_events])
        for name in names:
            saved = json.loads((directory / f'seed-{seed}/{name}-predictions.json').read_text(encoding='utf-8'))
            truth = np.asarray([record['truth'] for record in saved])
            predicted = np.asarray([record['prediction'] for record in saved])
            for group, mask in [('Endpoint has normal history', has_history), ('No normal endpoint history', ~has_history)]:
                normals = int(np.sum(mask & ~truth))
                anomalies = int(np.sum(mask & truth))
                fp = int(np.sum(mask & ~truth & predicted))
                tp = int(np.sum(mask & truth & predicted))
                breakdown.append({'seed': seed, 'model': name, 'group': group,
                                  'normal_requests': normals, 'anomalous_requests': anomalies,
                                  'false_positives': fp, 'true_positives': tp})
    (directory / 'endpoint-history-breakdown.json').write_text(json.dumps(breakdown, indent=2), encoding='utf-8')
    text += '## Effect of endpoint history\n\n'
    text += '| Model | Endpoint history | Normal test requests | Mean false alarms | Anomalous test requests | Mean anomalies found |\n'
    text += '|---|---|---:|---:|---:|---:|\n'
    for name in names:
        for group in ['Endpoint has normal history', 'No normal endpoint history']:
            selected = [row for row in breakdown if row['model'] == name and row['group'] == group]
            text += '| %s | %s | %d | %.1f | %d | %.1f |\n' % (name, group,
                     selected[0]['normal_requests'], np.mean([r['false_positives'] for r in selected]),
                     selected[0]['anomalous_requests'], np.mean([r['true_positives'] for r in selected]))
    text += '\nMissing normal endpoint history is separate from an API being undocumented; this dataset supplies no API specification.\n\n'
    text += '![Detection quality and CPU latency](comparison.png)\n'
    # Make repeated summaries idempotent.
    original = report.read_text(encoding='utf-8').split('\n## Interpretation\n')[0]
    original = original.replace('Attacks found', 'Anomalies found').replace('Attacks missed', 'Anomalies missed')
    report.write_text(original + text[text.index('\n## Interpretation\n'):], encoding='utf-8')
    print(json.dumps({'prediction_audit': 'passed', 'best_mean_f1': best, 'summary': summary}, indent=2))


if __name__ == '__main__':
    main()
