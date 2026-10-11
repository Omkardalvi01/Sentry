"""Prepare RCAEval RE3 telemetry windows for a separate failure-state task.

Fault exposure is a window label, never a malicious-request label. Data files
are pinned, hashed, downloaded without executing any external source code.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
import time

import numpy as np
import pandas as pd
import requests
from sklearn.model_selection import train_test_split

REVISION = 'afeacb11bcc94dadfd1c8f483ee4377b2b8b614e'
REPOSITORY = 'phamquiluan/RCAEval'


def download(relative, directory):
    path = directory / relative
    if path.exists():
        return path
    url = f'https://huggingface.co/datasets/{REPOSITORY}/resolve/{REVISION}/{relative}'
    path.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(4):
        try:
            response = requests.get(url, timeout=120)
            response.raise_for_status()
            temporary = path.with_suffix(path.suffix + '.partial')
            temporary.write_bytes(response.content)
            temporary.replace(path)
            return path
        except requests.RequestException:
            if attempt == 3:
                raise
            time.sleep(min(2 ** attempt, 4))


def normalize_message(message):
    """Remove clocks/identifiers while retaining error and stack-trace evidence."""
    text = str(message)
    text = re.sub(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}\b', '<id>', text)
    text = re.sub(r'\b\d{4}-\d\d-\d\d[T ][\d:.+Z-]+', '<time>', text)
    text = re.sub(r'\b\d{10,}\b', '<number>', text)
    return ' '.join(text.split())[:220]


def seconds(values):
    numeric = pd.to_numeric(values, errors='coerce')
    if numeric.notna().sum() > len(values) / 2:
        scale = float(numeric.dropna().abs().median())
        divisor = 1e9 if scale > 1e17 else 1e6 if scale > 1e14 else 1e3 if scale > 1e11 else 1
        return numeric / divisor
    return pd.to_datetime(values, utc=True, errors='coerce').astype('int64') / 1e9


def windows(case, directory):
    metrics = pd.read_parquet(directory / case / 'metrics.parquet').sort_values('time')
    logs = pd.read_parquet(directory / case / 'logs.parquet')
    inject = int((directory / case / 'inject_time.txt').read_text().strip())
    metrics['time'] = seconds(metrics['time'])
    logs['time_seconds'] = seconds(logs['timestamp'])
    beginning = int(metrics['time'].min())
    # A strictly earlier 3-minute warmup supplies the endpoint's normal baseline.
    warmup_end = beginning + 180
    if warmup_end >= inject - 60:
        raise ValueError(f'Insufficient normal warmup for {case}')
    columns = [column for column in metrics if column != 'time']
    # Convert each metric once, rather than converting hundreds of columns
    # again for every 60-second window.
    metrics[columns] = metrics[columns].apply(pd.to_numeric, errors='coerce')
    warmup = metrics.loc[metrics.time < warmup_end, columns]
    centre = warmup.median()
    scale = (warmup.sub(centre).abs().median() * 1.4826).clip(lower=0.01)
    output = []
    for start in range(warmup_end, int(metrics.time.max()) - 59, 60):
        end = start + 60
        # Remove transition windows: the label describes exposure to a fault,
        # not evidence that every individual request failed.
        if end > inject - 60 and start < inject + 60:
            continue
        block = metrics.loc[(metrics.time >= start) & (metrics.time < end), columns]
        if len(block) < 10:
            continue
        change = block.median().sub(centre).div(scale)
        change = change.replace([np.inf, -np.inf], np.nan).dropna()
        top = change.abs().sort_values(ascending=False).head(8).index
        selected = logs.loc[(logs.time_seconds >= start) & (logs.time_seconds < end), 'message'].astype(str)
        errors = selected.str.contains(r'error|exception|fail|panic|timeout|unavailable', case=False, regex=True)
        warnings = selected.str.contains(r'warn|retry|slow', case=False, regex=True)
        templates = selected.loc[errors].map(normalize_message).drop_duplicates().head(3)
        text = '\n'.join(['service telemetry over 60 seconds',
                          f'log count: {len(selected)}', f'error log fraction: {float(errors.mean()) if len(selected) else 0:.3f}',
                          f'warning log fraction: {float(warnings.mean()) if len(selected) else 0:.3f}',
                          'metric departures from earlier normal history:',
                          *[f'{column}: {np.clip(change[column], -99, 99):.2f}' for column in top],
                          'error log evidence:', *templates.tolist()])
        output.append({'case': case, 'start': start, 'end': end,
                       'label': int(start >= inject + 60), 'text': text})
    if {record['label'] for record in output} != {0, 1}:
        raise ValueError(f'Both normal and faulty windows required for {case}')
    return output


def partition_cases(cases):
    # Every window from one incident remains in one partition. Stratify by
    # application, not by the class which is present in each complete case.
    train, held = train_test_split(cases, test_size=0.4, random_state=2026,
                                  stratify=[case.split('_')[0] for case in cases])
    selection, held = train_test_split(held, test_size=0.5, random_state=2026,
                                      stratify=[case.split('_')[0] for case in held])
    calibration, test = train_test_split(held, test_size=0.5, random_state=2026,
                                        stratify=[case.split('_')[0] for case in held])
    return {'train': sorted(train), 'selection': sorted(selection),
            'calibration': sorted(calibration), 'test': sorted(test)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Choose a fresh output file')
    index_path = download('cases.parquet', args.data)
    index = pd.read_parquet(index_path)
    chosen = index.loc[(index.suite == 'RE3') & index.has_logs]
    cases = sorted(chosen.case.tolist())
    files = ['README.md'] + [f'{case}/{filename}' for case in cases
                            for filename in ('metrics.parquet', 'logs.parquet', 'inject_time.txt')]
    print(f'Downloading logs/metrics for {len(cases)} independent RCAEval RE3 cases; no trace archives.', flush=True)
    with ThreadPoolExecutor(max_workers=6) as pool:
        paths = list(pool.map(lambda relative: download(relative, args.data), files))
    parts = partition_cases(cases)
    result = {}
    for name, names in parts.items():
        result[name] = []
        for i, case in enumerate(names):
            result[name].extend(windows(case, args.data))
            if (i + 1) % 10 == 0 or i + 1 == len(names):
                print(f'{name}: prepared {i + 1}/{len(names)} cases.', flush=True)
    # Reject identical evidence crossing partitions. Retain the earlier split;
    # records with conflicting labels within a partition are ambiguous and removed.
    blocked, removed = set(), {}
    for name in ('train', 'selection', 'calibration', 'test'):
        group = result[name]
        labels_by_text = {}
        for record in group:
            labels_by_text.setdefault(record['text'], set()).add(record['label'])
        seen, kept = set(), []
        for record in group:
            text = record['text']
            if text in blocked or text in seen or len(labels_by_text[text]) != 1:
                continue
            kept.append(record)
            seen.add(text)
        blocked.update(labels_by_text)
        result[name] = kept
        removed[name] = len(group) - len(kept)
        if {r['label'] for r in kept} != {0, 1}:
            raise ValueError(f'Both labels required after deduplication in {name}')
    bundle = {'source': REPOSITORY, 'revision': REVISION, 'suite': 'RE3',
              'label_policy': '60-second windows before/during synthetic code-fault exposure; exclude normal baseline and injection transition. These are weak window labels, not malicious request or per-request failure labels.',
              'case_partitions': parts, 'splits': result, 'removed_duplicate_or_ambiguous_windows': removed,
              'hashes': {str(p.relative_to(args.data)): hashlib.sha256(p.read_bytes()).hexdigest() for p in [index_path] + paths},
              'downloaded_bytes': sum(p.stat().st_size for p in [index_path] + paths)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(bundle, indent=2, allow_nan=False), encoding='utf-8')
    print(json.dumps({'cases': {k: len(v) for k, v in parts.items()},
                      'windows': {k: {str(c): sum(r['label'] == c for r in v) for c in (0, 1)} for k, v in result.items()},
                      'downloaded_bytes': bundle['downloaded_bytes'], 'output': str(args.output)}, indent=2), flush=True)


if __name__ == '__main__':
    main()
