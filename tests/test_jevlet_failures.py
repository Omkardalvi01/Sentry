"""Protect fault labels, incident isolation, and gradient-free encoder features."""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'evaluation'))
from prepare_jevlet_failures import normalize_message, partition_cases, seconds, windows
from jevlet_failures import FailureClassifier


def test_incidents_remain_disjoint_and_each_application_is_represented():
    cases = [f're3{system}_svc_f1_{n}' for system in ('ob', 'ss', 'tt') for n in range(30)]
    parts = partition_cases(cases)
    assert sorted(case for group in parts.values() for case in group) == sorted(cases)
    names = list(parts)
    for i, name in enumerate(names):
        assert {case.split('_')[0] for case in parts[name]} == {'re3ob', 're3ss', 're3tt'}
        for other in names[:i]:
            assert not set(parts[name]) & set(parts[other])


def test_trace_clock_units_are_normalized():
    epoch = 1_700_000_000
    for multiplier in (1, 1000, 1_000_000, 1_000_000_000):
        values = pd.Series([epoch * multiplier, (epoch + 60) * multiplier])
        np.testing.assert_allclose(seconds(values), [epoch, epoch + 60])


def test_window_labels_exclude_warmup_and_injection_transition(tmp_path):
    epoch = 1_700_000_000
    inject = epoch + 360
    directory = tmp_path / 're3ob_service_f1_1'
    directory.mkdir()
    times = np.arange(epoch, epoch + 780)
    pd.DataFrame({'time': times, 'svc_cpu': np.where(times < inject, 1, 4)}).to_parquet(directory / 'metrics.parquet')
    pd.DataFrame({'timestamp': times * 1000, 'message': np.where(times < inject, 'request handled', 'ERROR timeout')}).to_parquet(directory / 'logs.parquet')
    (directory / 'inject_time.txt').write_text(str(inject))
    records = windows(directory.name, tmp_path)
    assert {r['label'] for r in records} == {0, 1}
    for record in records:
        assert record['start'] >= epoch + 180
        assert record['end'] <= inject - 60 or record['start'] >= inject + 60
        assert record['label'] == int(record['start'] >= inject + 60)
        assert str(inject) not in record['text']
        assert directory.name not in record['text']
    assert all('ERROR timeout' in r['text'] for r in records if r['label'])


def test_clock_and_identifier_removed_without_losing_error_evidence():
    text = normalize_message('2026-01-01T12:13:14Z ERROR timeout id 01234567-89ab-cdef-0123-456789abcdef')
    assert 'ERROR timeout' in text
    assert '2026-01-01' not in text
    assert '01234567' not in text


def test_frozen_inference_features_can_train_separate_head():
    with torch.inference_mode():
        encoded = torch.randn(8, 12)
    features = encoded.detach().clone()
    head = FailureClassifier(12)
    torch.nn.functional.cross_entropy(head(features), torch.tensor([0, 1] * 4)).backward()
    assert head.classifier.weight.grad is not None
    assert features.grad is None
