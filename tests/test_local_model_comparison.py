"""Guard against label leakage and calibration/split mistakes in the experiment."""

import copy
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'evaluation'))
from compare_local_models import metrics, split_rows, timestamp
from local_models import LocalDetector, event_text, threshold_at_fpr

def test_wire_size_has_identical_text_after_http_integer_validation():
    baseline = type('Baseline', (), {'profiles': {}, 'metadata': {'temporal_features': False}})()
    event = {'method': 'GET', 'path': '/items', 'status_code': 200, 'response_size_bytes': 120.0}
    assert event_text(event, baseline) == event_text(event | {'response_size_bytes':120}, baseline)


def test_calibration_is_later_and_selection_has_both_labels():
    rows = [{'timestamp': f'2023/7/19 14:{i // 3:02}', 'type': 'normal'} for i in range(120)]
    rows += [{'timestamp': f'2023/7/19 14:{i:02}', 'type': 'anomaly'} for i in range(10)]
    parts = split_rows(rows)
    moments = {name: {timestamp(row) for row in group} for name, group in parts.items()}
    assert not moments['selection'] & moments['calibration']
    assert not moments['train'] & moments['calibration']
    assert max(moments['train']) < min(moments['calibration'])
    assert max(moments['selection']) < min(moments['calibration'])
    assert sum(len(group) for group in parts.values()) == len(rows)
    assert {r['type'] for r in parts['train']} == {r['type'] for r in parts['selection']} == {'normal', 'anomaly'}


def test_calibration_threshold_does_not_flag_tied_normal_scores():
    scores = np.array([0.2] * 100)
    threshold = threshold_at_fpr(scores, 0.05)
    assert not (scores >= threshold).any()
    with pytest.raises(ValueError):
        threshold_at_fpr([], 0.05)
    with pytest.raises(ValueError):
        threshold_at_fpr([np.nan], 0.05)


def test_text_never_contains_label_identity_or_header_secrets():
    class Baseline:
        profiles = {}
        metadata = {'temporal_features': False}
    event = {'method': 'GET', 'path': '/items', 'request_id': 'private-request-id',
             'client_id': 'private-person', 'type': 'anomaly', 'review_label': 1,
             'request_headers': {'Authorization': 'private-token'}, 'status_code': 200}
    changed = copy.deepcopy(event)
    changed.update(type='normal', review_label=0, request_id='other', client_id='other')
    assert event_text(event, Baseline()) == event_text(changed, Baseline())
    text = event_text(event, Baseline())
    assert all(secret not in text for secret in ['private-token', 'private-person', 'private-request-id'])


def test_metrics_count_missed_anomalies_and_false_alarms():
    result = metrics(np.array([True, True, False, False]), np.array([0.8, 0.2, 0.7, 0.1]), 0.5)
    assert result['true_positive'] == result['false_positive'] == result['false_negative'] == result['true_negative'] == 1
    assert result['f1'] == result['false_positive_rate'] == 0.5


def test_adapter_uses_probability_column_and_configured_threshold():
    class Classifier:
        def predict_proba(self, values):
            return np.array([[0.1, 0.9]] * len(values))
    class Baseline:
        profiles = {}
        metadata = {'temporal_features': False}
    detector = LocalDetector('catboost', Classifier(), Baseline(), 0.8)
    assert detector.predict({'method': 'GET', 'path': '/'})['behavioral_anomaly']
    detector.threshold = 0.95
    assert not detector.predict({'method': 'GET', 'path': '/'})['behavioral_anomaly']
