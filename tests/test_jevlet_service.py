"""Verify the active HTTP contract and isolation from the legacy registry."""
import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'anomaly-detector'))
from detector import ModelRegistry, ModelVersion
from jevlet_service import JevletService


def checkpoint(path, threshold=.5):
    (path / 'jevlet').mkdir(parents=True)
    (path / 'jevlet/model.safetensors').write_bytes(b'test-double-not-real-weights')
    (path / 'baseline.pkl').write_bytes(b'trusted-test-double')
    (path / 'models.json').write_text(json.dumps({'jevlet': {'threshold': threshold}}))
    return path


def runtime(path):
    threshold = json.loads((path / 'models.json').read_text())['jevlet']['threshold']
    baseline = ModelVersion('preprocessing-only', 'now', metadata={'feature_version': 'endpoint-relative-v2'})
    def predict(event):
        score = .9 if event.get('request_body') == 'attack' else .1
        return {'behavioral_anomaly': score >= threshold, 'anomaly_score': score, 'threshold': threshold}
    return SimpleNamespace(baseline=baseline, predict=predict), None


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setenv('SENTRY_JEVLET_MODEL_DIR', str(tmp_path / 'models'))
    return JevletService(tmp_path / 'traffic.db', checkpoint(tmp_path / 'initial'),
                         device='cpu', model_factory=runtime)


def event(**extras):
    return {'request_id': 'one', 'method': 'GET', 'path': '/items',
            'timestamp': '2026-10-11T00:00:00Z', 'status_code': 200} | extras


def test_inventory_separate_and_size_rule_disabled(service):
    normal = service.predict(event(response_body='x' * 100000))
    assert not normal['behavioral_anomaly'] and not normal['numerical_anomaly']
    shadow = service.predict(event(graph_known=False))
    assert shadow['is_anomaly'] and 'shadow_candidate' in shadow['inventory_signals']
    assert not shadow['behavioral_anomaly']
    anomaly = service.predict(event(request_body='attack'))
    assert anomaly['behavioral_anomaly'] and anomaly['model_kind'] == 'jevlet'
    assert anomaly['model_version'].startswith('jevlet-')


def test_registry_preserves_forest_and_restarts(service, tmp_path):
    legacy = ModelRegistry(service.db_path)
    legacy.save_model(ModelVersion('legacy-forest', 'now'))
    legacy_before = legacy.list_models()
    candidate = service._candidate(checkpoint(tmp_path / 'second', .95))
    service._register(candidate)
    service.activate(candidate.version_id)
    assert not service.predict(event(request_body='attack'))['behavioral_anomaly']
    assert legacy.list_models() == legacy_before
    restored = JevletService(service.db_path, device='cpu', model_factory=runtime)
    assert restored.active_model.version_id == candidate.version_id
    (candidate.path / 'models.json').write_text('{"jevlet":{"threshold":0.8}}')
    with pytest.raises(ValueError, match='changed'):
        restored.activate(candidate.version_id)
    assert restored.active_model.version_id == candidate.version_id


def test_failure_head_must_match_encoder(service, tmp_path):
    path = checkpoint(tmp_path / 'failure')
    (path / 'failure-model.json').write_text(json.dumps({'encoder_sha256': 'wrong'}))
    with pytest.raises(ValueError, match='different Jevlet encoder'):
        service._candidate(path)


def test_checkpoint_registration_keeps_current_activation_until_requested(service, tmp_path):
    before = service.active_model.version_id
    path = checkpoint(tmp_path / 'registered', .95)
    version = service.register_checkpoint(path)
    assert service.active_model.version_id == before
    restored = JevletService(service.db_path, device='cpu', model_factory=runtime)
    assert restored.active_model.version_id == before
    service.activate(version)
    assert service.active_model.version_id == version
    assert not service.predict(event(request_body='attack'))['behavioral_anomaly']


def test_adapter_head_and_thresholds_are_part_of_version_identity(service, tmp_path):
    path = checkpoint(tmp_path / 'adapted')
    (path / 'request-adapter.json').write_text('{"scopes":{"app":{"threshold":0.2}}}')
    with pytest.raises(ValueError, match='weights missing'):
        service._candidate(path)
    (path / 'request-head.safetensors').write_bytes(b'first')
    first = service._candidate(path)
    service._register(first)
    (path / 'request-head.safetensors').write_bytes(b'second')
    assert service._candidate(path).version_id != first.version_id
    with pytest.raises(ValueError, match='changed'):
        service.activate(first.version_id)


def test_api_routes_validation_review_and_failure_unavailable(service, monkeypatch):
    import app as api
    monkeypatch.setattr(api, 'JevletService', lambda db: service)
    monkeypatch.delenv('SENTRY_REVIEW_TOKEN', raising=False)
    with TestClient(api.app) as client:
        assert client.get('/health').json()['model_kind'] == 'jevlet'
        assert client.post('/jevlet/predict', json=event()).json()['evaluation_status'] == 'evaluated'
        assert client.post('/jevlet/predict', json=event(status_code=0)).status_code == 422
        assert client.post('/jevlet/predict', json=event(timestamp='2026-10-11T00:00:00')).status_code == 422
        assert client.post('/predict', json=event()).status_code == 404
        assert client.get('/models').status_code == 404
        assert client.post('/models/retrain', json={}).status_code == 404
        assert client.post('/models/old/activate').status_code == 404
        assert client.get('/jevlet/models').json()['models'][0]['active']
        assert client.post('/jevlet/models/missing/activate').status_code == 404
        assert client.post('/jevlet/service-failure', json={'telemetry_text':'window'}).status_code == 409
        assert client.post('/jevlet/service-failure', json={'telemetry_text':''}).status_code == 422
        assert client.put('/traffic/one/review', json={'label':'normal'}).status_code == 503
        monkeypatch.setenv('SENTRY_REVIEW_TOKEN', 'test-token')
        assert client.put('/traffic/one/review', json={'label':'normal'}).status_code == 401
        assert client.put('/traffic/missing/review', json={'label':'normal'}, headers={'X-Review-Token':'test-token'}).status_code == 404


def test_retraining_needs_reviewed_data_and_retains_active(service, monkeypatch):
    import torch
    import app as api
    monkeypatch.setattr(torch.cuda, 'is_available', lambda: True)
    monkeypatch.setattr(api, 'JevletService', lambda db: service)
    before = service.active_model.version_id
    with TestClient(api.app) as client:
        response = client.post('/jevlet/models/retrain', json={})
        assert response.status_code == 409 and 'reviewed' in response.json()['detail']
        assert service.active_model.version_id == before
        assert client.post('/jevlet/models/retrain', json={'start':'not-a-date'}).status_code == 409
        assert client.post('/jevlet/models/retrain', json={'start':'2026-10-01'}).status_code == 409
