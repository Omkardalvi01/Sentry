import datetime as dt
import json
import sqlite3
import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'anomaly-detector'))
from database import initialize, connect
from detector import DetectorService, ModelRegistry, ModelVersion, endpoint_key, extract_features, fit_model

def events(n=128):
    return [dict(request_id=str(i), spec_title='test', spec_version='1', method='GET', path=f'/users/{i}',
                 graph_path_template='/users/{id}', graph_known=True, graph_context_status='resolved',
                 graph_security='[]', request_body='', response_body=json.dumps({'data':'x'*(20+i%8)}),
                 status_code=200, timestamp=(dt.datetime(2026,1,1,tzinfo=dt.timezone.utc)+dt.timedelta(minutes=i)).isoformat())
            for i in range(n)]

def test_documented_new_resource_is_not_shadow():
    model = ModelVersion('rules', 'now')
    result = model.predict(events(1)[0])
    assert not result['is_anomaly'] and result['new_observation']
    assert endpoint_key(events(2)[0]) == endpoint_key(events(2)[1])

def test_missing_graph_is_unknown():
    e = events(1)[0]; e['graph_known'] = None
    assert not ModelVersion('rules','now').predict(e)['inventory_signals']

def test_normal_then_abnormal_same_endpoint(tmp_path):
    data = events()
    model = fit_model(data[:96], data[96:])
    service = DetectorService(str(tmp_path/'traffic.db'))
    service.active_model = model
    normal = data[100].copy(); abnormal = normal | {'response_body':'x'*1000000,'status_code':500}
    first,second = service.predict(normal),service.predict(abnormal)
    assert first['anomaly_score'] != second['anomaly_score']
    assert second['behavioral_anomaly']
    assert first['evaluation_status'] == second['evaluation_status'] == 'evaluated'

def test_registry_and_rollback(tmp_path):
    service = DetectorService(str(tmp_path/'traffic.db')); data=events()
    model=fit_model(data[:96],data[96:]); service.registry.save_model(model)
    second=fit_model(data[:96],data[96:],seed=88); service.registry.save_model(second)
    service.rollback(model.version_id)
    assert DetectorService(service.db_path).active_model.version_id == model.version_id
    assert service.active_model.predict(data[0]) == service.registry.load(model.version_id).predict(data[0])
    with pytest.raises(ValueError): service.rollback('unknown')

def test_training_uses_approved_window_and_retains_old_on_failure(tmp_path):
    path=str(tmp_path/'traffic.db'); service=DetectorService(path)
    with connect(path) as conn:
        for e in events():
            conn.execute('INSERT INTO api_traffic(request_id,method,path,timestamp,request_body,response_body,status_code,graph_path_template,graph_known,graph_security,spec_title,spec_version,training_eligible) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)',
                         tuple(e[k] for k in ['request_id','method','path','timestamp','request_body','response_body','status_code','graph_path_template','graph_known','graph_security','spec_title','spec_version']))
    version=service.train_new_model('2026-01-01T00:00:00Z','2026-01-02T00:00:00Z')
    assert service.active_model.metadata['training_count'] == 102
    assert service.active_model.metadata['validation_count'] == 26
    with pytest.raises(ValueError): service.train_new_model('2026-02-01T00:00:00Z','2026-02-02T00:00:00Z')
    assert service.active_model.version_id == version

def test_cyclic_time_and_security():
    e=events(1)[0] | {'graph_security':'[{}, {"bearer":[]}]'}
    features=extract_features(e)
    assert features[-1] == 0
    e['timestamp']=None
    assert extract_features(e)[6] == 0

def test_legacy_database_upgrade(tmp_path):
    path=str(tmp_path/'legacy.db')
    with sqlite3.connect(path) as conn:
        conn.execute('CREATE TABLE api_traffic(id INTEGER PRIMARY KEY,request_id TEXT UNIQUE,method TEXT,path TEXT,timestamp TEXT)')
    initialize(path)
    with connect(path) as conn:
        assert 'graph_known' in {row['name'] for row in conn.execute('PRAGMA table_info(api_traffic)')}

def test_api_lifecycle_and_validation(tmp_path, monkeypatch):
    import app as detector_api
    from fastapi.testclient import TestClient
    monkeypatch.setattr(detector_api, 'DB_PATH', str(tmp_path/'api.db'))
    with TestClient(detector_api.app) as client:
        assert client.get('/health').json()['status'] == 'rules_only'
        assert client.post('/predict', json=events(1)[0]).json()['evaluation_status'] == 'evaluated'
        assert client.post('/predict', json=events(1)[0] | {'status_code': 0}).status_code == 422
        assert client.post('/models/retrain', json={}).status_code == 409
        assert client.get('/health').json()['status'] == 'rules_only'
        assert client.post('/models/missing/activate').status_code == 404
