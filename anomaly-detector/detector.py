"""Inventory decisions and behavioral novelty are separate, inspectable signals."""
import base64
import datetime as dt
import hashlib
import json
import math
import pickle
import re
import threading
import uuid
from urllib.parse import unquote

import numpy as np
from sklearn.ensemble import ExtraTreesClassifier, IsolationForest
from database import connect, initialize

FEATURE_VERSION = 'endpoint-relative-v2'
LEGACY_FEATURE_VERSION = 'endpoint-relative-v1'

def endpoint_key_v1(event):
    return json.dumps([event.get('spec_title') or '', event.get('spec_version') or '',
                       (event.get('method') or '').upper(),
                       event.get('graph_path_template') or event.get('path') or ''], separators=(',', ':'))

def endpoint_key(event):
    path = event.get('graph_path_template') or event.get('path') or ''
    if not event.get('graph_path_template'):
        parts = path.split('/')
        path = '/'.join('{id}' if index > 1 and
                        (part.isdigit() or re.fullmatch(r'[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}', part))
                        else part for index, part in enumerate(parts))
    return json.dumps([event.get('spec_title') or '', event.get('spec_version') or '',
                       (event.get('method') or '').upper(), path], separators=(',', ':'))

def requires_auth(raw):
    try:
        alternatives = json.loads(raw or '[]')
        return bool(alternatives) and all(bool(requirement) for requirement in alternatives)
    except (TypeError, ValueError):
        return False

def extract_features(event, profiles=None, graph=True, temporal=True):
    key = endpoint_key(event)
    baseline = (profiles or {}).get(key, {'request': 0.0, 'response': 0.0})
    request = math.log1p(len((event.get('request_body') or '').encode()))
    response = math.log1p(len((event.get('response_body') or '').encode()))
    def non_negative(value):
        try:
            number = float(value)
            return number if math.isfinite(number) and number >= 0 else None
        except (TypeError, ValueError):
            return None

    response_time = non_negative(event.get('response_time_ms'))
    response_bytes = non_negative(event.get('response_size_bytes'))
    size_measurement_present = response_bytes is not None and response_bytes > 0
    if not size_measurement_present:
        response_bytes = float(len((event.get('response_body') or '').encode()))
    latency = math.log1p(response_time) if response_time is not None else 0.0
    wire_response = math.log1p(response_bytes)
    timestamp = event.get('timestamp')
    present = 1.0
    try:
        timestamp = dt.datetime.fromisoformat(timestamp.replace('Z', '+00:00')) if isinstance(timestamp, str) else timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=dt.timezone.utc)
        timestamp = timestamp.astimezone(dt.timezone.utc)
        hour = timestamp.hour + timestamp.minute / 60
    except (ValueError, AttributeError, TypeError):
        present, hour = 0.0, 0.0
    status = event.get('status_code')
    if not temporal:
        hour = 0.0
    values = [request - baseline['request'], response - baseline['response'],
              float(status or 0) / 100, float(status is not None),
              math.sin(2 * math.pi * hour / 24), math.cos(2 * math.pi * hour / 24), present]
    method = (event.get('method') or '').upper()
    values.extend(float(method == candidate) for candidate in
                  ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE'))
    path = event.get('path') or '/'
    query = event.get('query_params') or ''
    body = event.get('request_body') or ''
    request_text = (path + '?' + query + ' ' + body).lower()
    decoded = request_text
    for _ in range(2):
        decoded = unquote(decoded).replace('\\', '/')
    segments = [part for part in path.split('/') if part]
    query_count = sum(1 for part in query.split('&') if part)
    status_num = int(status or 0)
    values.extend([
        math.log1p(len(path)), float(len(segments)),
        float(sum(part.isdigit() for part in segments)),
        math.log1p(len(query)), math.log1p(query_count),
        math.log1p(len(body.encode())),
        float(status_num // 100 == 4), float(status_num // 100 == 5),
        float('..' in decoded),
        float(bool(re.search(r'\b(select|union|insert|update|delete|drop)\b|--|\b(or|and)\s+\d+\s*=\s*\d+', decoded))),
        float(bool(re.search(r'<\s*(script|iframe)|javascript:|onerror\s*=', decoded))),
        float(bool(re.search(r'\$\(|\|\||&&|\b(wget|curl|powershell|cmd\.exe)\b', decoded))),
        float('%' in request_text), float('\x00' in request_text),
    ])
    values.extend([
        latency - baseline.get('latency', 0.0), float(response_time is not None),
        wire_response - baseline.get('wire_response', 0.0),
        float(size_measurement_present),
    ])
    headers = event.get('request_headers') or {}
    if isinstance(headers, str):
        try:
            headers = json.loads(headers)
        except (TypeError, ValueError):
            headers = {}
    if not isinstance(headers, dict):
        headers = {}
    header_names = {str(name).lower() for name in headers}
    values.extend([
        float('authorization' in header_names), float('cookie' in header_names),
        float(any(name in header_names for name in ('content-type', 'content_type'))),
        float(any(name in header_names for name in ('user-agent', 'user_agent'))),
    ])
    if graph:
        known = event.get('graph_known')
        values += [float(known is not None), float(bool(known)),
                   float(bool(event.get('graph_deprecated'))), float(requires_auth(event.get('graph_security')))]
    return values

def extract_features_v1(event, profiles=None, graph=True, temporal=True):
    """Keep persisted v1 models usable after the feature vector upgrade."""
    key = endpoint_key_v1(event)
    baseline = (profiles or {}).get(key, {'request': 0.0, 'response': 0.0})
    request = math.log1p(len((event.get('request_body') or '').encode()))
    response = math.log1p(len((event.get('response_body') or '').encode()))
    timestamp = event.get('timestamp')
    present = 1.0
    try:
        timestamp = dt.datetime.fromisoformat(timestamp.replace('Z', '+00:00')) if isinstance(timestamp, str) else timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=dt.timezone.utc)
        timestamp = timestamp.astimezone(dt.timezone.utc)
        hour = timestamp.hour + timestamp.minute / 60
    except (ValueError, AttributeError, TypeError):
        present, hour = 0.0, 0.0
    status = event.get('status_code')
    if not temporal:
        hour = 0.0
    values = [request - baseline['request'], response - baseline['response'],
              float(status or 0) / 100, float(status is not None),
              math.sin(2 * math.pi * hour / 24), math.cos(2 * math.pi * hour / 24), present]
    if graph:
        known = event.get('graph_known')
        values += [float(known is not None), float(bool(known)),
                   float(bool(event.get('graph_deprecated'))), float(requires_auth(event.get('graph_security')))]
    return values

class ModelVersion:
    def __init__(self, version_id, created_at, known_endpoints=None, known_status_codes=None,
                 ml_model_bytes=None, ml_model=None, metadata=None, profiles=None):
        self.version_id, self.created_at = version_id, created_at
        self.known_endpoints = set(known_endpoints or [])
        self.known_status_codes = set(known_status_codes or [])
        self.metadata, self.profiles = metadata or {}, profiles or {}
        self.ml_model_bytes = ml_model_bytes
        # Only models from the locally managed registry may be loaded.
        self.ml_model = ml_model if ml_model is not None else (pickle.loads(ml_model_bytes) if ml_model_bytes else None)

    def predict(self, event, graph=True, ml=True, numerical=True):
        legacy_features = self.metadata.get('feature_version') == LEGACY_FEATURE_VERSION
        key = endpoint_key_v1(event) if legacy_features else endpoint_key(event)
        inventory, reasons = [], []
        known = event.get('graph_known')
        if known is False:
            inventory.append('shadow_candidate')
            reasons.append('Operation is absent from the selected specification; active verification required')
        if known is True and event.get('graph_deprecated'):
            inventory.append('deprecated_observed')
            reasons.append('Traffic observed on a deprecated operation; lifecycle review required')
        new_observation = key not in self.known_endpoints
        score, behavioral, ml_anomaly = None, False, False
        profile = self.profiles.get(key)
        size_score = 0.0
        if profile and numerical:
            size_score = max(abs(math.log1p(len((event.get(field + "_body") or "").encode())) - profile[field]) / profile.get(field + "_scale", 0.1) for field in ["request", "response"])
        numerical_anomaly = profile is not None and numerical and size_score > self.metadata.get("size_threshold", 3.0)
        if ml and self.ml_model is not None:
            extractor = extract_features_v1 if legacy_features else extract_features
            values = np.asarray([extractor(event, self.profiles, graph=graph, temporal=self.metadata.get("temporal_features", True))])
            if self.metadata.get('model_kind') == 'reviewed_extra_trees':
                score = float(self.ml_model.predict_proba(values)[0, 1])
            else:
                score = float(-self.ml_model.score_samples(values)[0])
            ml_anomaly = score >= self.metadata['threshold']
            behavioral = ml_anomaly
            if behavioral:
                reasons.append('Behavior differs from the historical training baseline')
        if numerical_anomaly:
            behavioral = True
            reasons.append("Body size exceeds the validated endpoint-relative baseline")
        behavioral_score = max((score or 0) / max(self.metadata.get("threshold", 1), 1e-9), size_score / self.metadata.get("size_threshold", 3.0))
        return {'is_anomaly': bool(inventory) or behavioral,
                'behavioral_score': behavioral_score, 'numerical_anomaly': bool(numerical_anomaly), 'ml_anomaly': bool(ml_anomaly), 'anomaly_score': score,
                'score_kind': ('reviewed_classifier_score' if self.metadata.get('model_kind') == 'reviewed_extra_trees'
                               else 'isolation_forest_raw_not_probability'), 'reasons': reasons,
                'inventory_signals': inventory, 'behavioral_anomaly': behavioral,
                'new_observation': new_observation, 'operation_key': key,
                'evaluation_status': 'evaluated', 'model_version': self.version_id,
                'graph_context_status': event.get('graph_context_status', 'unknown')}

class ModelRegistry:
    def __init__(self, path):
        self.db_path = path
        initialize(path)

    def save_model(self, model):
        data = {'known_endpoints': sorted(model.known_endpoints), 'known_status_codes': sorted(model.known_status_codes),
                'ml_model_b64': base64.b64encode(model.ml_model_bytes).decode() if model.ml_model_bytes else '',
                'metadata': model.metadata, 'profiles': model.profiles}
        with connect(self.db_path) as conn:
            conn.execute('INSERT INTO model_registry VALUES (?,?,?,?)',
                         (model.version_id, model.created_at, len(model.known_endpoints), json.dumps(data)))
            conn.execute('INSERT INTO model_activation VALUES (1,?) ON CONFLICT(singleton) DO UPDATE SET model_id=excluded.model_id', (model.version_id,))

    def load(self, version_id=None):
        with connect(self.db_path) as conn:
            row = conn.execute('SELECT * FROM model_registry WHERE id=?', (version_id,)).fetchone() if version_id else conn.execute('SELECT * FROM model_registry ORDER BY created_at DESC LIMIT 1').fetchone()
        if row is None:
            return None
        data = json.loads(row['model_data'])
        if data.get('metadata', {}).get('feature_version') not in (FEATURE_VERSION, LEGACY_FEATURE_VERSION):
            return None
        blob = base64.b64decode(data['ml_model_b64']) if data.get('ml_model_b64') else None
        return ModelVersion(row['id'], row['created_at'], data.get('known_endpoints'), data.get('known_status_codes'),
                            blob, metadata=data['metadata'], profiles=data.get('profiles'))

    def load_latest_model(self):
        with connect(self.db_path) as conn:
            row = conn.execute('SELECT model_id FROM model_activation WHERE singleton=1').fetchone()
        return self.load(row['model_id']) if row else self.load()

    def activate(self, version_id):
        with connect(self.db_path) as conn:
            conn.execute('INSERT INTO model_activation VALUES (1,?) ON CONFLICT(singleton) DO UPDATE SET model_id=excluded.model_id', (version_id,))

    def list_models(self):
        with connect(self.db_path) as conn:
            rows = conn.execute('SELECT id,created_at,endpoints_count,model_data FROM model_registry ORDER BY created_at DESC').fetchall()
        return [{'id': row['id'], 'created_at': row['created_at'], 'endpoints_count': row['endpoints_count'],
                 'metadata': json.loads(row['model_data']).get('metadata', {})} for row in rows]


def fit_model(training, validation, graph=True, seed=42, target_fpr=0.05):
    if len(training) < 32 or len(validation) < 16:
        raise ValueError('Training requires at least 32 baseline events and 16 separate validation events')
    if not math.isfinite(target_fpr) or not 0 < target_fpr <= 0.25:
        raise ValueError('target_fpr must be greater than 0 and at most 0.25')
    groups = {}
    for event in training:
        groups.setdefault(endpoint_key(event), []).append(event)
    profiles = {key: {'request': float(np.median([math.log1p(len((e.get('request_body') or '').encode())) for e in group])),
                      'response': float(np.median([math.log1p(len((e.get('response_body') or '').encode())) for e in group]))}
                for key, group in groups.items()}
    for key, group in groups.items():
        for field in ['request', 'response']:
            values = [math.log1p(len((e.get(field + '_body') or '').encode())) for e in group]
            profiles[key][field + '_scale'] = max(float(np.median(np.abs(np.asarray(values) - profiles[key][field]))) * 1.4826, 0.1)
        for field, event_value in (
            ('latency', lambda e: e.get('response_time_ms')),
            ('wire_response', lambda e: e.get('response_size_bytes')),
        ):
            samples = []
            for event in group:
                raw = event_value(event)
                try:
                    value = float(raw)
                    if math.isfinite(value) and value >= 0:
                        samples.append(math.log1p(value))
                except (TypeError, ValueError):
                    continue
            if samples:
                profiles[key][field] = float(np.median(samples))
    timestamps = [dt.datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) for e in training if e.get('timestamp')]
    temporal = bool(timestamps) and (max(timestamps) - min(timestamps)).total_seconds() >= 86400
    residuals = [max(abs(math.log1p(len((e.get(field + '_body') or '').encode())) - profiles[endpoint_key(e)][field]) / profiles[endpoint_key(e)][field + '_scale'] for field in ['request', 'response']) for e in validation if endpoint_key(e) in profiles]
    size_threshold = max(3.0, float(np.quantile(residuals, 1-target_fpr, method='higher'))) if residuals else 3.0
    model = IsolationForest(n_estimators=100, contamination='auto', random_state=seed, n_jobs=1)
    model.fit(np.asarray([extract_features(e, profiles, graph=graph, temporal=temporal) for e in training]))
    scores = -model.score_samples(np.asarray([extract_features(e, profiles, graph=graph, temporal=temporal) for e in validation]))
    threshold = float(np.quantile(scores, 1 - target_fpr, method='higher')) + 1e-12
    metadata = {'feature_version': FEATURE_VERSION, 'graph_features': graph, 'seed': seed,
                'threshold': threshold, 'size_threshold': size_threshold, 'temporal_features': temporal, 'target_validation_fpr': target_fpr,
                'validation_fpr': float(np.mean(scores >= threshold)),
                'training_count': len(training), 'validation_count': len(validation),
                'parameters': model.get_params()}
    return ModelVersion(str(uuid.uuid4()), dt.datetime.now(dt.timezone.utc).isoformat(),
                        set(groups), {e.get('status_code') for e in training}, pickle.dumps(model), model, metadata, profiles)

def fit_reviewed_model(normal_training, anomaly_training, normal_validation, graph=True,
                       seed=42, target_fpr=0.05):
    """Train from normal history plus analyst-confirmed anomaly examples."""
    if len(anomaly_training) < 20:
        raise ValueError('Reviewed training requires at least 20 confirmed anomaly examples')
    baseline = fit_model(normal_training, normal_validation, graph=graph, seed=seed,
                         target_fpr=target_fpr)
    anomaly_ids = {id(event) for event in anomaly_training}
    labeled_events = sorted(list(normal_training) + list(anomaly_training),
                            key=lambda event: str(event.get('timestamp') or ''))
    labels = np.asarray([int(id(event) in anomaly_ids) for event in labeled_events])
    features = np.asarray([
        extract_features(event, baseline.profiles, graph=graph,
                         temporal=baseline.metadata['temporal_features'])
        for event in labeled_events
    ])
    classifier = ExtraTreesClassifier(
        n_estimators=300, min_samples_leaf=2, class_weight='balanced',
        max_features=0.8, n_jobs=1, random_state=seed,
    )
    classifier.fit(features, labels)
    validation_features = np.asarray([
        extract_features(event, baseline.profiles, graph=graph,
                         temporal=baseline.metadata['temporal_features'])
        for event in normal_validation
    ])
    validation_scores = classifier.predict_proba(validation_features)[:, 1]
    threshold = float(np.quantile(validation_scores, 1 - target_fpr, method='higher')) + 1e-12
    baseline.ml_model = classifier
    baseline.ml_model_bytes = pickle.dumps(classifier)
    baseline.metadata.update({
        'model_kind': 'reviewed_extra_trees',
        'threshold': threshold,
        'validation_fpr': float(np.mean(validation_scores >= threshold)),
        'target_validation_fpr': target_fpr,
        'training_count': len(labeled_events),
        'training_normal_count': len(normal_training),
        'training_reviewed_anomaly_count': len(anomaly_training),
        'validation_count': len(normal_validation),
        'parameters': classifier.get_params(),
    })
    baseline.known_endpoints.update(endpoint_key(event) for event in anomaly_training)
    baseline.known_status_codes.update(event.get('status_code') for event in anomaly_training)
    return baseline

class DetectorService:
    def __init__(self, db_path, cache=None):
        self.db_path, self.cache = db_path, cache
        self.registry = ModelRegistry(db_path)
        self._lock = threading.Lock()
        self.active_model = self.registry.load_latest_model()
        self.last_training_error = None
        # Inventory evaluation remains available during ML cold start.
        self.rules_model = ModelVersion('rules-only', dt.datetime.now(dt.timezone.utc).isoformat())

    def predict(self, event):
        current = self.active_model or self.rules_model
        # Do not reuse endpoint-level predictions: every request can be anomalous.
        return current.predict(event, graph=current.metadata.get('graph_features', True))

    def train_new_model(self, start=None, end=None, target_fpr=0.05):
        if not self._lock.acquire(blocking=False):
            raise ValueError('Training or rollback is already running')
        try:
            end = end or dt.datetime.now(dt.timezone.utc).isoformat()
            start = start or (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=7)).isoformat()
            if dt.datetime.fromisoformat(start.replace('Z', '+00:00')) >= dt.datetime.fromisoformat(end.replace('Z', '+00:00')):
                raise ValueError('Training start must precede end')
            with connect(self.db_path) as conn:
                rows = conn.execute('''SELECT t.* FROM api_traffic t LEFT JOIN predictions p ON t.request_id=p.request_id
                    WHERE (t.training_eligible=1 OR t.review_label IN (0,1))
                    AND julianday(t.timestamp)>=julianday(?) AND julianday(t.timestamp)<julianday(?)
                    AND (t.review_label IS NOT NULL OR p.status IS NULL OR (p.status='evaluated' AND json_extract(p.result,'$.is_anomaly')=0))
                    ORDER BY julianday(t.timestamp),t.id''', (start, end)).fetchall()
            events = [dict(row) for row in rows]
            for e in events:
                if e.get('graph_known') is not None:
                    e['graph_known'] = bool(e['graph_known'])
            cut = int(len(events) * 0.8)
            if cut and cut < len(events):
                # Keep events with an identical timestamp in one split.
                boundary = events[cut]['timestamp']
                while cut > 0 and events[cut-1]['timestamp'] == boundary:
                    cut -= 1
            training, validation = events[:cut], events[cut:]
            training_normals = [event for event in training if event.get('review_label') != 1]
            training_anomalies = [event for event in training if event.get('review_label') == 1]
            validation_normals = [event for event in validation if event.get('review_label') != 1]
            if len(training_anomalies) >= 20:
                trained = fit_reviewed_model(training_normals, training_anomalies,
                                             validation_normals, target_fpr=target_fpr)
            else:
                trained = fit_model(training_normals, validation_normals, target_fpr=target_fpr)
            trained.metadata.update({'window_start': start, 'window_end': end,
                'training_last_timestamp': training[-1]['timestamp'], 'validation_first_timestamp': validation[0]['timestamp'],
                'data_digest': hashlib.sha256(json.dumps(events, sort_keys=True).encode()).hexdigest()})
            self.registry.save_model(trained)
            self.active_model = trained
            self.last_training_error = None
            return trained.version_id
        except Exception as exc:
            self.last_training_error = str(exc)
            raise
        finally:
            self._lock.release()

    def review_event(self, request_id, label):
        if label not in (0, 1):
            raise ValueError('review label must be 0 (normal) or 1 (anomaly)')
        with connect(self.db_path) as conn:
            cursor = conn.execute('UPDATE api_traffic SET review_label=? WHERE request_id=?',
                                  (label, request_id))
            if cursor.rowcount == 0:
                raise ValueError('Unknown request_id')

    def rollback(self, version_id):
        with self._lock:
            model = self.registry.load(version_id)
            if model is None:
                raise ValueError('Unknown or incompatible model version')
            self.registry.activate(model.version_id)
            self.active_model = model
            return model.version_id
