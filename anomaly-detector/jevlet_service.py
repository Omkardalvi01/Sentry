"""Active Jevlet event service; the legacy forest remains in detector.py."""

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
from types import SimpleNamespace

from database import connect, initialize

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'evaluation'))


class JevletService:
    def __init__(self, db_path, checkpoint=None, repo=None, device=None, model_factory=None):
        self.db_path = str(db_path)
        self.repo = Path(repo or os.environ.get('SENTRY_JEVLET_REPO',
                         str(ROOT.parents[1] / 'DL/mini_proj/jevlet'))).resolve()
        self.device = device or os.environ.get('SENTRY_JEVLET_DEVICE', 'cuda')
        self._factory = model_factory or self._load_runtime
        self._mutation = threading.Lock()
        self._prediction = threading.Lock()
        self.last_training_error = None
        self.model_dir = Path(os.environ.get('SENTRY_JEVLET_MODEL_DIR', str(ROOT / '.local-data/jevlet-models'))).resolve()
        initialize(self.db_path)
        with connect(self.db_path) as conn:
            conn.executescript('''CREATE TABLE IF NOT EXISTS jevlet_registry
                (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, checkpoint TEXT NOT NULL, metadata TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS jevlet_activation
                (singleton INTEGER PRIMARY KEY CHECK(singleton=1), model_id TEXT NOT NULL REFERENCES jevlet_registry(id));''')
            active = conn.execute('''SELECT r.* FROM jevlet_registry r JOIN jevlet_activation a
                                   ON r.id=a.model_id WHERE a.singleton=1''').fetchone()
        if active:
            self.active_model = self._candidate(Path(active['checkpoint']))
            if self.active_model.version_id != active['id']:
                raise ValueError('Active Jevlet checkpoint changed since registration')
        else:
            initial = Path(checkpoint or os.environ.get('SENTRY_JEVLET_CHECKPOINT',
                           str(self.model_dir / 'bootstrap'))).resolve()
            self.active_model = self._candidate(initial)
            self._register(self.active_model)

    def _load_runtime(self, checkpoint):
        os.environ.setdefault('USE_TF', '0')
        os.environ.setdefault('TOKENIZERS_PARALLELISM', 'false')
        os.environ.setdefault('HF_HOME', str(self.repo / '.cache/huggingface'))
        import torch
        torch.set_num_threads(int(os.environ.get('SENTRY_JEVLET_THREADS', '4')))
        if self.device.startswith('cuda') and not torch.cuda.is_available():
            raise ValueError('CUDA unavailable; set SENTRY_JEVLET_DEVICE=cpu explicitly for CPU inference')
        if (checkpoint / 'failure-model.json').exists():
            from jevlet_failures import JevletWithFailures
            failures = JevletWithFailures.load(checkpoint, self.repo, self.device)
            return failures.security, failures
        from local_models import LocalDetector
        return LocalDetector.load(checkpoint, 'jevlet', self.repo, self.device), None

    def _candidate(self, path):
        path = path.resolve()
        weights = path / 'jevlet/model.safetensors'
        if not weights.is_file() or not (path / 'models.json').is_file():
            raise ValueError(f'Jevlet checkpoint missing: {path}. Configure SENTRY_JEVLET_CHECKPOINT.')
        digest = hashlib.sha256(weights.read_bytes()).hexdigest()
        manifest = json.loads((path / 'models.json').read_text(encoding='utf-8'))
        threshold = float(manifest['jevlet']['threshold'])
        if not 0 <= threshold <= 1:
            raise ValueError('Invalid Jevlet classification threshold')
        failure_config = (json.loads((path / 'failure-model.json').read_text())
                          if (path / 'failure-model.json').exists() else None)
        if failure_config and failure_config['encoder_sha256'] != digest:
            raise ValueError('Failure head was trained with a different Jevlet encoder')
        config_hashes = {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in sorted((path / 'jevlet').rglob('*')) if p.is_file() and p != weights}
        spec_digest = hashlib.sha256(json.dumps({'weights': digest, 'threshold': threshold,
                      'configuration': config_hashes,
                      'baseline': hashlib.sha256((path / 'baseline.pkl').read_bytes()).hexdigest(),
                      'failure': hashlib.sha256((path / 'failure-head.safetensors').read_bytes()).hexdigest()
                      if (path / 'failure-head.safetensors').exists() else None,
                      'failure_config': failure_config}, sort_keys=True).encode()).hexdigest()
        adapter_config = path / 'request-adapter.json'
        if adapter_config.exists():
            head = path / 'request-head.safetensors'
            if not head.is_file():
                raise ValueError('Request adapter weights missing')
            spec_digest = hashlib.sha256((spec_digest + hashlib.sha256(adapter_config.read_bytes()).hexdigest()
                                         + hashlib.sha256(head.read_bytes()).hexdigest()).encode()).hexdigest()
        runtime, failures = self._factory(path)
        created = dt.datetime.now(dt.timezone.utc).isoformat()
        return SimpleNamespace(version_id='jevlet-' + spec_digest[:20], created_at=created,
                 path=path, runtime=runtime, failures=failures,
                 known_endpoints=runtime.baseline.known_endpoints,
                 metadata={'model_kind': 'jevlet', 'checkpoint_sha256': digest,
                           'feature_version': runtime.baseline.metadata['feature_version'],
                           'threshold': threshold, 'device': self.device, 'precision': 'fp32',
                           'service_failure_available': failures is not None,
                           'input_policy': 'bounded captured event evidence; labels and identities excluded',
                           'training': manifest['jevlet'].get('metrics', {})})

    def _register(self, candidate):
        with connect(self.db_path) as conn:
            conn.execute('INSERT OR IGNORE INTO jevlet_registry VALUES (?,?,?,?)',
                         (candidate.version_id, candidate.created_at, str(candidate.path), json.dumps(candidate.metadata)))
            conn.execute('''INSERT INTO jevlet_activation VALUES (1,?) ON CONFLICT(singleton)
                          DO UPDATE SET model_id=excluded.model_id''', (candidate.version_id,))

    def register_checkpoint(self, path):
        """Validate a trusted local checkpoint without changing activation."""
        if not self._mutation.acquire(blocking=False):
            raise ValueError('Jevlet training or activation already running')
        try:
            candidate = self._candidate(Path(path))
            with connect(self.db_path) as conn:
                conn.execute('INSERT OR IGNORE INTO jevlet_registry VALUES (?,?,?,?)',
                             (candidate.version_id, candidate.created_at, str(candidate.path),
                              json.dumps(candidate.metadata)))
            return candidate.version_id
        finally:
            self._mutation.release()

    def predict(self, event):
        # Take an immutable snapshot so an activation cannot mix model/threshold.
        with self._prediction:
            current = self.active_model
            result = current.runtime.baseline.predict(event, ml=False, numerical=False)
            prediction = current.runtime.predict(event)
        behavioral = prediction['behavioral_anomaly']
        if behavioral:
            result['reasons'].append('Jevlet classified the captured request evidence as anomalous')
        result.update(is_anomaly=bool(result['inventory_signals']) or behavioral,
                      behavioral_anomaly=behavioral, ml_anomaly=behavioral, numerical_anomaly=False,
                      anomaly_score=prediction['anomaly_score'], threshold=prediction['threshold'],
                      behavioral_score=prediction['anomaly_score'], score_kind='jevlet_classifier_score',
                      model_kind='jevlet', model_version=current.version_id)
        return result

    def predict_service_failure(self, text):
        with self._prediction:
            current = self.active_model
            if current.failures is None:
                raise ValueError('This checkpoint has no trained service-failure classifier')
            result = current.failures.predict(telemetry_text=text)['service_failure']
        return result | {'evaluation_status': 'evaluated', 'model_kind': 'jevlet_service_failure',
                         'model_version': current.version_id}

    def list_models(self):
        with connect(self.db_path) as conn:
            rows = conn.execute('SELECT * FROM jevlet_registry ORDER BY created_at DESC').fetchall()
        return [{'id': r['id'], 'created_at': r['created_at'], 'metadata': json.loads(r['metadata']),
                 'active': r['id'] == self.active_model.version_id} for r in rows]

    def activate(self, version):
        if not self._mutation.acquire(blocking=False):
            raise ValueError('Jevlet training or activation already running')
        try:
            with connect(self.db_path) as conn:
                row = conn.execute('SELECT checkpoint FROM jevlet_registry WHERE id=?', (version,)).fetchone()
            if row is None:
                raise ValueError('Unknown Jevlet model version')
            candidate = self._candidate(Path(row['checkpoint']))
            if candidate.version_id != version:
                raise ValueError('Registered checkpoint changed')
            with self._prediction:
                self._register(candidate)
                self.active_model = candidate
            return version
        finally:
            self._mutation.release()

    def review_event(self, request_id, label):
        if label not in (0, 1):
            raise ValueError('Review label must be normal or anomaly')
        with connect(self.db_path) as conn:
            changed = conn.execute('UPDATE api_traffic SET review_label=? WHERE request_id=?', (label, request_id)).rowcount
        if not changed:
            raise ValueError('Unknown request_id')

    def train_new_model(self, start=None, end=None, target_fpr=0.05):
        """Train Jevlet on reviewed labels only. Never fit a forest or self-label."""
        if not self._mutation.acquire(blocking=False):
            raise ValueError('Jevlet training or activation already running')
        directory = None
        try:
            import numpy as np
            import torch
            from sklearn.model_selection import train_test_split
            from compare_local_models import train_jevlet, write_json
            from local_models import LocalDetector, normal_baseline, threshold_at_fpr
            if not torch.cuda.is_available():
                raise ValueError('Jevlet retraining requires CUDA')
            end = end or dt.datetime.now(dt.timezone.utc).isoformat()
            start = start or (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=7)).isoformat()
            def instant(value):
                parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
                if parsed.tzinfo is None:
                    raise ValueError('Training timestamps must include a timezone')
                return parsed.astimezone(dt.timezone.utc)
            if instant(start) >= instant(end):
                raise ValueError('Training start must precede end')
            with connect(self.db_path) as conn:
                rows = conn.execute('''SELECT * FROM api_traffic WHERE review_label IN (0,1)
                       AND julianday(timestamp)>=julianday(?) AND julianday(timestamp)<julianday(?)
                       ORDER BY julianday(timestamp),id''', (start, end)).fetchall()
            events = [dict(row) for row in rows]
            for event in events:
                for field in ('request_headers', 'response_headers'):
                    if isinstance(event.get(field), str):
                        event[field] = json.loads(event[field] or '{}')
            normal = [e for e in events if e['review_label'] == 0]
            if len(normal) < 160 or sum(e['review_label'] == 1 for e in events) < 20:
                raise ValueError('Jevlet requires at least 160 reviewed normal events and 20 reviewed anomalies')
            boundary = instant(normal[int(len(normal) * .8)]['timestamp'])
            earlier = [e for e in events if instant(e['timestamp']) < boundary]
            calibration = [e for e in events if instant(e['timestamp']) >= boundary and e['review_label'] == 0]
            training, selection = train_test_split(earlier, test_size=.2, random_state=42,
                                                   stratify=[e['review_label'] for e in earlier])
            if len(calibration) < 32 or any({e['review_label'] for e in group} != {0, 1} for group in (training, selection)):
                raise ValueError('Reviewed data needs both classes in training/selection and a later normal calibration window')
            groups = {'train': training, 'selection': selection}
            targets = {name: np.asarray([e['review_label'] for e in group]) for name, group in groups.items()}
            baseline = normal_baseline([e for e in training if e['review_label'] == 0])
            self.model_dir.mkdir(parents=True, exist_ok=True)
            directory = self.model_dir / ('trained-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%f'))
            directory.mkdir()
            import pickle
            with (directory / 'baseline.pkl').open('wb') as stream:
                pickle.dump(baseline, stream)
            args = SimpleNamespace(base_model='distilbert/distilbert-base-uncased', max_length=384,
                                   samples_per_epoch=4096, epochs=6, batch_size=16)
            model, detail = train_jevlet(args, directory, baseline, groups, targets, 42)
            scorer = LocalDetector('jevlet', model, baseline, 0)
            scorer.threshold = threshold_at_fpr(scorer.score(calibration), target_fpr)
            write_json(directory / 'models.json', {'jevlet': {'threshold': scorer.threshold,
                       'metrics': {'training_device': 'cuda', 'reviewed_only': True,
                                   'training_rows': len(training), 'selection_rows': len(selection),
                                   'calibration_normals': len(calibration), 'window_start': start, 'window_end': end}}})
            del scorer, model
            torch.cuda.empty_cache()
            candidate = self._candidate(directory)
            with self._prediction:
                self._register(candidate)
                self.active_model = candidate
            self.last_training_error = None
            return candidate.version_id
        except Exception as exc:
            self.last_training_error = str(exc)
            raise
        finally:
            self._mutation.release()

    def health(self):
        current = self.active_model
        return {'status': 'healthy', 'active_model_id': current.version_id, 'model_kind': 'jevlet',
                'device': self.device, 'precision': 'fp32', 'tracked_endpoints': len(current.known_endpoints),
                'service_failure_available': current.failures is not None,
                'last_training_error': self.last_training_error,
                'prediction_cache': 'disabled; each event is evaluated'}
