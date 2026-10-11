"""Shared event preprocessing and checkpoint adapters for evaluation and Jevlet serving."""

import json
import math
import pickle
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'anomaly-detector'))
from detector import FEATURE_VERSION, ModelVersion, endpoint_key, extract_features  # noqa: E402


def normal_baseline(events):
    """Fit normal-only preprocessing statistics without training any CPU model."""
    import datetime as dt
    groups = {}
    for event in events:
        groups.setdefault(endpoint_key(event), []).append(event)
    profiles = {}
    for key, group in groups.items():
        profile = {}
        for field in ('request', 'response'):
            values = np.asarray([math.log1p(len((e.get(field + '_body') or '').encode())) for e in group])
            profile[field] = float(np.median(values))
            profile[field + '_scale'] = max(float(np.median(np.abs(values - profile[field]))) * 1.4826, 0.1)
        for field, source in (('latency', 'response_time_ms'), ('wire_response', 'response_size_bytes')):
            values = [math.log1p(float(e[source])) for e in group if e.get(source) is not None
                      and math.isfinite(float(e[source])) and float(e[source]) >= 0]
            if values:
                profile[field] = float(np.median(values))
        profiles[key] = profile
    timestamps = [dt.datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) for e in events if e.get('timestamp')]
    temporal = bool(timestamps) and (max(timestamps) - min(timestamps)).total_seconds() >= 86400
    return ModelVersion('normal-preprocessing-only', dt.datetime.now(dt.timezone.utc).isoformat(),
                        set(groups), {e.get('status_code') for e in events},
                        metadata={'feature_version': FEATURE_VERSION, 'temporal_features': temporal,
                                  'graph_features': False}, profiles=profiles)


def matrix(events, baseline):
    return np.asarray([extract_features(e, baseline.profiles, graph=False,
                       temporal=baseline.metadata['temporal_features']) for e in events])


def event_text(event, baseline):
    """Serialize captured evidence only, never labels, identities, or request IDs."""
    features = matrix([event], baseline)[0]
    # Put payload evidence first so a long response cannot hide a request attack.
    return '\n'.join([
        'method: ' + (event.get('method') or ''),
        'path: ' + (event.get('path') or '')[:180],
        'query: ' + (event.get('query_params') or '')[:240],
        'request: ' + (event.get('request_body') or '')[:360],
        'response: ' + (event.get('response_body') or '')[:360],
        'status: ' + str(event.get('status_code')),
        'response milliseconds: ' + str(event.get('response_time_ms')),
        # CSV preparation represents wire sizes as floats; the HTTP/Kafka
        # schemas represent them as integers. Preserve the trained text format.
        'response bytes: ' + str(float(event['response_size_bytes']) if event.get('response_size_bytes') is not None else None),
        'request size change log: %.3f' % features[0],
        'response size change log: %.3f' % features[1],
        'latency change log: %.3f' % features[29],
        'wire size change log: %.3f' % features[31],
        'request headers present: ' + ', '.join(sorted((event.get('request_headers') or {}).keys())),
    ])


def questions(target=None):
    result = [{'id': 'security', 'type': 'choice',
               'text': 'Classify this API exchange.', 'options': ['normal', 'anomalous']}]
    if target is not None:
        result[0]['target'] = int(target)
    return result


def threshold_at_fpr(normal_scores, target_fpr):
    scores = np.asarray(normal_scores, dtype=float)
    if not len(scores) or not np.isfinite(scores).all():
        raise ValueError('Calibration requires finite normal scores')
    if not 0 < target_fpr <= 0.25:
        raise ValueError('target_fpr must be in (0, 0.25]')
    return float(np.nextafter(np.quantile(scores, 1 - target_fpr, method='higher'), math.inf))


class LocalDetector:
    """One event-in/result-out interface for all three fitted candidates."""

    def __init__(self, kind, model, baseline, threshold):
        self.kind, self.model, self.baseline, self.threshold = kind, model, baseline, threshold
        self.request_adapter = None

    def score(self, events):
        if self.kind == 'isolation_forest':
            return -self.model.score_samples(matrix(events, self.baseline))
        if self.kind == 'catboost':
            return self.model.predict_proba(matrix(events, self.baseline))[:, 1]
        if self.kind == 'jevlet':
            scores = np.empty(len(events))
            adapted = [i for i, e in enumerate(events)
                       if self.request_adapter is not None and self.request_adapter.scope(e)]
            if adapted:
                scores[adapted] = self.request_adapter.scores([events[i] for i in adapted])
            for i in set(range(len(events))) - set(adapted):
                scores[i] = self.model.predict(event_text(events[i], self.baseline), questions())['answers'][0]['probabilities'][1]
            return scores
        raise ValueError('Unknown model kind')

    def predict(self, event):
        score = float(self.score([event])[0])
        adapted = self.request_adapter is not None and self.request_adapter.scope(event)
        threshold = self.request_adapter.threshold(event) if adapted else self.threshold
        return {'model_kind': self.kind, 'behavioral_anomaly': score >= threshold,
                'anomaly_score': score, 'threshold': threshold,
                'score_kind': ('raw_anomaly_score' if self.kind == 'isolation_forest'
                               else 'classifier_probability'),
                'evaluation_status': 'evaluated'}

    def to(self, device):
        """Keep an optional head on the same device as its Jevlet encoder."""
        self.model.to(device)
        if self.request_adapter is not None:
            self.request_adapter.head.to(device)
        return self

    @classmethod
    def load(cls, directory, kind, jevlet_repo=None, device='cpu'):
        """Load only a checkpoint produced by this trusted local experiment."""
        directory = Path(directory)
        with (directory / 'baseline.pkl').open('rb') as stream:
            baseline = pickle.load(stream)
        manifest = json.loads((directory / 'models.json').read_text(encoding='utf-8'))
        if kind == 'isolation_forest':
            if (directory / 'isolation-forest-gpu.pt').exists():
                from gpu_isolation_forest import TorchIsolationForest
                model = TorchIsolationForest.load(directory / 'isolation-forest-gpu.pt', device)
            else:
                model = baseline.ml_model
        elif kind == 'catboost':
            from catboost import CatBoostClassifier
            model = CatBoostClassifier()
            model.load_model(str(directory / 'catboost.cbm'))
        elif kind == 'jevlet':
            if jevlet_repo:
                sys.path.insert(0, str(Path(jevlet_repo) / 'src'))
            from jevlet.model import Jevlet
            model = Jevlet.load(directory / 'jevlet', device)
        else:
            raise ValueError('Unknown model kind')
        detector = cls(kind, model, baseline, manifest[kind]['threshold'])
        if kind == 'jevlet' and (directory / 'request-adapter.json').exists():
            from jevlet_request_adapter import RequestAdapter
            detector.request_adapter = RequestAdapter.load(directory, model)
        return detector
