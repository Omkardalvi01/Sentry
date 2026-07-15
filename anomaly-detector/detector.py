import sqlite3
import json
import uuid
import datetime
import base64
import pickle
import numpy as np
from sklearn.ensemble import IsolationForest

def extract_features(event: dict) -> list:
    """Extracts numerical and graph topology features for the Isolation Forest model."""
    req_len = len(event.get('request_body') or "")
    res_len = len(event.get('response_body') or "")
    
    # Topology features
    is_deprecated = 1.0 if event.get('graph_deprecated') else 0.0
    has_auth = 1.0 if event.get('graph_security') else 0.0
    dep_count = float(event.get('graph_dependency_count') or 0)
    
    # status code
    status = float(event.get('status_code') or 200)

    return [req_len, res_len, is_deprecated, has_auth, dep_count, status]

class ModelVersion:
    """Immutable trained model state for anomaly prediction."""
    def __init__(self, version_id: str, created_at: str, known_endpoints: set, known_status_codes: set, ml_model_bytes: bytes = None, ml_model=None):
        self.version_id = version_id
        self.created_at = created_at
        self.known_endpoints = known_endpoints
        self.known_status_codes = known_status_codes
        
        self.ml_model_bytes = ml_model_bytes
        self.ml_model = ml_model
        if self.ml_model is None and ml_model_bytes:
            self.ml_model = pickle.loads(ml_model_bytes)

    def predict(self, event: dict) -> dict:
        reasons = []
        score = 0.0
        
        method = event.get('method')
        path = event.get('path')
        status_code = event.get('status_code')
        
        endpoint_key = f"{method} {path}"
        
        # 1. Categorical Checks (Shadow APIs)
        if self.known_endpoints and endpoint_key not in self.known_endpoints:
            reasons.append(f"Unseen endpoint: {method} {path} (Shadow API)")
            score += 0.8
        
        if status_code and self.known_status_codes and status_code not in self.known_status_codes:
            reasons.append(f"Unseen status code: {status_code}")
            score += 0.4
            
        # 2. Topology-Aware Machine Learning (Isolation Forest)
        if self.ml_model is not None:
            features = extract_features(event)
            # IsolationForest predict returns -1 for anomaly, 1 for normal
            # score_samples returns negative anomaly score (lower is more anomalous)
            try:
                X = np.array([features])
                pred = self.ml_model.predict(X)[0]
                anomaly_score = -self.ml_model.score_samples(X)[0] # Invert so positive = anomalous
                
                if pred == -1:
                    reasons.append(f"ML Topology/Data Anomaly (Score: {anomaly_score:.2f})")
                    score += 0.6
            except Exception as e:
                print(f"ML prediction error: {e}")

        score = min(score, 1.0)
        return {
            "is_anomaly": score >= 0.5,
            "anomaly_score": round(score, 2),
            "reasons": reasons,
            "model_version": self.version_id
        }

class ModelRegistry:
    """Handles persistent storage of models in SQLite."""
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS model_registry (
            id TEXT PRIMARY KEY,
            created_at DATETIME,
            endpoints_count INTEGER,
            model_data TEXT
        )
        """)
        conn.commit()
        conn.close()

    def save_model(self, model: ModelVersion):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        model_b64 = base64.b64encode(model.ml_model_bytes).decode('utf-8') if model.ml_model_bytes else ""
        
        model_data = {
            "known_endpoints": list(model.known_endpoints),
            "known_status_codes": list(model.known_status_codes),
            "ml_model_b64": model_b64
        }
        
        cursor.execute(
            "INSERT INTO model_registry (id, created_at, endpoints_count, model_data) VALUES (?, ?, ?, ?)",
            (model.version_id, model.created_at, len(model.known_endpoints), json.dumps(model_data))
        )
        conn.commit()
        conn.close()

    def load_latest_model(self) -> ModelVersion:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='model_registry'")
        if not cursor.fetchone():
            return None
            
        cursor.execute("SELECT * FROM model_registry ORDER BY created_at DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
            
        data = json.loads(row['model_data'])
        ml_model_bytes = base64.b64decode(data.get('ml_model_b64', '')) if data.get('ml_model_b64') else None
        
        return ModelVersion(
            version_id=row['id'],
            created_at=row['created_at'],
            known_endpoints=set(data.get('known_endpoints', [])),
            known_status_codes=set(data.get('known_status_codes', [])),
            ml_model_bytes=ml_model_bytes
        )
        
    def list_models(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT id, created_at, endpoints_count FROM model_registry ORDER BY created_at DESC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

class DetectorService:
    """Orchestrator for training and predicting with atomic model swaps."""
    def __init__(self, db_path: str, cache=None):
        self.db_path = db_path
        self.registry = ModelRegistry(db_path)
        self.cache = cache
        self.active_model = self.registry.load_latest_model()
        
        if not self.active_model:
            print("No previous models found. Training initial baseline...")
            self.train_new_model()

    def predict(self, event: dict) -> dict:
        method = event.get('method')
        path = event.get('path')

        if self.cache is not None:
            cached = self.cache.get(method, path)
            if cached is not None:
                return cached

        current_model = self.active_model
        if current_model is None:
            return {"error": "No trained model available yet."}

        result = current_model.predict(event)

        if self.cache is not None:
            self.cache.set(method, path, result)

        return result

    def train_new_model(self):
        print("Training new topology-aware anomaly detection model...")
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='api_traffic'")
            if not cursor.fetchone():
                print(f"Warning: api_traffic table not found. Cannot train.")
                return

            cursor.execute("SELECT * FROM api_traffic")
            rows = cursor.fetchall()
            
            known_endpoints = set()
            known_status_codes = set()
            features_list = []
            
            for row in rows:
                row_dict = dict(row)
                method = row_dict.get('method')
                path = row_dict.get('path')
                status_code = row_dict.get('status_code')
                
                endpoint_key = f"{method} {path}"
                known_endpoints.add(endpoint_key)
                if status_code is not None:
                    known_status_codes.add(status_code)
                
                features = extract_features(row_dict)
                features_list.append(features)
                
            ml_model = None
            ml_model_bytes = None
            if len(features_list) > 10:
                X = np.array(features_list)
                # contamination is the expected proportion of outliers
                iso_forest = IsolationForest(contamination=0.01, random_state=42)
                iso_forest.fit(X)
                ml_model = iso_forest
                ml_model_bytes = pickle.dumps(iso_forest)
            else:
                print("Not enough data to train IsolationForest (requires > 10 events). Model will use categorical rules only.")
                
            new_model = ModelVersion(
                version_id=str(uuid.uuid4())[:8],
                created_at=datetime.datetime.utcnow().isoformat(),
                known_endpoints=known_endpoints,
                known_status_codes=known_status_codes,
                ml_model_bytes=ml_model_bytes,
                ml_model=ml_model
            )
            
            self.registry.save_model(new_model)
            self.active_model = new_model
            print(f"✓ New model '{new_model.version_id}' activated seamlessly. Tracking {len(known_endpoints)} endpoints.")

            if self.cache is not None:
                self.cache.flush_model_cache()
            
        finally:
            conn.close()
