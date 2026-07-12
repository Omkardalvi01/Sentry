import sqlite3
import statistics
import json
from collections import defaultdict
import uuid
import datetime

class ModelVersion:
    """Immutable trained model state for anomaly prediction."""
    def __init__(self, version_id: str, created_at: str, known_endpoints: set, known_status_codes: set, numerical_baselines: dict):
        self.version_id = version_id
        self.created_at = created_at
        self.known_endpoints = known_endpoints
        self.known_status_codes = known_status_codes
        self.numerical_baselines = numerical_baselines

    def predict(self, event: dict) -> dict:
        reasons = []
        score = 0.0
        
        method = event.get('method')
        path = event.get('path')
        status_code = event.get('status_code')
        req_body = event.get('request_body') or ""
        res_body = event.get('response_body') or ""
        
        endpoint_key = f"{method} {path}"
        
        # 1. Categorical Checks
        if self.known_endpoints and endpoint_key not in self.known_endpoints:
            reasons.append(f"Unseen endpoint: {method} {path} (Shadow API)")
            score += 0.8
        
        if status_code and self.known_status_codes and status_code not in self.known_status_codes:
            reasons.append(f"Unseen status code: {status_code}")
            score += 0.4
            
        # 2. Numerical Checks (Z-score)
        if endpoint_key in self.numerical_baselines:
            baseline = self.numerical_baselines[endpoint_key]
            
            req_len = len(req_body)
            if baseline['req_std'] > 0:
                z_req = abs(req_len - baseline['req_mean']) / baseline['req_std']
                if z_req > 3.0:
                    reasons.append(f"Anomalous request body length (Z-score: {z_req:.2f})")
                    score += min(0.1 * z_req, 0.5)
            elif req_len > baseline['req_mean'] * 2 and req_len > 100:
                reasons.append(f"Request body significantly larger than constant baseline")
                score += 0.3
                
            res_len = len(res_body)
            if baseline['res_std'] > 0:
                z_res = abs(res_len - baseline['res_mean']) / baseline['res_std']
                if z_res > 3.0:
                    reasons.append(f"Anomalous response body length (Z-score: {z_res:.2f})")
                    score += min(0.1 * z_res, 0.5)
            elif res_len > baseline['res_mean'] * 2 and res_len > 100:
                reasons.append(f"Response body significantly larger than constant baseline")
                score += 0.3

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
        
        model_data = {
            "known_endpoints": list(model.known_endpoints),
            "known_status_codes": list(model.known_status_codes),
            "numerical_baselines": model.numerical_baselines
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
        
        # Check if table exists first
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='model_registry'")
        if not cursor.fetchone():
            return None
            
        cursor.execute("SELECT * FROM model_registry ORDER BY created_at DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
            
        data = json.loads(row['model_data'])
        return ModelVersion(
            version_id=row['id'],
            created_at=row['created_at'],
            known_endpoints=set(data['known_endpoints']),
            known_status_codes=set(data['known_status_codes']),
            numerical_baselines=data['numerical_baselines']
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
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.registry = ModelRegistry(db_path)
        self.active_model = self.registry.load_latest_model()
        
        if not self.active_model:
            print("No previous models found. Training initial baseline...")
            self.train_new_model()

    def predict(self, event: dict) -> dict:
        # Grab a local reference for thread-safety (atomic swap)
        current_model = self.active_model 
        if current_model is None:
            return {"error": "No trained model available yet."}
        return current_model.predict(event)

    def train_new_model(self):
        print("Training new anomaly detection model...")
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='api_traffic'")
            if not cursor.fetchone():
                print(f"Warning: api_traffic table not found. Cannot train.")
                return

            cursor.execute("SELECT method, path, status_code, length(request_body) as req_len, length(response_body) as res_len FROM api_traffic")
            rows = cursor.fetchall()
            
            known_endpoints = set()
            known_status_codes = set()
            lens_by_endpoint = defaultdict(lambda: {'req': [], 'res': []})
            
            for row in rows:
                method = row['method']
                path = row['path']
                status_code = row['status_code']
                
                req_len = row['req_len'] or 0
                res_len = row['res_len'] or 0
                
                endpoint_key = f"{method} {path}"
                known_endpoints.add(endpoint_key)
                if status_code is not None:
                    known_status_codes.add(status_code)
                
                lens_by_endpoint[endpoint_key]['req'].append(req_len)
                lens_by_endpoint[endpoint_key]['res'].append(res_len)
                
            numerical_baselines = {}
            for ep, lengths in lens_by_endpoint.items():
                req_mean = statistics.mean(lengths['req']) if lengths['req'] else 0
                req_std = statistics.stdev(lengths['req']) if len(lengths['req']) > 1 else 0
                
                res_mean = statistics.mean(lengths['res']) if lengths['res'] else 0
                res_std = statistics.stdev(lengths['res']) if len(lengths['res']) > 1 else 0
                
                numerical_baselines[ep] = {
                    'req_mean': req_mean,
                    'req_std': req_std,
                    'res_mean': res_mean,
                    'res_std': res_std
                }
                
            new_model = ModelVersion(
                version_id=str(uuid.uuid4())[:8],
                created_at=datetime.datetime.utcnow().isoformat(),
                known_endpoints=known_endpoints,
                known_status_codes=known_status_codes,
                numerical_baselines=numerical_baselines
            )
            
            # Save to registry
            self.registry.save_model(new_model)
            
            # Atomic swap
            self.active_model = new_model
            print(f"✓ New model '{new_model.version_id}' activated seamlessly. Tracking {len(known_endpoints)} endpoints.")
            
        finally:
            conn.close()
