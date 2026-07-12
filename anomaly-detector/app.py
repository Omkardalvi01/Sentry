from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, Any, Optional
import os
from contextlib import asynccontextmanager
from apscheduler.schedulers.background import BackgroundScheduler

from detector import DetectorService

# Setup detector service
DB_PATH = os.environ.get("SENTRY_DB_PATH", "../traffic.db")
detector_service = None
scheduler = BackgroundScheduler()

@asynccontextmanager
async def lifespan(app: FastAPI):
    global detector_service
    print(f"Initializing Detector Service with DB: {DB_PATH}")
    detector_service = DetectorService(DB_PATH)
    
    # Start APScheduler
    print("Starting 24-hour retraining scheduler...")
    # Trigger once a day
    scheduler.add_job(detector_service.train_new_model, 'interval', hours=24)
    scheduler.start()
    
    yield
    
    print("Shutting down scheduler...")
    scheduler.shutdown()

app = FastAPI(title="Sentry Anomaly Detector API", lifespan=lifespan)

# Pydantic schema for validation
class TrafficEvent(BaseModel):
    request_id: str
    method: str
    path: str
    query_params: Optional[str] = ""
    request_headers: Optional[Dict[str, Any]] = {}
    request_body: Optional[str] = ""
    status_code: int
    response_headers: Optional[Dict[str, Any]] = {}
    response_body: Optional[str] = ""
    timestamp: str

@app.post("/predict")
def predict_anomaly(event: TrafficEvent):
    """
    Predicts if a given API traffic event is anomalous using the active model.
    """
    report = detector_service.predict(event.model_dump())
    return report

@app.get("/models")
def list_models():
    """
    Lists all historically trained models from the registry.
    """
    return {"models": detector_service.registry.list_models()}

@app.post("/models/retrain")
def force_retrain(background_tasks: BackgroundTasks):
    """
    Forces an immediate retraining of a new model in the background.
    """
    background_tasks.add_task(detector_service.train_new_model)
    return {"status": "Training new model in background..."}

@app.get("/health")
def health_check():
    active = detector_service.active_model
    return {
        "status": "ok", 
        "active_model_id": active.version_id if active else None,
        "tracked_endpoints": len(active.known_endpoints) if active else 0
    }
