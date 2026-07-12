from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, Any, Optional
import os
from contextlib import asynccontextmanager
from apscheduler.schedulers.background import BackgroundScheduler

from detector import DetectorService
from cache import EndpointCache

# Config from environment
DB_PATH = os.environ.get("SENTRY_DB_PATH", "../traffic.db")
REDIS_URL = os.environ.get("SENTRY_REDIS_URL", "redis://localhost:6379")

detector_service = None
scheduler = BackgroundScheduler()

@asynccontextmanager
async def lifespan(app: FastAPI):
    global detector_service

    # Initialize Redis cache (gracefully degrades if Redis is unavailable)
    cache = EndpointCache(redis_url=REDIS_URL)

    print(f"Initializing Detector Service with DB: {DB_PATH}")
    detector_service = DetectorService(DB_PATH, cache=cache)

    # Start APScheduler — retrains model every 24 hours and auto-flushes cache
    print("Starting 24-hour retraining scheduler...")
    scheduler.add_job(detector_service.train_new_model, 'interval', hours=24)
    scheduler.start()

    yield

    print("Shutting down scheduler...")
    scheduler.shutdown()

app = FastAPI(title="Sentry Anomaly Detector API", lifespan=lifespan)

# Pydantic schema
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
    Predicts if a given API traffic event is anomalous.
    Returns cached result for known-normal endpoints (LFU + TTL eviction via Redis).
    """
    return detector_service.predict(event.model_dump())

@app.get("/models")
def list_models():
    """Lists all historically trained models from the registry."""
    return {"models": detector_service.registry.list_models()}

@app.post("/models/retrain")
def force_retrain(background_tasks: BackgroundTasks):
    """
    Forces immediate retraining in the background.
    Cache is automatically flushed after the new model is activated.
    """
    background_tasks.add_task(detector_service.train_new_model)
    return {"status": "Training new model in background. Cache will be flushed on completion."}

@app.get("/health")
def health_check():
    active = detector_service.active_model
    cache = detector_service.cache
    return {
        "status": "ok",
        "active_model_id": active.version_id if active else None,
        "tracked_endpoints": len(active.known_endpoints) if active else 0,
        "cache": {
            "available": cache.is_available if cache else False,
            "ttl_seconds": int(os.environ.get("SENTRY_CACHE_TTL", 300)),
            "eviction_policy": "allkeys-lfu (configured on Redis server)",
        }
    }
