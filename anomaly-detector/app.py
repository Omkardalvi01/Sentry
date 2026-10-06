import datetime as dt
import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator
from detector import DetectorService

DB_PATH = os.environ.get('SENTRY_DB_PATH', '../traffic.db')
detector_service = None

@asynccontextmanager
async def lifespan(app):
    global detector_service
    detector_service = DetectorService(DB_PATH)
    scheduler = BackgroundScheduler()
    def retrain():
        try:
            detector_service.train_new_model()
        except Exception as exc:
            logging.warning('Scheduled retraining retained previous model: %s', exc)
    scheduler.add_job(retrain, 'interval', hours=24, max_instances=1)
    scheduler.start()
    yield
    scheduler.shutdown()

app = FastAPI(title='Sentry inventory and behavioral detector', lifespan=lifespan)

class TrafficEvent(BaseModel):
    request_id: str = Field(min_length=1)
    method: str = Field(pattern=r"^(GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE|TRACE)$")
    path: str = Field(pattern=r'^/')
    timestamp: dt.datetime
    status_code: int = Field(ge=100, le=599)
    request_body: str | None = ''
    response_body: str | None = ''
    query_params: str | None = ''
    request_headers: dict[str, Any] | None = None
    response_headers: dict[str, Any] | None = None
    spec_title: str = ''
    spec_version: str = ''
    graph_path_template: str = ''
    graph_known: bool | None = None
    graph_context_status: str = 'unknown'
    graph_deprecated: bool = False
    graph_security: str = ''
    graph_tag: str = ''

    @field_validator('timestamp')
    @classmethod
    def timezone_required(cls, value):
        if value.tzinfo is None:
            raise ValueError('timestamp must include a timezone')
        return value

class TrainingWindow(BaseModel):
    start: str | None = None
    end: str | None = None

@app.post('/predict')
def predict(event: TrafficEvent):
    return detector_service.predict(event.model_dump(mode="json"))

@app.get('/models')
def models():
    return {'models': detector_service.registry.list_models()}

@app.post('/models/retrain')
def retrain(window: TrainingWindow):
    try:
        return {'status': 'activated', 'model_version': detector_service.train_new_model(window.start, window.end)}
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

@app.post('/models/{version_id}/activate')
def activate(version_id: str):
    try:
        return {'model_version': detector_service.rollback(version_id)}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

@app.get('/health')
def health():
    model = detector_service.active_model
    return {'status': 'healthy' if model else 'rules_only', 'active_model_id': model.version_id if model else None,
            'tracked_endpoints': len(model.known_endpoints) if model else 0,
            'last_training_error': detector_service.last_training_error,
            'prediction_cache': 'disabled; each event is evaluated'}
