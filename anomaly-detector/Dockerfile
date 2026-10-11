FROM python:3.11.16-slim-bookworm
WORKDIR /app
COPY anomaly-detector/requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir --require-hashes -r /app/requirements.lock
COPY anomaly-detector/requirements-jevlet.txt /app/requirements-jevlet.txt
RUN pip install --no-cache-dir torch==2.8.0 --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir -r /app/requirements-jevlet.txt
COPY anomaly-detector /app/anomaly-detector
COPY internal/storage/migrations /app/internal/storage/migrations
COPY research /app/research
COPY evaluation/local_models.py evaluation/jevlet_failures.py evaluation/jevlet_request_adapter.py evaluation/compare_local_models.py evaluation/replay_fur.py /app/evaluation/
WORKDIR /app/anomaly-detector
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5001"]
