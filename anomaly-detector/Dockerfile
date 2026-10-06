FROM python:3.11.16-slim-bookworm
WORKDIR /app
COPY anomaly-detector/requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir --require-hashes -r /app/requirements.lock
COPY anomaly-detector /app/anomaly-detector
COPY internal/storage/migrations /app/internal/storage/migrations
COPY research /app/research
WORKDIR /app/anomaly-detector
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5001"]
