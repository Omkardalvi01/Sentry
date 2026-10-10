#!/usr/bin/env python3
"""Evaluate Sentry's detector on the FUR-API held-out labeled HTTP traces."""

import argparse
import csv
import datetime as dt
import hashlib
import json
import math
import sqlite3
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
EVAL = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "anomaly-detector"))
from detector import DetectorService  # noqa: E402
from database import connect, initialize  # noqa: E402


def read_csv(path):
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def event_from_row(row, request_id):
    parsed = urlsplit(row["request_url"].strip())
    timestamp = dt.datetime.strptime(row["timestamp"].strip(), "%Y/%m/%d %H:%M")
    headers = {}
    for item in row.get("request_headers", "").split(";"):
        name, separator, _ = item.partition(":")
        if separator and name.strip():
            headers[name.strip()] = ""
    if row.get("agent", "").strip():
        headers["User-Agent"] = row["agent"].strip()

    def body_value(value):
        value = (value or "").strip()
        return "" if value.lower() == "nan" else value

    def number_value(value):
        try:
            number = float(value)
            return number if math.isfinite(number) and number >= 0 else None
        except (TypeError, ValueError):
            return None

    return {
        "request_id": request_id,
        "method": row["method"].strip().upper(),
        "path": parsed.path or "/",
        "query_params": parsed.query,
        "request_body": body_value(row["request_body"]),
        "response_body": body_value(row["response_body"]),
        "request_headers": headers,
        "response_time_ms": number_value(row.get("response_time")),
        "response_size_bytes": number_value(row.get("response_size")),
        "status_code": int(row["status"].strip()),
        "timestamp": timestamp.replace(tzinfo=dt.timezone.utc).isoformat(),
        "client_id": row.get("user_identity", "").strip(),
    }


def ratio(numerator, denominator):
    return round(numerator / denominator, 6) if denominator else None


def valid_status(row):
    try:
        return 100 <= int(row["status"].strip()) <= 599
    except (TypeError, ValueError):
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=EVAL / "datasets/FUR-API")
    parser.add_argument("--output", type=Path, default=EVAL / "results/fur-api-enhanced.json")
    args = parser.parse_args()
    train_path = args.source / "dataset/train.csv"
    test_path = args.source / "dataset/test.csv"
    train_rows, test_rows = read_csv(train_path), read_csv(test_path)
    train_labels = Counter(row["type"].strip() for row in train_rows)
    test_labels = Counter(row["type"].strip() for row in test_rows)
    if set(train_labels | test_labels) != {"normal", "anomaly"}:
        parser.error("unexpected FUR-API labels")
    excluded_train = sum(not valid_status(row) for row in train_rows)
    excluded_test = sum(not valid_status(row) for row in test_rows)
    normal_train = [row for row in train_rows if row["type"].strip() == "normal" and valid_status(row)]
    test_rows = [row for row in test_rows if valid_status(row)]
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    db_path = EVAL / "results" / ("fur-api-" + run_id + ".db")
    db_path.parent.mkdir(exist_ok=True)
    initialize(str(db_path))
    with connect(str(db_path)) as conn:
        conn.executemany("""INSERT INTO api_traffic
            (request_id, method, path, query_params, request_headers, request_body,
             status_code, response_headers, response_body, response_time_ms, response_size_bytes,
             timestamp, graph_known,
             graph_context_status, training_eligible)
            VALUES (?, ?, ?, ?, ?, ?, ?, '{}', ?, ?, ?, ?, NULL, 'unknown', 1)""", [
            (event["request_id"], event["method"], event["path"], event["query_params"],
             json.dumps(event["request_headers"]), event["request_body"], event["status_code"], event["response_body"],
             event["response_time_ms"], event["response_size_bytes"], event["timestamp"])
            for event in (event_from_row(row, "fur-train-%d" % i) for i, row in enumerate(normal_train))
        ])
    started = time.perf_counter()
    detector = DetectorService(str(db_path), cache=None)
    detector.train_new_model(
        start="1900-01-01T00:00:00+00:00",
        end="2100-01-01T00:00:00+00:00",
    )
    train_seconds = time.perf_counter() - started
    confusion = Counter()
    reason_counts = Counter()
    unseen_test = Counter()
    known_endpoints = {
        (row["method"].strip().upper(), urlsplit(row["request_url"].strip()).path or "/")
        for row in normal_train
    }
    predicted_count = 0
    started = time.perf_counter()
    for i, row in enumerate(test_rows):
        event = event_from_row(row, "fur-test-%d" % i)
        result = detector.predict(event)
        truth = row["type"].strip() == "anomaly"
        predicted = bool(result["is_anomaly"])
        confusion[(truth, predicted)] += 1
        if (event["method"], event["path"]) not in known_endpoints:
            unseen_test["anomaly" if truth else "normal"] += 1
        for reason in result.get("reasons", []):
            kind = reason.split(":", 1)[0].split(" (", 1)[0]
            reason_counts[("tp" if truth else "fp") if predicted else ("fn" if truth else "tn"), kind] += 1
        predicted_count += 1
    predict_seconds = time.perf_counter() - started
    tp, fp, tn, fn = (confusion[(True, True)], confusion[(False, True)],
                      confusion[(False, False)], confusion[(True, False)])
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    output = {
        "dataset": "FUR-API",
        "source_revision": subprocess.check_output(
            ["git", "-C", str(args.source), "rev-parse", "HEAD"], text=True
        ).strip(),
        "sentry_revision": subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True
        ).strip(),
        "sentry_worktree_dirty": bool(subprocess.check_output(
            ["git", "-C", str(ROOT), "status", "--porcelain"], text=True
        ).strip()),
        "detector_sha256": hashlib.sha256((ROOT / "anomaly-detector/detector.py").read_bytes()).hexdigest(),
        "train_sha256": hashlib.sha256(train_path.read_bytes()).hexdigest(),
        "test_sha256": hashlib.sha256(test_path.read_bytes()).hexdigest(),
        "protocol": "Train the current DetectorService on valid normal training rows marked training_eligible; exclude labeled training anomalies. Sort by timestamp, train on the first 80%, and calibrate the threshold on the final 20% at a 5% target false-positive rate. Score held-out valid rows without cache or test-label tuning.",
        "train_label_counts": dict(train_labels),
        "test_label_counts": dict(test_labels),
        "excluded_train_invalid_status": excluded_train,
        "excluded_test_invalid_status": excluded_test,
        "training_rows_used": len(normal_train),
        "test_rows_used": len(test_rows),
        "unseen_test_endpoints": dict(unseen_test),
        "reason_counts_by_outcome": {
            outcome: {reason: count for (group, reason), count in reason_counts.items() if group == outcome}
            for outcome in ("tp", "fp", "tn", "fn")
        },
        "model_version": detector.active_model.version_id,
        "feature_version": detector.active_model.metadata["feature_version"],
        "target_validation_fpr": detector.active_model.metadata["target_validation_fpr"],
        "observed_validation_fpr": detector.active_model.metadata["validation_fpr"],
        "true_positive": tp, "false_positive": fp, "true_negative": tn, "false_negative": fn,
        "precision": precision, "recall": recall,
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "specificity": ratio(tn, tn + fp),
        "balanced_accuracy": round((recall + ratio(tn, tn + fp)) / 2, 6),
        "training_seconds": round(train_seconds, 3),
        "prediction_seconds": round(predict_seconds, 3),
        "test_events_per_second": round(len(test_rows) / predict_seconds, 2),
        "prediction_records": predicted_count,
        "db_path": str(db_path.relative_to(EVAL)),
        "limitations": [
            "No API spec or service graph topology is supplied by FUR-API; graph-context feature slots are unknown.",
            "Request header names are used as presence indicators; raw header values are not modeled.",
            "The detector uses its training-only validation split to calibrate a 5% target false-positive rate; no test labels are used for tuning.",
        ],
    }
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
