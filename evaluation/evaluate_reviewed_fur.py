#!/usr/bin/env python3
"""Evaluate anomaly scoring with confirmed training anomalies from FUR-API.

This is a separate, label-aware experiment. It trains only on labeled examples
from FUR-API's train.csv, calibrates on the chronological normal validation
slice, and scores test.csv once at the end.
"""

import argparse
import datetime as dt
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
EVAL = Path(__file__).resolve().parent
sys.path.insert(0, str(EVAL))
from replay_fur import event_from_row, read_csv, valid_status  # noqa: E402
sys.path.insert(0, str(ROOT / "anomaly-detector"))
from detector import extract_features, fit_model, fit_reviewed_model  # noqa: E402


def ratio(numerator, denominator):
    return round(numerator / denominator, 6) if denominator else None


def counts(labels, predictions):
    tp = int(np.sum(labels & predictions))
    fp = int(np.sum(~labels & predictions))
    tn = int(np.sum(~labels & ~predictions))
    fn = int(np.sum(labels & ~predictions))
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    specificity = ratio(tn, tn + fp)
    return {
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "precision": precision,
        "recall": recall,
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "specificity": specificity,
        "balanced_accuracy": round((recall + specificity) / 2, 6),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=EVAL / "datasets/FUR-API")
    parser.add_argument("--output", type=Path, default=EVAL / "results/fur-api-reviewed-examples.json")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--target-fpr", type=float, default=0.05)
    args = parser.parse_args()
    if not 0 < args.target_fpr <= 0.25:
        parser.error("--target-fpr must be greater than 0 and at most 0.25")

    train_path = args.source / "dataset/train.csv"
    test_path = args.source / "dataset/test.csv"
    all_train = [row for row in read_csv(train_path) if valid_status(row)]
    all_train.sort(key=lambda row: dt.datetime.strptime(row["timestamp"].strip(), "%Y/%m/%d %H:%M"))
    test_rows = [row for row in read_csv(test_path) if valid_status(row)]

    normal_rows = [row for row in all_train if row["type"].strip() == "normal"]
    boundary = dt.datetime.strptime(
        normal_rows[int(len(normal_rows) * 0.8)]["timestamp"].strip(), "%Y/%m/%d %H:%M"
    )
    training_rows = [row for row in all_train
                     if dt.datetime.strptime(row["timestamp"].strip(), "%Y/%m/%d %H:%M") < boundary]
    validation_rows = [row for row in all_train
                       if dt.datetime.strptime(row["timestamp"].strip(), "%Y/%m/%d %H:%M") >= boundary]
    training_normal = [row for row in training_rows if row["type"].strip() == "normal"]
    validation_normal = [row for row in validation_rows if row["type"].strip() == "normal"]
    training_anomaly_count = sum(row["type"].strip() == "anomaly" for row in training_rows)
    if training_anomaly_count < 20:
        parser.error("the chronological training slice needs at least 20 labeled anomalies")

    # Fit endpoint baselines on normal training traffic only. Train a baseline
    # Isolation Forest and the label-aware classifier on the same feature set.
    baseline = fit_model(
        [event_from_row(row, "baseline-train-%d" % i) for i, row in enumerate(training_normal)],
        [event_from_row(row, "baseline-val-%d" % i) for i, row in enumerate(validation_normal)],
        graph=False,
        seed=args.seed,
        target_fpr=args.target_fpr,
    )
    temporal = baseline.metadata["temporal_features"]

    def feature_matrix(rows, prefix):
        return np.asarray([
            extract_features(event_from_row(row, "%s-%d" % (prefix, i)), baseline.profiles,
                             graph=False, temporal=temporal)
            for i, row in enumerate(rows)
        ])

    validation_x = feature_matrix(validation_rows, "reviewed-validation")
    test_x = feature_matrix(test_rows, "reviewed-test")
    validation_y = np.asarray([row["type"].strip() == "anomaly" for row in validation_rows])
    test_y = np.asarray([row["type"].strip() == "anomaly" for row in test_rows])

    reviewed_model = fit_reviewed_model(
        [event_from_row(row, "reviewed-normal-%d" % i) for i, row in enumerate(training_rows)
         if row["type"].strip() == "normal"],
        [event_from_row(row, "reviewed-anomaly-%d" % i) for i, row in enumerate(training_rows)
         if row["type"].strip() == "anomaly"],
        [event_from_row(row, "reviewed-validation-%d" % i) for i, row in enumerate(validation_rows)
         if row["type"].strip() == "normal"],
        graph=False,
        seed=args.seed,
        target_fpr=args.target_fpr,
    )
    validation_scores = reviewed_model.ml_model.predict_proba(validation_x)[:, 1]
    test_scores = reviewed_model.ml_model.predict_proba(test_x)[:, 1]
    threshold = reviewed_model.metadata["threshold"]
    validation_predictions = validation_scores >= threshold
    test_predictions = test_scores >= threshold

    # The unsupervised reference uses identical rows, features, endpoint
    # profiles, validation normals, and target FPR.
    forest_scores_validation = -baseline.ml_model.score_samples(validation_x)
    forest_scores_test = -baseline.ml_model.score_samples(test_x)
    forest_threshold = float(np.quantile(
        forest_scores_validation[~validation_y], 1 - args.target_fpr, method="higher"
    )) + 1e-12
    forest_validation_predictions = forest_scores_validation >= forest_threshold
    forest_test_predictions = forest_scores_test >= forest_threshold

    result = {
        "dataset": "FUR-API",
        "evaluation": "reviewed anomaly examples versus Isolation Forest, chronological train/validation/test",
        "protocol": (
            "Use the first 80% of valid normal train timestamps for training and the remaining 20% for validation. "
            "Include labeled anomalies before the timestamp boundary in classifier training; use only validation "
            "normal scores to calibrate a target FPR. Test labels are used only for final metrics."
        ),
        "classifier": "ExtraTreesClassifier",
        "classifier_parameters": reviewed_model.metadata["parameters"],
        "seed": args.seed,
        "target_validation_fpr": args.target_fpr,
        "training_rows": len(training_rows),
        "training_normal_rows": len(training_normal),
        "training_labeled_anomaly_rows": training_anomaly_count,
        "validation_rows": len(validation_rows),
        "validation_normal_rows": len(validation_normal),
        "validation_labeled_anomaly_rows": int(np.sum(validation_y)),
        "test_rows": len(test_rows),
        "test_normal_rows": int(np.sum(~test_y)),
        "test_anomaly_rows": int(np.sum(test_y)),
        "feature_version": baseline.metadata["feature_version"],
        "graph_features_enabled": False,
        "validation": {
            "classifier_average_precision": round(float(average_precision_score(validation_y, validation_scores)), 6),
            "classifier_metrics_at_calibrated_threshold": counts(validation_y, validation_predictions),
            "classifier_observed_fpr": ratio(int(np.sum(validation_predictions & ~validation_y)), int(np.sum(~validation_y))),
            "isolation_forest_average_precision": round(float(average_precision_score(validation_y, forest_scores_validation)), 6),
            "isolation_forest_metrics_at_calibrated_threshold": counts(validation_y, forest_validation_predictions),
            "isolation_forest_observed_fpr": ratio(int(np.sum(forest_validation_predictions & ~validation_y)), int(np.sum(~validation_y))),
        },
        "test": {
            "classifier_threshold": threshold,
            "classifier_average_precision": round(float(average_precision_score(test_y, test_scores)), 6),
            "classifier_roc_auc": round(float(roc_auc_score(test_y, test_scores)), 6),
            "classifier_metrics": counts(test_y, test_predictions),
            "isolation_forest_threshold": forest_threshold,
            "isolation_forest_average_precision": round(float(average_precision_score(test_y, forest_scores_test)), 6),
            "isolation_forest_roc_auc": round(float(roc_auc_score(test_y, forest_scores_test)), 6),
            "isolation_forest_metrics": counts(test_y, forest_test_predictions),
        },
        "source_revision": subprocess.check_output(["git", "-C", str(args.source), "rev-parse", "HEAD"], text=True).strip(),
        "sentry_revision": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
        "detector_sha256": hashlib.sha256((ROOT / "anomaly-detector/detector.py").read_bytes()).hexdigest(),
        "train_sha256": hashlib.sha256(train_path.read_bytes()).hexdigest(),
        "test_sha256": hashlib.sha256(test_path.read_bytes()).hexdigest(),
        "limitations": [
            "This experiment requires analyst-confirmed anomaly labels; the service selects the reviewed-label classifier only after at least 20 are present in the training window.",
            "Only 52 labeled anomalies fall before the chronological training boundary and 8 fall in validation, so the measured gain needs confirmation on another labeled dataset.",
            "FUR-API has no API specification or service graph; graph context is not evaluated here.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
