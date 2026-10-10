#!/usr/bin/env python3
"""Evaluate the Isolation Forest component alone on FUR-API train/test data."""

import argparse
from collections import Counter
import datetime as dt
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
EVAL = Path(__file__).resolve().parent
sys.path.insert(0, str(EVAL))
from replay_fur import event_from_row, read_csv, valid_status  # noqa: E402
sys.path.insert(0, str(ROOT / "anomaly-detector"))
from detector import extract_features, fit_model  # noqa: E402


def ratio(n, d):
    return round(n / d, 6) if d else 0.0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=EVAL / "datasets/FUR-API")
    parser.add_argument("--output", type=Path, default=EVAL / "results/isolation-forest-fur-api.json")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--target-fpr", type=float, default=0.05)
    args = parser.parse_args()

    train_path = args.source / "dataset/train.csv"
    test_path = args.source / "dataset/test.csv"
    original_train, original_test = read_csv(train_path), read_csv(test_path)
    train_rows = [r for r in original_train if r["type"].strip() == "normal" and valid_status(r)]
    train_rows.sort(key=lambda r: dt.datetime.strptime(r["timestamp"].strip(), "%Y/%m/%d %H:%M"))
    test_rows = [r for r in original_test if valid_status(r)]
    train_events = [event_from_row(r, "fur-if-train-%d" % i) for i, r in enumerate(train_rows)]
    test_events = [event_from_row(r, "fur-if-test-%d" % i) for i, r in enumerate(test_rows)]

    # FUR-API has no graph/spec metadata. Keep the final 20% of normal training
    # rows as validation so the threshold is calibrated without test labels.
    cut = int(len(train_events) * 0.8)
    while cut > 0 and train_events[cut - 1]["timestamp"] == train_events[cut]["timestamp"]:
        cut -= 1
    training, validation = train_events[:cut], train_events[cut:]
    started = time.perf_counter()
    model = fit_model(training, validation, graph=False, seed=args.seed, target_fpr=args.target_fpr)
    training_seconds = time.perf_counter() - started

    truths, predictions, scores = [], [], []
    started = time.perf_counter()
    for event, row in zip(test_events, test_rows):
        result = model.predict(event, graph=False, ml=True, numerical=False)
        truths.append(row["type"].strip() == "anomaly")
        predictions.append(bool(result["ml_anomaly"]))
        scores.append(float(result["anomaly_score"]))
    prediction_seconds = time.perf_counter() - started
    tp = sum(y and p for y, p in zip(truths, predictions))
    fp = sum(not y and p for y, p in zip(truths, predictions))
    tn = sum(not y and not p for y, p in zip(truths, predictions))
    fn = sum(y and not p for y, p in zip(truths, predictions))
    precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    specificity = ratio(tn, tn + fp)

    # Compare the feature toggles on the exact same held-out rows and training
    # split. FUR-API has no spec, so graph=True adds the graph feature slots but
    # those slots remain unknown/constant for every event.
    graph_model = fit_model(training, validation, graph=True, seed=args.seed, target_fpr=args.target_fpr)
    configurations = {
        "isolation_forest_only": (model, False, True, False),
        "isolation_forest_graph_features": (graph_model, True, True, False),
        "endpoint_size_rule_only": (model, False, False, True),
        "isolation_forest_plus_endpoint_size": (model, False, True, True),
        "graph_features_plus_isolation_forest_and_size": (graph_model, True, True, True),
    }
    comparison = {}
    for name, (candidate_model, graph_enabled, ml_enabled, numerical_enabled) in configurations.items():
        y_true, y_pred, y_score = [], [], []
        for event, row in zip(test_events, test_rows):
            result = candidate_model.predict(event, graph=graph_enabled, ml=ml_enabled,
                                             numerical=numerical_enabled)
            y_true.append(row["type"].strip() == "anomaly")
            y_pred.append(bool(result["behavioral_anomaly"]))
            y_score.append(float(result["behavioral_score"]))
        ctp = sum(y and p for y, p in zip(y_true, y_pred))
        cfp = sum(not y and p for y, p in zip(y_true, y_pred))
        ctn = sum(not y and not p for y, p in zip(y_true, y_pred))
        cfn = sum(y and not p for y, p in zip(y_true, y_pred))
        cprecision, crecall = ratio(ctp, ctp + cfp), ratio(ctp, ctp + cfn)
        comparison[name] = {
            "graph_features_enabled": graph_enabled,
            "isolation_forest_enabled": ml_enabled,
            "endpoint_size_rule_enabled": numerical_enabled,
            "true_positive": ctp, "false_positive": cfp,
            "true_negative": ctn, "false_negative": cfn,
            "precision": cprecision, "recall": crecall,
            "f1": ratio(2 * ctp, 2 * ctp + cfp + cfn),
            "specificity": ratio(ctn, ctn + cfp),
            "balanced_accuracy": round((crecall + ratio(ctn, ctn + cfp)) / 2, 6),
            "average_precision": round(float(average_precision_score(y_true, y_score)), 6),
            "roc_auc": round(float(roc_auc_score(y_true, y_score)), 6),
        }
    threshold_sweep = {}
    test_truth = np.asarray([row["type"].strip() == "anomaly" for row in test_rows])
    for graph_enabled, candidate_model in ((False, model), (True, graph_model)):
        validation_scores = -candidate_model.ml_model.score_samples(np.asarray([
            extract_features(event, candidate_model.profiles, graph=graph_enabled,
                             temporal=candidate_model.metadata["temporal_features"])
            for event in validation
        ]))
        test_scores = -candidate_model.ml_model.score_samples(np.asarray([
            extract_features(event, candidate_model.profiles, graph=graph_enabled,
                             temporal=candidate_model.metadata["temporal_features"])
            for event in test_events
        ]))
        settings = {}
        for target_fpr in (0.01, 0.025, 0.05, 0.10):
            threshold = float(np.quantile(validation_scores, 1 - target_fpr, method="higher")) + 1e-12
            y_pred = test_scores >= threshold
            stp = int(np.sum(test_truth & y_pred))
            sfp = int(np.sum(~test_truth & y_pred))
            stn = int(np.sum(~test_truth & ~y_pred))
            sfn = int(np.sum(test_truth & ~y_pred))
            sp, sr = ratio(stp, stp + sfp), ratio(stp, stp + sfn)
            settings[str(target_fpr)] = {
                "threshold": threshold,
                "validation_fpr": round(float(np.mean(validation_scores >= threshold)), 6),
                "true_positive": stp, "false_positive": sfp,
                "true_negative": stn, "false_negative": sfn,
                "precision": sp, "recall": sr,
                "f1": ratio(2 * stp, 2 * stp + sfp + sfn),
                "specificity": ratio(stn, stn + sfp),
            }
        threshold_sweep["graph_features_%s" % ("on" if graph_enabled else "off")] = settings
    output = {
        "evaluation": "Isolation Forest only, FUR-API held-out test set",
        "dataset": "FUR-API",
        "source_revision": subprocess.check_output(["git", "-C", str(args.source), "rev-parse", "HEAD"], text=True).strip(),
        "sentry_revision": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
        "sentry_worktree_dirty": bool(subprocess.check_output(
            ["git", "-C", str(ROOT), "status", "--porcelain"], text=True).strip()),
        "detector_sha256": hashlib.sha256((ROOT / "anomaly-detector/detector.py").read_bytes()).hexdigest(),
        "train_sha256": hashlib.sha256(train_path.read_bytes()).hexdigest(),
        "test_sha256": hashlib.sha256(test_path.read_bytes()).hexdigest(),
        "protocol": "Train IsolationForest on the first 80% of valid normal train rows; calibrate the score threshold on the chronological remaining 20%. Score held-out test rows with graph features and numerical endpoint-size rules disabled. Test labels are used only for final metrics.",
        "seed": args.seed,
        "target_validation_fpr": args.target_fpr,
        "training_rows": len(training),
        "validation_rows": len(validation),
        "test_rows": len(test_rows),
        "train_label_counts": dict(Counter(r["type"].strip() for r in original_train)),
        "test_label_counts": dict(Counter(r["type"].strip() for r in original_test)),
        "test_normal_rows": sum(not y for y in truths),
        "test_anomaly_rows": sum(truths),
        "excluded_labeled_train_anomalies": sum(r["type"].strip() == "anomaly" for r in original_train),
        "excluded_invalid_train_status": sum(not valid_status(r) for r in original_train),
        "excluded_invalid_test_status": sum(not valid_status(r) for r in original_test),
        "threshold": model.metadata["threshold"],
        "validation_fpr": model.metadata["validation_fpr"],
        "feature_comparison": comparison,
        "threshold_sweep": threshold_sweep,
        "graph_feature_note": "FUR-API contains no specification or service graph metadata. In graph-enabled runs, graph feature slots are present but unknown for every event; compare graph-enabled quality only on the controlled API testbeds.",
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "precision": precision,
        "recall": recall,
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "specificity": specificity,
        "balanced_accuracy": round((recall + specificity) / 2, 6),
        "average_precision": round(float(average_precision_score(truths, scores)), 6),
        "roc_auc": round(float(roc_auc_score(truths, scores)), 6),
        "training_seconds": round(training_seconds, 3),
        "prediction_seconds": round(prediction_seconds, 3),
        "test_events_per_second": round(len(test_rows) / prediction_seconds, 2),
        "limitations": [
            "FUR-API supplies request-level labels but no API specification or graph topology.",
            "Features include HTTP method, route and query shape, decoded attack-pattern markers, request and response sizes, status, optional response latency, and header-name presence; header values are not used.",
            "This is a component-only score; it excludes the detector's numerical endpoint-relative rule and inventory findings.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
