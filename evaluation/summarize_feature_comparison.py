#!/usr/bin/env python3
"""Combine FUR-API component toggles with the controlled graph testbed ablation."""

import argparse
import csv
import hashlib
import json
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVAL = Path(__file__).resolve().parent


def summarize(rows, method):
    selected = [row for row in rows if row["method"] == method]
    keys = ("precision", "recall", "f1", "pr_auc", "p50_ms", "p95_ms", "events_per_second")
    return {
        "runs": len(selected),
        **{key: round(statistics.mean(float(row[key]) for row in selected), 6)
           for key in keys},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controlled-raw", type=Path,
                        default=EVAL / "results/graph-inventory-raw")
    parser.add_argument("--fur-report", type=Path,
                        default=EVAL / "results/isolation-forest-fur-api.json")
    parser.add_argument("--merged-report", type=Path,
                        default=EVAL / "results/fur-api-enhanced.json")
    parser.add_argument("--output", type=Path,
                        default=EVAL / "results/detector-feature-comparison.json")
    args = parser.parse_args()

    with (args.controlled_raw / "behavior.csv").open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    behavior_path = args.controlled_raw / "behavior.csv"
    manifest = json.loads((args.controlled_raw / "manifest.json").read_text())
    fur = json.loads(args.fur_report.read_text())
    merged = json.loads(args.merged_report.read_text())
    in_domain = {
        name: summarize(rows, name) for name in (
            "traffic_behavior", "inventory_behavior", "traffic_if_only",
            "inventory_if_only", "without_ml")
    }
    held_out = {
        name: summarize(rows, name) for name in (
            "held_out_traffic_behavior", "held_out_inventory_behavior")
    }
    report = {
        "evaluation": "Isolation Forest, endpoint-size rule, and graph-feature ablation",
        "sentry_revision": fur["sentry_revision"],
        "sentry_worktree_dirty": fur["sentry_worktree_dirty"],
        "detector_sha256": fur["detector_sha256"],
        "fur_api": {
            "source_revision": fur["source_revision"],
            "protocol": fur["protocol"],
            "rows": {key: fur[key] for key in (
                "training_rows", "validation_rows", "test_rows", "test_normal_rows",
                "test_anomaly_rows")},
            "feature_comparison": fur["feature_comparison"],
            "graph_feature_note": fur["graph_feature_note"],
        },
        "current_detector_replay": {
            "protocol": merged["protocol"],
            "feature_version": merged["feature_version"],
            "detector_sha256": merged["detector_sha256"],
            "target_validation_fpr": merged["target_validation_fpr"],
            "confusion_matrix": {key: merged[key] for key in (
                "true_positive", "false_positive", "true_negative", "false_negative")},
            "metrics": {key: merged[key] for key in (
                "precision", "recall", "f1", "specificity", "balanced_accuracy",
                "test_events_per_second")},
        },
        "controlled_api_testbeds": {
            "protocol": "Five seeds across three local APIs; 160 normal training events, 40 validation events, and 120 test events per app/seed. Inventory-aware models include graph-known, deprecated, and auth metadata. Held-out results train on two APIs and test on the third.",
            "seeds": manifest["seeds"],
            "apps": manifest["apps"],
            "events_per_app_seed": manifest["events_per_app_seed"],
            "split": manifest["split"],
            "binary_sha256": manifest["binary_sha256"],
            "behavior_csv_sha256": hashlib.sha256(behavior_path.read_bytes()).hexdigest(),
            "in_domain": in_domain,
            "held_out_application": held_out,
            "interpretation": [
                "The synthetic anomaly is a 100 KB response on an otherwise normal endpoint; the endpoint-relative size rule detects this hand-designed change in-domain.",
                "Adding graph feature slots did not change the in-domain or held-out metrics in these fixtures.",
                "Neither model variant generalized to an unseen fixture application under the held-out split.",
            ],
        },
        "limitations": [
            "FUR-API has no API specification or graph topology, so graph-enabled FUR results contain unknown graph features and cannot measure graph utility.",
            "The controlled APIs and anomaly scenarios are synthetic; in-domain perfect scores are not evidence of production performance.",
            "The held-out testbed result is zero, so claims about cross-application generalization are unsupported.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"output": str(args.output), "fur_api": fur["feature_comparison"],
                      "controlled_in_domain": in_domain, "controlled_held_out": held_out}, indent=2))


if __name__ == "__main__":
    main()
