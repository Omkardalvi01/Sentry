#!/usr/bin/env python3
"""Score graph-backed zombie and shadow API scans on labeled local fixtures."""

import argparse
import hashlib
import json
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVAL = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "research"))
sys.path.insert(0, str(ROOT / "anomaly-detector"))
from benchmark import collect  # noqa: E402
from database import connect, initialize  # noqa: E402
from testbed import APPS, specification, start, truth  # noqa: E402


def ratio(n, d):
    return round(n / d, 6) if d else 0.0


def metrics(expected, predicted):
    tp = len(expected & predicted)
    fp = len(predicted - expected)
    fn = len(expected - predicted)
    precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision,
            "recall": recall, "f1": ratio(2 * precision * recall, precision + recall)}


def run(command, cwd, logfile):
    started = time.perf_counter()
    result = subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, check=False, timeout=180)
    logfile.write_text(result.stdout)
    if result.returncode:
        raise RuntimeError("command failed (%d): %s\n%s" %
                           (result.returncode, " ".join(map(str, command)), result.stdout[-4000:]))
    return round(time.perf_counter() - started, 3), result.stdout


def findings_from_db(db_path):
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute("SELECT data FROM findings ORDER BY rowid").fetchall()
    return [json.loads(row[0]) for row in rows]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=EVAL / "bin/sentry")
    parser.add_argument("--memgraph-uri", default="bolt://127.0.0.1:7689")
    parser.add_argument("--raw-dir", type=Path, default=EVAL / "results/graph-inventory-raw")
    parser.add_argument("--output", type=Path, default=EVAL / "results/zombie-shadow-graph.json")
    parser.add_argument("--apps", nargs="+", choices=APPS, default=list(APPS))
    args = parser.parse_args()
    if not args.binary.is_file():
        parser.error("Sentry binary not found; build evaluation/bin/sentry first")

    args.raw_dir.mkdir(parents=True, exist_ok=True)
    by_mode = {"active_only": [], "graph_plus_passive_inventory": []}
    by_class = {mode: {name: [] for name in ("zombie", "shadow")} for mode in by_mode}
    per_app = {}
    ingest_records = {}
    strategy_set = "deprecated_alive,version_probe,method_probe,shadow_path,auth_bypass"

    for app in args.apps:
        server = start(app)
        base = "http://127.0.0.1:%d" % server.server_port
        spec = specification(app, server.server_port)
        app_dir = args.raw_dir / app
        app_dir.mkdir(parents=True, exist_ok=True)
        spec_path = app_dir / "spec.json"
        spec_path.write_text(json.dumps(spec, indent=2) + "\n")
        try:
            events, labels = collect(app, base, spec, seed=11)
            observed_unknown = {}
            for event in events[200:]:
                if event["graph_known"] is False:
                    observed_unknown[(event["method"], event["path"])] = event
            labels = truth(app)
            expected = {tuple(x) for x in labels["positive_endpoints"]}
            per_app[app] = {"target": base, "ground_truth_endpoints": len(expected),
                            "passive_candidates": len(observed_unknown), "modes": {}}

            ingest_seconds, ingest_output = run(
                [str(args.binary), "ingest", "--file", str(spec_path), "--clean",
                 "--memgraph-uri", args.memgraph_uri], ROOT,
                app_dir / "ingest.log")
            ingest_records[app] = {"seconds": ingest_seconds,
                                   "spec_sha256": hashlib.sha256(spec_path.read_bytes()).hexdigest(),
                                   "summary": ingest_output[-1200:]}

            for mode in by_mode:
                workdir = app_dir / mode
                workdir.mkdir(exist_ok=True)
                db_path = workdir / "traffic.db"
                # A rerun must start from an empty traffic and findings store.
                db_path.unlink(missing_ok=True)
                initialize(str(db_path))
                if mode == "graph_plus_passive_inventory":
                    with connect(str(db_path)) as conn:
                        conn.executemany("""INSERT INTO api_traffic
                            (request_id,method,path,query_params,status_code,timestamp,
                             graph_known,spec_title,spec_version,training_eligible)
                            VALUES (?,?,?,?,?,?,?,?,?,0)""", [
                            ("eval-%s-%s" % (method, path), method, path, "", event["status_code"],
                             event["timestamp"], 0, app, "1")
                            for (method, path), event in sorted(observed_unknown.items())
                        ])

                scan_cmd = [str(args.binary), "scan", "--target", base,
                            "--spec-title", app, "--spec-version", "1",
                            "--strategies", strategy_set, "--workers", "5", "--rps", "1000",
                            "--max-requests", "250", "--header", "Authorization: Bearer fixture",
                            "--output", "json", "--memgraph-uri", args.memgraph_uri]
                seconds, _ = run(scan_cmd, workdir, workdir / "scan.log")
                findings = findings_from_db(db_path)
                predicted = set()
                predicted_by_class = {name: set() for name in ("zombie", "shadow")}
                zombie_truth = {tuple(x) for x in labels["zombie_endpoints"]}
                shadow_truth = {tuple(x) for x in labels["shadow_endpoints"]}
                for finding in findings:
                    pair = (finding["method"], finding["path"])
                    if finding.get("strategy") == "auth_bypass" or finding.get("verification") == "candidate":
                        continue
                    predicted.add(pair)
                    if pair in zombie_truth:
                        predicted_by_class["zombie"].add(pair)
                    elif pair in shadow_truth or finding.get("strategy") == "shadow_path":
                        predicted_by_class["shadow"].add(pair)
                    else:
                        predicted_by_class["zombie"].add(pair)
                result_metrics = metrics(expected, predicted)
                scans = []
                with sqlite3.connect(db_path) as conn:
                    scans = [json.loads(row[0]) for row in conn.execute("SELECT data FROM scans")]
                scan = scans[-1] if scans else {}
                result = {**result_metrics, "findings": len(findings),
                          "verified_endpoints": sorted([list(x) for x in predicted]),
                          "probes_sent": scan.get("probesSent", 0),
                          "status": scan.get("status", "missing"), "seconds": seconds}
                per_app[app]["modes"][mode] = result
                by_mode[mode].append((app, expected, predicted, result))
                result["classes"] = {}
                for class_name in ("zombie", "shadow"):
                    class_expected = {tuple(x) for x in labels[class_name + "_endpoints"]}
                    class_predicted = predicted_by_class[class_name]
                    class_metrics = metrics(class_expected, class_predicted)
                    result["classes"][class_name] = class_metrics
                    by_class[mode][class_name].append((app, class_expected, class_predicted))

        finally:
            server.shutdown()
            server.server_close()

    aggregate = {}
    for mode, app_results in by_mode.items():
        expected = {(app, *pair) for app, positives, _, _ in app_results for pair in positives}
        predicted = {(app, *pair) for app, _, found, _ in app_results for pair in found}
        aggregate[mode] = {**metrics(expected, predicted),
                           "probes_sent": sum(r["probes_sent"] for _, _, _, r in app_results),
                           "seconds": round(sum(r["seconds"] for _, _, _, r in app_results), 3),
                           "evaluated_apps": len(app_results)}
        aggregate[mode]["classes"] = {}
        for class_name, class_results in by_class[mode].items():
            class_expected = {(app, *pair) for app, positives, _ in class_results for pair in positives}
            class_predicted = {(app, *pair) for app, _, found in class_results for pair in found}
            aggregate[mode]["classes"][class_name] = metrics(class_expected, class_predicted)

    report = {
        "evaluation": "Graph-backed zombie and shadow API inventory detection",
        "sentry_revision": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
        "dataset": "Sentry controlled local API testbeds",
        "protocol": "Ingest each OpenAPI spec into Memgraph; run the production graph-backed scan. Compare active-only probes with graph inventory plus held-out passive unknown-route candidates. Exclude auth-bypass findings from inventory metrics.",
        "memgraph_uri": args.memgraph_uri,
        "strategies": strategy_set,
        "request_budget_per_scan": 250,
        "apps": per_app,
        "aggregate": aggregate,
        "ingestion": ingest_records,
        "limitations": [
            "Controlled synthetic API behavior and labels, not independent production deployments.",
            "Passive candidates are drawn from held-out test traffic; this measures verification after observation, not discovery from arbitrary logs.",
            "This measures API inventory discrepancies, not downstream service impact or blast radius.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"output": str(args.output), "aggregate": aggregate}, indent=2))


if __name__ == "__main__":
    main()
