#!/usr/bin/env python3
"""Run Sentry's local-spec scanner against a loopback API and record results."""

import argparse
import datetime as dt
import hashlib
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
EVAL = Path(__file__).resolve().parent


def run(command, log_path, timeout):
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=timeout, check=False,
        )
        output, code = completed.stdout, completed.returncode
    except subprocess.TimeoutExpired as error:
        output = (error.stdout or b"").decode(errors="replace") if isinstance(error.stdout, bytes) else (error.stdout or "")
        output += "\nTimed out after %s seconds\n" % timeout
        code = 124
    log_path.write_text(output)
    return {"exit_code": code, "elapsed_seconds": round(time.monotonic() - started, 3), "log": str(log_path.relative_to(EVAL))}


def summarize(report):
    scan = report.get("scan", {})
    findings = report.get("findings") or []
    by_strategy, by_severity = {}, {}
    for finding in findings:
        strategy = finding.get("strategy", "unknown")
        severity = finding.get("severity", "unknown")
        by_strategy[strategy] = by_strategy.get(strategy, 0) + 1
        by_severity[severity] = by_severity.get(severity, 0) + 1
    return {"scan": scan, "findings": findings,
            "findings_by_strategy": by_strategy, "findings_by_severity": by_severity}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--source", required=True, type=Path, help="Cloned upstream repository")
    parser.add_argument("--binary", type=Path, default=EVAL / "bin/sentry")
    parser.add_argument("--strategies", default="deprecated_alive,version_probe,method_probe,shadow_path,auth_bypass")
    parser.add_argument("--rps", type=int, default=5)
    args = parser.parse_args()
    target = urlparse(args.target)
    if target.scheme not in ("http", "https") or target.hostname not in ("localhost", "127.0.0.1", "::1"):
        parser.error("--target must be a local HTTP service")
    if not args.name.replace("-", "").replace("_", "").isalnum():
        parser.error("--name must be alphanumeric, with optional dashes or underscores")
    if not args.spec.is_file() or not args.binary.is_file():
        parser.error("spec or Sentry binary is missing")
    results = EVAL / "results"
    results.mkdir(exist_ok=True)
    spec_hash = hashlib.sha256(args.spec.read_bytes()).hexdigest()
    revision = subprocess.run(
        ["git", "-C", str(args.source), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    record = {
        "name": args.name,
        "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source_revision": revision,
        "spec_sha256": spec_hash,
        "spec_path": str(args.spec.resolve().relative_to(ROOT)),
        "target": args.target,
        "parameters": {"strategies": args.strategies, "rps": args.rps},
    }
    try:
        with urllib.request.urlopen(args.target, timeout=10) as response:
            record["target_http_status"] = response.status
    except urllib.error.HTTPError as error:
        record["target_http_status"] = error.code
    except (urllib.error.URLError, TimeoutError) as error:
        record["target_error"] = str(error)
        record["status"] = "target_unavailable"
    if "target_error" not in record:
        report_path = results / (args.name + "-scan-report.json")
        record["scan"] = run([
            str(args.binary), "scan-spec", "--file", str(args.spec),
            "--target", args.target, "--strategies", args.strategies,
            "--rps", str(args.rps), "--output-file", str(report_path),
        ], results / (args.name + "-scan.log"), 900)
        record["scan_report"] = str(report_path.relative_to(EVAL))
        record["status"] = "completed" if record["scan"]["exit_code"] == 0 else "scan_failed"
        if report_path.exists():
            record["measurements"] = summarize(json.loads(report_path.read_text()))
    output = results / (args.name + ".json")
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": record["status"], "results": str(output), "measurements": record["measurements"]}, indent=2))
    return 0 if record["status"] == "completed" else 1


if __name__ == "__main__":
    sys.exit(main())
