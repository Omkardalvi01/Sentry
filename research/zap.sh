#!/bin/sh
# Supplementary comparison only. Keep original reports for category mapping.
set -eu
if [ "$#" -ne 2 ]; then echo "Usage: research/zap.sh SPEC_FILE TARGET_BASE_URL" >&2; exit 2; fi
spec_file="$1"
target_base="$2"
mkdir -p research/results/zap
cp "$spec_file" research/results/zap/spec.json
python3 - "$target_base" <<'PY'
import json,sys
from pathlib import Path
p=Path('research/results/zap/spec.json');spec=json.loads(p.read_text());spec['servers']=[{'url':sys.argv[1]}];p.write_text(json.dumps(spec))
PY
docker run --rm --network host -v "$PWD/research/results/zap:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:2.16.1 zap-api-scan.py -t /zap/wrk/spec.json -f openapi -J report.json -r report.html
