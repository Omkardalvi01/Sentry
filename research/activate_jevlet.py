"""Register and activate a trusted local checkpoint using existing model APIs.

Without --detector-url the service must be stopped; activation is picked up on
its next startup. With a live service, use its activation endpoint so memory
and the persistent activation table change together. Never uploads weights.
"""
import argparse
import json
from pathlib import Path
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'anomaly-detector'))
from jevlet_service import JevletService


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkpoint', type=Path, required=True)
    parser.add_argument('--db', type=Path, required=True)
    parser.add_argument('--repo', type=Path)
    parser.add_argument('--device', default='cuda')
    parser.add_argument('--detector-url', help='Running detector base URL; omit only when stopped')
    args = parser.parse_args()
    if args.detector_url:
        with urllib.request.urlopen(args.detector_url.rstrip('/') + '/health', timeout=10) as response:
            health = json.load(response)
        if health.get('model_kind') != 'jevlet':
            raise ValueError('Expected a running Jevlet detector')
    service = JevletService(args.db, checkpoint=args.checkpoint, repo=args.repo, device=args.device)
    version = service.register_checkpoint(args.checkpoint)
    if args.detector_url:
        request = urllib.request.Request(args.detector_url.rstrip('/') + '/jevlet/models/' + version + '/activate',
                                         data=b'', method='POST')
        with urllib.request.urlopen(request, timeout=90) as response:
            result = json.load(response)
        if result['model_version'] != version:
            raise ValueError('The live detector did not activate the registered checkpoint')
    else:
        service.activate(version)
    print(json.dumps({'model_version': version, 'checkpoint': str(args.checkpoint.resolve()),
                      'activation': 'live' if args.detector_url else 'next-startup'}))


if __name__ == '__main__':
    main()
