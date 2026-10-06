"""A supervised, real local fixture demo. Ctrl+C stops its application processes."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import random
import signal
import socket
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / '.local-data/app'
PID_FILE = DATA / 'supervisor.json'
sys.path.insert(0, str(ROOT / 'anomaly-detector'))
from detector import DetectorService, fit_model
from testbed import APPS, specification
from benchmark import collect, request


def get_json(url, data=None):
    import urllib.request
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=5) as response:
        return json.load(response)


def wait_for(fn, label, timeout=90):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        try:
            result = fn()
            if result:
                return result
        except (OSError, ValueError):
            pass
        time.sleep(.5)
    raise RuntimeError(f'{label} did not become ready; see {DATA / "logs"}')


def port_open(port):
    with socket.create_connection(('127.0.0.1', port), timeout=1):
        return True


def running():
    if not PID_FILE.exists():
        return False
    try:
        state=json.loads(PID_FILE.read_text())
        return Path(f'/proc/{state["pid"]}/stat').read_text().split()[21] == state['start_time']
    except (OSError,ValueError,KeyError):
        return False


def stop():
    if not PID_FILE.exists():
        print('No running Sentry local supervisor recorded.')
        return
    state = json.loads(PID_FILE.read_text())
    proc = Path(f'/proc/{state["pid"]}')
    if proc.exists() and proc.joinpath('stat').read_text().split()[21] == state['start_time']:
        os.kill(state['pid'], signal.SIGTERM)
        wait_for(lambda: not PID_FILE.exists(), 'Local shutdown', timeout=30)
        print('Sentry local processes stopped.')
    else:
        PID_FILE.unlink()
        print('Recorded supervisor already exited.')


def run():
    DATA.mkdir(parents=True, exist_ok=True)
    (DATA / 'logs').mkdir(exist_ok=True)
    if PID_FILE.exists():
        state = json.loads(PID_FILE.read_text())
        proc = Path(f'/proc/{state["pid"]}')
        if proc.exists() and proc.joinpath('stat').read_text().split()[21] == state['start_time']:
            raise RuntimeError('Sentry is already running; open http://127.0.0.1:8088')
    for port in [8088, 5001, 9001, 9002, 9003]:
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        try:
            sock.bind(('127.0.0.1', port))
        except OSError as exc:
            raise RuntimeError(f'Port {port} is already occupied') from exc
        finally:
            sock.close()
    PID_FILE.write_text(json.dumps({'pid': os.getpid(), 'start_time': Path('/proc/self/stat').read_text().split()[21]}))
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    children = []
    binary = str(ROOT / 'bin/sentry')
    db = DATA / 'traffic.db'
    topic = 'sentry-local-traffic'

    def launch(name, args, env=None):
        log = (DATA / 'logs' / f'{name}.log').open('a')
        process = subprocess.Popen(args, cwd=ROOT, env={**os.environ, **(env or {})},
                                   stdout=log, stderr=log, start_new_session=True)
        children.append((name, process, log))
        return process

    def checked(args):
        result=subprocess.run(args,cwd=ROOT,timeout=60,capture_output=True,text=True)
        with (DATA/'logs/cli.log').open('a') as log:
            log.write(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(result.stderr[-3000:] or result.stdout[-3000:])

    try:
        print('Waiting for Memgraph, Kafka, and Redis…', flush=True)
        for port in [7688, 19092, 6388]:
            wait_for(lambda port=port: port_open(port), f'Service on {port}')
        baseline, validation = [], []
        for app, port in zip(APPS, [9001, 9002, 9003]):
            launch(app, [str(ROOT / '.venv/bin/python'), 'research/testbed.py', '--app', app,
                         '--port', str(port), '--output', str(DATA / 'specs')])
            base = f'http://127.0.0.1:{port}'
            wait_for(lambda base=base: get_json(base + '/__health'), app)
            spec_file = DATA / 'specs' / f'{app}.json'
            checked([binary, 'ingest', '--file', str(spec_file), '--memgraph-uri', 'bolt://127.0.0.1:7688'])
            events, _ = collect(app, base, specification(app, port), 42)
            baseline.extend(events[:160]); validation.extend(events[160:200])
        service = DetectorService(str(db))
        if service.active_model is None:
            model = fit_model(baseline, validation)
            model.metadata['baseline_source'] = 'normal HTTP requests against local demo fixtures'
            service.registry.save_model(model)
        launch('detector', [str(ROOT / '.venv/bin/python'), '-m', 'uvicorn', 'app:app',
                           '--app-dir', 'anomaly-detector', '--port', '5001'], {'SENTRY_DB_PATH': str(db)})
        wait_for(lambda: get_json('http://127.0.0.1:5001/health'), 'Detector')
        launch('consumer', [binary, 'consume-traffic', '--kafka-brokers', '127.0.0.1:19092',
                            '--kafka-topic', topic, '--kafka-group', 'sentry-local', '--sqlite-db', str(db),
                            '--memgraph-uri', 'bolt://127.0.0.1:7688'],
               {'SENTRY_PYTHON_API': 'http://127.0.0.1:5001/predict', 'SENTRY_REDIS_URL': 'redis://127.0.0.1:6388'})
        launch('dashboard', [binary, 'dashboard', '--port', '8088', '--sqlite-db', str(db),
                             '--memgraph-uri', 'bolt://127.0.0.1:7688'],
               {'SENTRY_DETECTOR_URL': 'http://127.0.0.1:5001'})
        wait_for(lambda: get_json('http://127.0.0.1:8088/api/health'), 'Dashboard')
        rng = random.Random(42)
        batch_file = DATA / 'live-batch.jsonl'
        batch_number = 0
        announced = False
        while True:
            for name, process, _ in children:
                if process.poll() is not None:
                    raise RuntimeError(f'{name} exited; see {DATA / "logs" / (name + ".log")}')
            events = []
            for app, port in zip(APPS, [9001, 9002, 9003]):
                paths = ['/v2/items/1', f'/v2/profile?size={rng.randint(16,48)}', '/v2/large']
                paths.append(['/private/export', '/v1/protected', '/v2/items/1?payload=large'][batch_number % 3])
                for path in paths:
                    code, body, headers = request(f'http://127.0.0.1:{port}', path)
                    events.append({'request_id': str(uuid.uuid4()), 'method': 'GET',
                                   'path': path.split('?',1)[0], 'query_params': path.partition('?')[2],
                                   'request_body': '', 'response_body': body, 'status_code': code,
                                   'response_headers': headers, 'timestamp': dt.datetime.now(dt.timezone.utc).isoformat(),
                                   'spec_title': app, 'spec_version': '1', 'target_origin': f'http://127.0.0.1:{port}'})
            batch_file.write_text(''.join(json.dumps(event) + '\n' for event in events))
            checked([binary, 'replay-traffic', '--file', str(batch_file), '--broker', '127.0.0.1:19092', '--topic', topic])
            if not announced:
                batch_ids={event['request_id'] for event in events}
                wait_for(lambda: batch_ids <= {row['request_id'] for row in get_json('http://127.0.0.1:8088/api/traffic')['items'] if row['evaluation_status']=='evaluated'}, 'Evaluated Kafka traffic')
                # Populate the initial findings through a real scan of the resource fixture.
                scan = get_json('http://127.0.0.1:8088/api/scans', {'target':'http://127.0.0.1:9001',
                    'specTitle':'resource','specVersion':'1','workers':5,'rps':100,
                    'headers':{'Authorization':'Bearer fixture'}})
                wait_for(lambda: get_json('http://127.0.0.1:8088/api/scans/' + scan['id'])['status'] != 'running', 'Initial scan')
                print('\nSENTRY READY: http://127.0.0.1:8088\nDetector API: http://127.0.0.1:5001/docs\n'
                      'Fixtures: 9001 resource · 9002 versioned · 9003 gateway\n'
                      'Traffic is real HTTP against intentionally vulnerable local fixtures.\n'
                      'Ctrl+C stops this demo. Logs and history: .local-data/app/\n', flush=True)
                announced = True
            batch_number += 1
            time.sleep(3)
    except KeyboardInterrupt:
        print('Stopping Sentry local processes…', flush=True)
    finally:
        for _, process, log in reversed(children):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
            log.close()
        PID_FILE.unlink(missing_ok=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--stop', action='store_true')
    parser.add_argument('--running', action='store_true')
    args = parser.parse_args()
    if args.running:
        sys.exit(0 if running() else 1)
    stop() if args.stop else run()
