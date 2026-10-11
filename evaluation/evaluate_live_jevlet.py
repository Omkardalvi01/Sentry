"""Measure a running Jevlet service, optionally through Kafka and durable Go storage."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
import uuid

from compare_local_models import metrics, read_rows, write_json
from replay_fur import event_from_row

ROOT = Path(__file__).resolve().parents[1]


def fetch(url, body=None):
    request = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                     headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--api', default='http://127.0.0.1:5001')
    parser.add_argument('--source', type=Path, default=ROOT/'evaluation/datasets/FUR-API/dataset/test.csv')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--db', type=Path, help='Use the real Kafka consumer and read its durable predictions')
    parser.add_argument('--broker', default='127.0.0.1:19092')
    parser.add_argument('--topic', default='sentry-local-traffic')
    parser.add_argument('--reuse-published', type=Path, help='Recheck a preserved JSONL replay against the same test source without republishing')
    parser.add_argument('--failure-data', type=Path, default=ROOT/'.local-data/external-dataset-review/rcaeval-failure-windows.json')
    args = parser.parse_args()
    if (args.output/'metrics.json').exists():
        parser.error('Output already contains results; choose another directory')
    args.output.mkdir(parents=True, exist_ok=True)
    health_before = fetch(args.api+'/health')
    if health_before['model_kind'] != 'jevlet':
        raise ValueError('Running service is not Jevlet')
    models_before = fetch(args.api+'/jevlet/models')
    rows, excluded = read_rows(args.source)
    run_id = 'jevlet-test-'+uuid.uuid4().hex+'-'
    events = [event_from_row(row, run_id+str(i)) for i,row in enumerate(rows)]
    # Labels and user identity are kept only in this evaluator, never published.
    for event in events:
        event.pop('client_id', None)
        if event['response_size_bytes'] is not None:
            if not event['response_size_bytes'].is_integer():
                raise ValueError('Dataset wire size is not a whole number')
            event['response_size_bytes'] = int(event['response_size_bytes'])
    if args.reuse_published:
        if not args.db:
            parser.error('--reuse-published requires --db')
        captured = [json.loads(line) for line in args.reuse_published.read_text(encoding='utf-8').splitlines()]
        if len(captured)!=len(events):
            raise ValueError('Preserved replay count does not match the dataset')
        for expected,saved in zip(events,captured):
            if expected | {'request_id':saved['request_id']} != saved:
                raise ValueError('Preserved replay evidence differs from this test source')
        events = captured
        run_id = events[0]['request_id'].rsplit('-',1)[0]+'-'
        if any(not e['request_id'].startswith(run_id) for e in events):
            raise ValueError('Preserved replay mixes run identities')
    # The runtime requires an absolute HTTP path. Do not silently rewrite
    # malformed dataset requests or count rejected records as model decisions.
    excluded_paths = sum(not e['path'].startswith('/') for e in events)
    accepted = [(e,r) for e,r in zip(events,rows) if e['path'].startswith('/')]
    events,rows = map(list,zip(*accepted))
    began = time.perf_counter()
    if args.db:
        traffic_file = args.output/'held-out-traffic.jsonl'
        traffic_file.write_text(''.join(json.dumps(e)+'\n' for e in events), encoding='utf-8')
        binary = ROOT/'bin/sentry.exe' if (ROOT/'bin/sentry.exe').is_file() else ROOT/'bin/sentry'
        if not args.reuse_published:
            result = subprocess.run([str(binary),'replay-traffic','--file',str(traffic_file),
                                     '--broker',args.broker,'--topic',args.topic], capture_output=True,text=True,timeout=70)
            (args.output/'publish.log').write_text(result.stdout+result.stderr, encoding='utf-8')
            result.check_returncode()
        predictions = {}
        deadline = time.monotonic()+600
        while len(predictions)<len(events):
            with sqlite3.connect(args.db) as conn:
                records = conn.execute('SELECT request_id,status,result FROM predictions WHERE request_id LIKE ?',
                                       (run_id+'%',)).fetchall()
            if any(status=='rejected' for _,status,_ in records):
                raise ValueError('Held-out event was rejected by the consumer')
            predictions = {identity:json.loads(payload) for identity,status,payload in records if status=='evaluated'}
            if time.monotonic()>deadline:
                raise TimeoutError(f'Only {len(predictions)}/{len(events)} events evaluated')
            if len(predictions)<len(events):
                time.sleep(1)
        outputs = [predictions[e['request_id']] for e in events]
        pipeline = 'Kafka -> Go graph enrichment -> Jevlet HTTP -> SQLite'
    else:
        outputs = [fetch(args.api+'/jevlet/predict', e) for e in events]
        pipeline = 'Jevlet HTTP endpoint'
    elapsed = time.perf_counter()-began
    if any(p.get('model_kind')!='jevlet' or p.get('evaluation_status')!='evaluated' for p in outputs):
        raise ValueError('Unexpected model or incomplete prediction')
    versions = {p['model_version'] for p in outputs}
    if versions != {health_before['active_model_id']}:
        raise ValueError('Model changed during the held-out evaluation')
    thresholds = {p['threshold'] for p in outputs}
    if len(thresholds)!=1:
        raise ValueError('Threshold changed during evaluation')
    quality = metrics([r['type'].strip()=='anomaly' for r in rows],
                      [p['anomaly_score'] for p in outputs], next(iter(thresholds)))
    predictions = [{'request_id':e['request_id'],'truth':r['type'].strip(), 'prediction':p}
                   for e,r,p in zip(events,rows,outputs)]
    write_json(args.output/'request-predictions.json', predictions)
    result = {'pipeline':pipeline,'health':health_before,'model_registry':models_before,
              'test_rows':len(rows),'excluded_invalid_status':excluded,
              'excluded_non_absolute_paths':excluded_paths,
              'reused_published_events':str(args.reuse_published) if args.reuse_published else None,
              'source_sha256':hashlib.sha256(args.source.read_bytes()).hexdigest(),
              'request_anomaly':quality,'pipeline_seconds':elapsed,
              'graph_context_counts':{status:sum(p['graph_context_status']==status for p in outputs)
                                     for status in {p['graph_context_status'] for p in outputs}},
              'inventory_flagged_rows':sum(bool(p['inventory_signals']) for p in outputs)}
    if args.failure_data.is_file() and health_before.get('service_failure_available'):
        data = json.loads(args.failure_data.read_text(encoding='utf-8'))
        records = data['splits']['test']
        failures = [fetch(args.api+'/jevlet/service-failure',{'telemetry_text':r['text']}) for r in records]
        if {p['model_version'] for p in failures} != versions:
            raise ValueError('Service-failure model changed during evaluation')
        result['service_failure'] = metrics([bool(r['label']) for r in records],
                                           [p['score'] for p in failures],failures[0]['threshold'])
        result['service_failure_rows'] = len(records)
        result['service_failure_cases'] = len({r['case'] for r in records})
        result['service_failure_label_policy'] = data['label_policy']
        write_json(args.output/'failure-predictions.json', [{'case':r['case'],'start':r['start'],
                   'truth':r['label'],'prediction':p} for r,p in zip(records,failures)])
    for path in ('/predict','/models'):
        try:
            fetch(args.api+path, events[0] if path=='/predict' else None)
        except urllib.error.HTTPError as exc:
            if exc.code!=404:
                raise
        else:
            raise ValueError('Legacy forest endpoint still exists: '+path)
    if fetch(args.api+'/health')['active_model_id']!=health_before['active_model_id']:
        raise ValueError('Evaluation changed the active model')
    write_json(args.output/'metrics.json',result)
    report = '# Live Jevlet integration evaluation\n\n'+pipeline+'; '+health_before['device']+' inference, FP32. The existing seed-42 checkpoint and normal-calibrated thresholds were fixed before this test.\n\n'
    report += f'FUR-API official held-out test: {len(rows)} labelled requests ({excluded} invalid status row and {excluded_paths} non-absolute paths excluded by the runtime contract). Labels are used only for evaluation.\n\n'
    report += '| Task | Accuracy | Precision | Recall | F1 | False alarms |\n|---|---:|---:|---:|---:|---:|\n'
    for name,key in [('Request anomaly','request_anomaly'),('Service fault exposure','service_failure')]:
        if key in result:
            m=result[key]
            report += f'| {name} | {m["accuracy"]:.2%} | {m["precision"]:.2%} | {m["recall"]:.2%} | {m["f1"]:.3f} | {m["false_positive_rate"]:.2%} |\n'
    report += '\nRequest anomalies: '+json.dumps({k:quality[k] for k in ('true_positive','false_positive','true_negative','false_negative')})+'.\n\n'
    report += 'Inventory signals are evaluated separately from request classification. Graph context counts: '+json.dumps(result['graph_context_counts'])+'.\n\n'
    report += 'FUR-API is one dataset with repeated evidence and overlapping dates between official training/test rows. These scores do not establish performance on future production traffic or the local demo fixtures. The earlier comparison manifest documents partition and evidence overlap.\n\n'
    if 'service_failure' in result:
        report += f'Service-failure output: {result["service_failure_rows"]} correlated telemetry windows from {result["service_failure_cases"]} held-out RCAEval incidents, tested through the separate HTTP route. Labels describe fault exposure, not malicious requests or verified per-request failure. This route requires a prepared telemetry window; no Kafka telemetry aggregation was added.\n\n'
    report += 'Isolation Forest source and legacy registry are retained; their HTTP prediction/model endpoints return 404. All changes, checkpoints, and evaluation results remain local.\n'
    (args.output/'REPORT.md').write_text(report,encoding='utf-8')
    print(json.dumps(result,indent=2),flush=True)


if __name__=='__main__':
    main()
