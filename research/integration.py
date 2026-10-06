"""Real Kafka → Go → SQLite → Python → browser verification on disposable services."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'anomaly-detector'))
from database import initialize, connect
from detector import DetectorService, fit_model
from testbed import start, specification
from benchmark import collect


def fetch(base,path,body=None):
    request=urllib.request.Request(base+path,data=json.dumps(body).encode() if body is not None else None,
                                   headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=5) as response:return json.load(response)

def wait_for(predicate,timeout=60):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        try:
            result=predicate()
            if result:return result
        except Exception:
            pass
        time.sleep(.2)
    raise AssertionError('Timed out waiting for integration condition')


def run(browser=False):
    processes=[];server=start('resource');base=f'http://127.0.0.1:{server.server_port}';binary=ROOT/'bin/sentry'
    evidence=ROOT/'research/results/integration';evidence.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='sentry-integration-') as directory:
        directory=Path(directory);db=directory/'traffic.db';initialize(db)
        spec=specification('resource',server.server_port);spec_file=directory/'spec.json';spec_file.write_text(json.dumps(spec))
        events,labels=collect('resource',base,spec,88)
        model=fit_model(events[:160],events[160:200]);DetectorService(str(db)).registry.save_model(model)
        subprocess.run([str(binary),'ingest','--file',str(spec_file),'--memgraph-uri','bolt://127.0.0.1:7689'],check=True)
        def launch(args,env=None):
            log=(directory/f'process-{len(processes)}.log').open('w')
            process=subprocess.Popen(args,cwd=ROOT,env={**os.environ,**(env or {})},stdout=log,stderr=log)
            processes.append((process,log));return process
        try:
            detector=launch([str(ROOT/'.venv/bin/python'),'-m','uvicorn','app:app','--app-dir','anomaly-detector','--port','5009'],{'SENTRY_DB_PATH':str(db)})
            wait_for(lambda:fetch('http://127.0.0.1:5009','/health'))
            consumer_args=[str(binary),'consume-traffic','--kafka-brokers','127.0.0.1:19093','--kafka-topic','sentry-integration-'+str(os.getpid()),'--kafka-group','sentry-integration-'+str(os.getpid()),'--sqlite-db',str(db),'--memgraph-uri','bolt://127.0.0.1:7689']
            consumer=launch(consumer_args,{'SENTRY_PYTHON_API':'http://127.0.0.1:5009/predict','SENTRY_REDIS_URL':'redis://127.0.0.1:6389'})
            dashboard_args=[str(binary),'dashboard','--port','8099','--sqlite-db',str(db),'--memgraph-uri','bolt://127.0.0.1:7689']
            dashboard=launch(dashboard_args,{'SENTRY_DETECTOR_URL':'http://127.0.0.1:5009'})
            wait_for(lambda:fetch('http://127.0.0.1:8099','/api/health'))
            normal=next(e for e in events[:160] if e['path']=='/v2/items/1') | {'request_id':'live-normal'}
            abnormal=next(e for e in events[200:] if e['query_params']=='payload=large') | {'request_id':'live-abnormal'}
            shadow=next(e for e in events[200:] if e['path']=='/private/export') | {'request_id':'live-shadow'}
            traffic_file=directory/'traffic.jsonl';traffic_file.write_text(''.join(json.dumps(e)+'\n' for e in [normal,abnormal,shadow]))
            replay=[str(binary),'replay-traffic','--file',str(traffic_file),'--broker','127.0.0.1:19093','--topic',consumer_args[6]]
            # Topic is named explicitly rather than inferred from command position.
            replay[-1]='sentry-integration-'+str(os.getpid())
            subprocess.run(replay,check=True,capture_output=True)
            def evaluated():
                items=fetch('http://127.0.0.1:8099','/api/traffic')['items']
                return items if len(items)==3 and all(e['evaluation_status']=='evaluated' for e in items) else False
            rows=wait_for(evaluated);by_id={e['request_id']:e for e in rows}
            assert by_id['live-abnormal']['prediction']['behavioral_anomaly']
            assert 'shadow_candidate' in by_id['live-shadow']['prediction']['inventory_signals']
            dry=fetch('http://127.0.0.1:8099','/api/scans',{'target':base,'specTitle':'resource','specVersion':'1','dryRun':True})
            dry=wait_for(lambda:(s if (s:=fetch('http://127.0.0.1:8099','/api/scans/'+dry['id']))['status']!='running' else False))
            assert dry['status']=='dry_run' and dry['probesSent']==0
            scan=fetch('http://127.0.0.1:8099','/api/scans',{'target':base,'specTitle':'resource','specVersion':'1','workers':5,'rps':1000,'headers':{'Authorization':'Bearer fixture'}})
            completed=wait_for(lambda:(s if (s:=fetch('http://127.0.0.1:8099','/api/scans/'+scan['id']))['status']!='running' else False))
            assert completed['status']=='completed',completed
            findings=fetch('http://127.0.0.1:8099','/api/findings')
            assert any(f['path']=='/private/export' and 'passive' in f['provenance'] for f in findings)
            assert any(f['verification']=='authentication_exposure' for f in findings)
            if browser:
                from playwright.sync_api import sync_playwright
                with sync_playwright() as playwright:
                    chromium=playwright.chromium.launch(headless=True)
                    page=chromium.new_page(viewport={'width':1440,'height':1000});errors=[]
                    page.on('pageerror',lambda error:errors.append(str(error)))
                    page.goto('http://127.0.0.1:8099');page.wait_for_function("document.querySelector('#overview').textContent.includes('Traffic observations')")
                    page.locator('nav [data-view="findings"]').click();page.locator('#results-table tbody tr').first.click();assert page.locator('#detail').is_visible();page.locator('#close-detail').click()
                    page.locator('#new-scan').click();page.locator('#scan-target').fill(base);page.locator('#scan-rps').fill('1000');page.locator('#dry-run').check();page.locator('#submit-scan').click();page.wait_for_function("document.querySelector('#scan-summary').textContent.includes('dry run')")
                    page.screenshot(path=str(evidence/'dashboard-desktop.png'),full_page=True)
                    page.set_viewport_size({'width':390,'height':844});page.locator('nav [data-view="overview"]').click();page.screenshot(path=str(evidence/'dashboard-mobile.png'),full_page=True)
                    assert not errors,errors
                    chromium.close()
            dashboard.terminate();dashboard.wait(timeout=15)
            dashboard=launch(dashboard_args,{'SENTRY_DETECTOR_URL':'http://127.0.0.1:5009'})
            wait_for(lambda:fetch('http://127.0.0.1:8099','/api/health'))
            persisted=fetch('http://127.0.0.1:8099','/api/scans/'+scan['id']);assert persisted['status']=='completed'
            subprocess.run(replay,check=True,capture_output=True);time.sleep(1)
            assert len(fetch('http://127.0.0.1:8099','/api/traffic')['items'])==3
            # An offline detector leaves durable pending state, then consumer restart retries it.
            detector.terminate();detector.wait(timeout=15)
            offline=normal | {'request_id':'live-pending'}
            traffic_file.write_text(json.dumps(offline)+'\n');subprocess.run(replay,check=True,capture_output=True)
            wait_for(lambda:any(e['request_id']=='live-pending' and e['evaluation_status']=='pending' for e in fetch('http://127.0.0.1:8099','/api/traffic')['items']))
            consumer.terminate();consumer.wait(timeout=15)
            detector=launch([str(ROOT/'.venv/bin/python'),'-m','uvicorn','app:app','--app-dir','anomaly-detector','--port','5009'],{'SENTRY_DB_PATH':str(db)})
            wait_for(lambda:fetch('http://127.0.0.1:5009','/health'))
            consumer=launch(consumer_args,{'SENTRY_PYTHON_API':'http://127.0.0.1:5009/predict','SENTRY_REDIS_URL':'redis://127.0.0.1:6389'})
            wait_for(lambda:any(e['request_id']=='live-pending' and e['evaluation_status']=='evaluated' for e in fetch('http://127.0.0.1:8099','/api/traffic')['items']))
            result={'passed':True,'events':4,'scan_id':scan['id'],'findings':len(findings),'browser_checked':browser,'checks':['real Kafka ingestion','per-event predictions','passive-to-active verification','authentication comparison','zero-request dry run','restart persistence','duplicate replay','detector outage','pending recovery after consumer restart']}
            (evidence/'result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
        finally:
            for process,log in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try:process.wait(timeout=15)
                    except subprocess.TimeoutExpired:process.kill();process.wait()
                log.close()
                (evidence/Path(log.name).name).write_text(Path(log.name).read_text())
            with connect(db) as conn:
                state=[dict(row) for row in conn.execute('SELECT request_id,status,result FROM predictions')]
            (evidence/'prediction-state.json').write_text(json.dumps(state,indent=2))
            server.shutdown();server.server_close()

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--browser',action='store_true');args=parser.parse_args();run(args.browser)
