"""Reproducible local evaluation using production Go scanning and Python models."""
import argparse
import csv
import datetime as dt
import json
import os
from pathlib import Path
import random
import re
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request

import numpy as np
from sklearn.metrics import average_precision_score, precision_recall_fscore_support
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'anomaly-detector'))
from detector import fit_model
from testbed import APPS, specification, start, truth

ROOT=Path(__file__).resolve().parents[1]

def resolve(path, spec):
    path=path.split('?',1)[0]
    routes=sorted(spec['paths'],key=lambda p:(p.count('{'),p))
    for route in routes:
        expression='/'.join('[^/]+' if p.startswith('{') else re.escape(p) for p in route.split('/'))
        if re.fullmatch(expression,path):return route
    return path

def request(base,path):
    req=urllib.request.Request(base+path,headers={'Authorization':'Bearer fixture'})
    try:response=urllib.request.urlopen(req,timeout=5)
    except urllib.error.HTTPError as exc:response=exc
    with response:
        return response.status,response.read().decode(),dict(response.headers)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args):return None
urllib.request.install_opener(urllib.request.build_opener(NoRedirect()))

def collect(app,base,spec,seed):
    rng=random.Random(seed);events=[];labels=[]
    # The baseline consists of normal workflows; validation is later in time.
    normal=['/v2/items/1','/v2/profile','/v2/large']
    test=['/v2/items/42','/v2/new','/v1/items/1','/v1/protected','/v1/public','/v1/profile','/private/export','/debug','/v1/retired','/v1/redirect','/v1/waf','/v1/mismatch','/v2/error','/nonsense','/v2/items/1?payload=large']
    for i in range(320):
        phase='train' if i<160 else 'validation' if i<200 else 'test'
        path=rng.choice(normal) if phase!='test' else test[(i-200)%len(test)]
        if path=='/v2/profile':path+=f'?size={rng.randint(16,48)}'
        code,body,headers=request(base,path);route=resolve(path,spec);operation=spec['paths'].get(route,{}).get('get')
        event={'request_id':f'{app}-{seed}-{i}','spec_title':app,'spec_version':'1','method':'GET','path':path.split('?',1)[0],
               'query_params':path.partition('?')[2],'timestamp':(dt.datetime(2026,1,1,tzinfo=dt.timezone.utc)+dt.timedelta(minutes=i)).isoformat(),
               'request_body':'','response_body':body,'status_code':code,'response_headers':headers,
               'graph_path_template':route,'graph_known':operation is not None,'graph_context_status':'resolved',
               'graph_deprecated':bool(operation and operation.get('deprecated')),'graph_security':json.dumps(operation.get('security',[]) if operation else [])}
        events.append(event)
        positive={tuple(e) for e in truth(app)['positive_endpoints']}
        labels.append({'request_id':event['request_id'],'phase':phase,'inventory_positive':('GET',route) in positive,
                       'behavioral_positive':'payload=large' in path,'scenario':path})
    return events,labels

def binary_metrics(expected,predicted):
    expected=set(expected);predicted=set(predicted);tp=len(expected&predicted);fp=len(predicted-expected);fn=len(expected-predicted)
    precision=tp/(tp+fp) if tp+fp else 0;recall=tp/(tp+fn) if tp+fn else 0
    return {'tp':tp,'fp':fp,'fn':fn,'precision':precision,'recall':recall,'f1':2*precision*recall/(precision+recall) if precision+recall else 0}

def scan(binary,base,spec_file,candidates,output,extra=()):
    args=[str(binary),'scan-spec','--file',str(spec_file),'--target',base,'--header','Authorization: Bearer fixture','--output-file',str(output),'--rps','1000','--max-requests','250']
    if candidates:args+=['--candidate-file',str(candidates)]
    args+=list(extra);started=time.perf_counter();subprocess.run(args,cwd=ROOT,check=True,capture_output=True)
    result=json.loads(output.read_text());return result,time.perf_counter()-started

def run(output,binary,seeds):
    output.mkdir(parents=True,exist_ok=True);inventory_results=[];behavior_results=[];datasets={}
    for seed in seeds:
        for app in APPS:
            server=start(app);base=f'http://127.0.0.1:{server.server_port}';spec=specification(app,server.server_port)
            folder=output/f'{app}-{seed}';folder.mkdir(exist_ok=True);spec_file=folder/'spec.json';spec_file.write_text(json.dumps(spec,indent=2));(folder/'truth.json').write_text(json.dumps(truth(app),indent=2))
            try:
                events,labels=collect(app,base,spec,seed);datasets[(app,seed)]=(events,labels)
                (folder/'events.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events));(folder/'labels.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in labels))
                test_events=events[200:];candidates=sorted({(e['method'],e['graph_path_template']) for e in test_events if e['graph_known'] is False})
                candidate_file=folder/'candidates.json';candidate_file.write_text(json.dumps([{'method':m,'path':p} for m,p in candidates]))
                expected={tuple(e) for e in truth(app)['positive_endpoints']}
                baseline={('GET',e['graph_path_template']) for e in test_events if e['status_code']<400 and (e['graph_deprecated'] or e['graph_known'] is False)}
                passive={('GET',e['graph_path_template']) for e in test_events if e['graph_deprecated'] or e['graph_known'] is False}
                for name,predicted in [('status_based',baseline),('passive_inventory',passive)]:inventory_results.append({'app':app,'seed':seed,'method':name,**binary_metrics(expected,predicted),'requests':0,'seconds':0,'detection_delay_seconds':None})
                for name,candidate,extra in [('active_only',None,()),('hybrid',candidate_file,()),('without_schema',candidate_file,('--disable-schema',)),('without_catch_all',candidate_file,('--disable-catch-all',)),('without_passive',None,())]:
                    response,duration=scan(binary,base,spec_file,candidate,folder/f'{name}.json',extra)
                    predicted={(f['method'],f['path']) for f in response['findings'] if f['strategy']!='auth_bypass' and f['verification']!='candidate'}
                    inventory_results.append({'app':app,'seed':seed,'method':name,**binary_metrics(expected,predicted),'requests':response['scan']['probesSent'],'seconds':duration,'detection_delay_seconds':duration})
                    (folder/f'{name}-false-positives.json').write_text(json.dumps([list(e) for e in sorted(predicted-expected)]))
                for graph in [False,True]:
                    model=fit_model(events[:160],events[160:200],graph=graph,seed=seed)
                    evaluate_model(model,test_events,labels[200:],behavior_results,app,seed,'inventory_behavior' if graph else 'traffic_behavior',graph)
                    evaluate_model(model,test_events,labels[200:],behavior_results,app,seed,'inventory_if_only' if graph else 'traffic_if_only',graph,numerical=False)
                    if not graph:
                        evaluate_model(model,test_events,labels[200:],behavior_results,app,seed,'without_ml',graph,ml=False)
                    (folder/('graph-model.json' if graph else 'traffic-model.json')).write_text(json.dumps(model.metadata,indent=2))
            finally:server.shutdown();server.server_close()
    # Hold out every application completely; no calibration on held-out traffic.
    for seed in seeds:
        for held in APPS:
            training=sum([datasets[(app,seed)][0][:160] for app in APPS if app!=held],[])
            validation=sum([datasets[(app,seed)][0][160:200] for app in APPS if app!=held],[])
            events,labels=datasets[(held,seed)]
            for graph in [False,True]:
                model=fit_model(training,validation,graph=graph,seed=seed)
                evaluate_model(model,events[200:],labels[200:],behavior_results,held,seed,'held_out_inventory_behavior' if graph else 'held_out_traffic_behavior',graph)
    for name,rows in [('inventory',inventory_results),('behavior',behavior_results)]:
        with (output/f'{name}.csv').open('w') as f:writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    summarize(output,inventory_results,behavior_results)
    manifest={'seeds':seeds,'apps':APPS,'events_per_app_seed':320,'split':[160,40,120],'scan_request_budget':250,'scan_rps':1000,'scan_workers':5,
              'python':sys.version,'numpy':np.__version__,'binary_sha256':__import__('hashlib').sha256(binary.read_bytes()).hexdigest(),
              'limitations':['synthetic local HTTP traffic','fixed controlled scenarios','scan duration is an upper-bound batch verification delay; not Kafka end-to-end delay','latency is local model inference, not end-to-end service latency','schema mismatch negatives require fixture truth; response mismatch alone does not establish endpoint retirement']}
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2));print(json.dumps(json.loads((output/'summary.json').read_text()),indent=2))

def evaluate_model(model,events,labels,rows,app,seed,name,graph,ml=True,numerical=True):
    raw=[];pred=[];latencies=[]
    for event in events:
        started=time.perf_counter();result=model.predict(event,graph=graph,ml=ml,numerical=numerical);latencies.append((time.perf_counter()-started)*1000)
        raw.append(result['behavioral_score']);pred.append(result['behavioral_anomaly'])
    expected=[label['behavioral_positive'] for label in labels]
    p,r,f,_=precision_recall_fscore_support(expected,pred,average='binary',zero_division=0)
    rows.append({'app':app,'seed':seed,'method':name,'precision':float(p),'recall':float(r),'f1':float(f),
                 'pr_auc':float(average_precision_score(expected,raw)),'p50_ms':float(np.percentile(latencies,50)),
                 'p95_ms':float(np.percentile(latencies,95)),'events_per_second':1000/float(np.mean(latencies)),
                 'max_rss_kib':__import__('resource').getrusage(__import__('resource').RUSAGE_SELF).ru_maxrss,
                 'false_positives':sum(bool(p) and not e for p,e in zip(pred,expected))})

def summarize(output,inventory,behavior):
    summary={}
    for kind,rows in [('inventory',inventory),('behavior',behavior)]:
        methods=sorted({r['method'] for r in rows});summary[kind]={}
        for method in methods:
            values=[r['f1'] for r in rows if r['method']==method]
            rng=np.random.default_rng(42);means=[float(np.mean(rng.choice(values,len(values),replace=True))) for _ in range(2000)]
            summary[kind][method]={'mean_f1':statistics.mean(values),'bootstrap_95_ci':list(np.percentile(means,[2.5,97.5]))}
    (output/'summary.json').write_text(json.dumps(summary,indent=2))
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig,axes=plt.subplots(1,2,figsize=(12,4),layout='constrained')
    for ax,(kind,methods) in zip(axes,summary.items()):
        names=list(methods);ax.barh(names,[methods[n]['mean_f1'] for n in names],color='#397763');ax.set_xlim(0,1);ax.set_xlabel('Mean F1');ax.set_title(kind.capitalize()+' · controlled local testbeds')
    fig.savefig(output/'comparison.svg');fig.savefig(output/'comparison.png',dpi=180);plt.close(fig)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,default=ROOT/'research/results');parser.add_argument('--binary',type=Path,default=ROOT/'bin/sentry');parser.add_argument('--seeds',type=int,nargs='+',default=[11,22,33,44,55]);args=parser.parse_args();run(args.output,args.binary,args.seeds)
