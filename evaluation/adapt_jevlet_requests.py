"""Train a scoped request adapter on CUDA with separate selection/calibration.

Input JSON: splits train/selection/calibration/test, each containing event,
truth, app and family. Input overlap is audited before fitting; test scores are
computed only after the head and thresholds have been saved. Test labels never
choose weights or thresholds. Generated results are not production accuracy.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time

os.environ.setdefault('USE_TF', '0')
os.environ.setdefault('HF_HUB_OFFLINE', '1')
os.environ.setdefault('TRANSFORMERS_OFFLINE', '1')
os.environ.setdefault('TOKENIZERS_PARALLELISM', 'false')
import numpy as np
import torch
from safetensors.torch import save_file
from compare_local_models import metrics, write_json
from local_models import LocalDetector, threshold_at_fpr
from jevlet_request_adapter import RequestHead, encode_requests, request_text


def group_weights(rows):
    groups = [(r['app'], bool(r['truth'])) for r in rows]
    counts = {key: groups.count(key) for key in set(groups)}
    return torch.tensor([1 / counts[g] for g in groups], device='cuda')


def evaluate_records(detector, rows):
    events = [r['event'] for r in rows]
    scores = detector.score(events)
    outputs = []
    for row, score in zip(rows, scores):
        adapted = detector.request_adapter and detector.request_adapter.scope(row['event'])
        threshold = detector.request_adapter.threshold(row['event']) if adapted else detector.threshold
        outputs.append({'request_id':row['event']['request_id'], 'app':row['app'], 'family':row['family'],
                        'truth':bool(row['truth']), 'score':float(score), 'threshold':threshold,
                        'prediction':bool(score >= threshold)})
    summaries = {}
    for app in sorted({r['app'] for r in rows}):
        indices = [i for i, r in enumerate(rows) if r['app']==app]
        for subgroup in ('all', 'request_content', 'ownership'):
            chosen = [i for i in indices if subgroup=='all' or
                      (rows[i]['family'].startswith('bola_') == (subgroup=='ownership'))]
            if not chosen: continue
            thresholds = {outputs[i]['threshold'] for i in chosen}
            if len(thresholds)!=1: raise ValueError('Expected one threshold per application')
            summaries[app+'/'+subgroup] = metrics([rows[i]['truth'] for i in chosen],
                                                 scores[chosen], thresholds.pop())
    return {'metrics':summaries, 'predictions':outputs}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--checkpoint', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--jevlet-repo', type=Path, default=Path('E:/clg/DL/mini_proj/jevlet'))
    args=parser.parse_args()
    if not torch.cuda.is_available(): raise RuntimeError('Adapter training requires CUDA')
    torch.set_num_threads(4); torch.manual_seed(42); np.random.seed(42)
    data=json.loads(args.data.read_text(encoding='utf-8')); parts=data['splits']
    # Audit attack-template separation and contradictory visible evidence before fitting.
    attack_keys={p:{request_text(r['event']) for r in rows if r['truth']}
                 for p,rows in parts.items()}
    for p in ('selection','calibration','test'):
        if attack_keys['train'] & attack_keys[p]: raise ValueError('Attack input overlaps fitting and '+p)
    if attack_keys['selection'] & attack_keys['test']: raise ValueError('Selection/test attack overlap')
    fitting_text={request_text(r['event']):bool(r['truth']) for r in parts['train']}
    for r in parts['train']:
        if fitting_text[request_text(r['event'])]!=bool(r['truth']): raise ValueError('Contradictory fitting labels')
    args.output.mkdir(parents=True, exist_ok=False)
    write_json(args.output/'protocol.json', {'seed':42,'architecture':'1536 -> 128 GELU dropout 0.1 -> 2',
      'optimizer':'CUDA AdamW lr 0.001 weight_decay 0.01; maximum 100 epochs, patience 12',
      'selection':'mean cross entropy with equal weight per application/class; no test-based selection',
      'calibration':'separate normal-only 5% FPR per application; thresholds saved before test scoring',
      'encoder':'frozen Jevlet, FP32 CUDA; original security/failure weights unchanged',
      'data_sha256':hashlib.sha256(args.data.read_bytes()).hexdigest(),
      'counts':{p:len(v) for p,v in parts.items()},'gpu':torch.cuda.get_device_name()})
    detector=LocalDetector.load(args.checkpoint,'jevlet',args.jevlet_repo,'cuda')
    for parameter in detector.model.parameters(): parameter.requires_grad_(False)
    began=time.perf_counter()
    features={p:encode_requests(detector.model,[r['event'] for r in parts[p]]).clone()
              for p in ('train','selection','calibration')}
    extraction_seconds=time.perf_counter()-began
    labels={p:torch.tensor([r['truth'] for r in parts[p]],dtype=torch.long,device='cuda') for p in features}
    weights={p:group_weights(parts[p]) for p in ('train','selection')}
    head=RequestHead(features['train'].shape[1]).cuda()
    head.centre.copy_(features['train'].mean(0)); head.scale.copy_(features['train'].std(0).clamp_min(.01))
    optimizer=torch.optim.AdamW(head.parameters(),lr=.001,weight_decay=.01)
    best=float('inf'); stale=0; history=[]; state=None; began=time.perf_counter()
    for epoch in range(100):
        head.train(); order=torch.randperm(len(features['train']),device='cuda')
        for indices in order.split(64):
            optimizer.zero_grad(set_to_none=True)
            losses=torch.nn.functional.cross_entropy(head(features['train'][indices]),labels['train'][indices],reduction='none')
            loss=(losses*weights['train'][indices]).sum()/weights['train'][indices].sum()
            loss.backward(); torch.nn.utils.clip_grad_norm_(head.parameters(),1); optimizer.step()
        head.eval()
        with torch.no_grad():
            losses=torch.nn.functional.cross_entropy(head(features['selection']),labels['selection'],reduction='none')
            val=float((losses*weights['selection']).sum()/weights['selection'].sum())
        if not np.isfinite(val): raise ValueError('Nonfinite selection loss')
        history.append({'epoch':epoch+1,'selection_balanced_log_loss':val})
        if val < best-1e-4:
            best=val; stale=0; state={k:v.detach().clone() for k,v in head.state_dict().items()}
        else: stale+=1
        if stale>=12: break
    torch.cuda.synchronize(); training_seconds=time.perf_counter()-began
    head.load_state_dict(state); head.eval()
    with torch.inference_mode(): cal=head(features['calibration']).softmax(-1)[:,1].cpu().numpy()
    scopes={}
    for app,prefixes in data['protocol']['scopes'].items():
        indices=[i for i,r in enumerate(parts['calibration']) if r['app']==app and not r['truth']]
        if len(indices)<64: raise ValueError('Need at least 64 calibration normals per application')
        scopes[app]={'prefixes':prefixes,'threshold':threshold_at_fpr(cal[indices],.05),'calibration_normals':len(indices)}
    candidate=args.output/'checkpoint'; shutil.copytree(args.checkpoint,candidate)
    config={'feature_size':1536,'hidden_size':128,'input_version':'request-evidence-v1',
            'encoder_sha256':hashlib.sha256((candidate/'jevlet/model.safetensors').read_bytes()).hexdigest(),
            'scopes':scopes,'training_device':'cuda','frozen_encoder':True,
            'limitations':'No requester/resource ownership evidence; known application path scopes only.'}
    save_file({k:v.detach().cpu().contiguous() for k,v in head.state_dict().items()},str(candidate/'request-head.safetensors'))
    write_json(candidate/'request-adapter.json',config)
    write_json(args.output/'training.json',{'history':history,'training_seconds':training_seconds,
               'extraction_seconds':extraction_seconds,'device':'cuda','selection_best_loss':best})
    # Head and thresholds are now fixed. First access to held-out model scores.
    candidate_detector=LocalDetector.load(candidate,'jevlet',args.jevlet_repo,'cuda')
    for label,model in [('baseline',detector),('adapted',candidate_detector)]:
        result=evaluate_records(model,parts['test'])
        write_json(args.output/(label+'-test.json'),result)
        print(label+': '+json.dumps(result['metrics']),flush=True)
    print('Saved independently reloadable candidate: '+str(candidate),flush=True)


if __name__=='__main__': main()
