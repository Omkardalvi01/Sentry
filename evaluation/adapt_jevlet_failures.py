"""Compare a nonlinear CUDA failure head using whole-incident partitions."""
import argparse
import json
from pathlib import Path
import shutil
import time
import numpy as np
import torch
from safetensors.torch import save_file
from jevlet_failures import JevletWithFailures, FailureClassifier, encode_windows
from compare_local_models import metrics, write_json
from local_models import threshold_at_fpr


def weights(rows):
    groups=[(r['case'].split('_')[0],r['label']) for r in rows]
    counts={g:groups.count(g) for g in set(groups)}
    return torch.tensor([1/counts[g] for g in groups],device='cuda')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data',type=Path,required=True)
    parser.add_argument('--checkpoint',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--jevlet-repo',type=Path,default=Path('E:/clg/DL/mini_proj/jevlet'))
    args=parser.parse_args()
    if not torch.cuda.is_available(): raise RuntimeError('Failure adaptation requires CUDA')
    torch.set_num_threads(4); torch.manual_seed(42); np.random.seed(42)
    data=json.loads(args.data.read_text(encoding='utf-8')); parts=data['splits']
    cases={p:{r['case'] for r in rows} for p,rows in parts.items()}
    for first in cases:
        for second in cases:
            if first!=second and cases[first]&cases[second]: raise ValueError('Incident overlap')
    args.output.mkdir(parents=True,exist_ok=False)
    write_json(args.output/'protocol.json',{'architecture':'1536 -> 64 GELU dropout 0.1 -> 2',
       'seed':42,'training_device':'cuda','max_epochs':100,'patience':12,'learning_rate':.001,
       'selection':'Balanced log loss with equal weights per application/class; compare with current linear head before test scoring',
       'calibration':'Separate normal-only 5% FPR; whole incidents disjoint',
       'limits':'Previously inspected held-out incidents, not new independent data; windows within incidents correlated'})
    runtime=JevletWithFailures.load(args.checkpoint,args.jevlet_repo,'cuda')
    for parameter in runtime.security.model.parameters(): parameter.requires_grad_(False)
    features={p:encode_windows(runtime.security.model,[r['text'] for r in parts[p]]).clone()
              for p in ('train','selection','calibration')}
    labels={p:torch.tensor([r['label'] for r in parts[p]],dtype=torch.long,device='cuda') for p in features}
    w={p:weights(parts[p]) for p in ('train','selection')}
    def validation(head):
        with torch.no_grad():
            losses=torch.nn.functional.cross_entropy(head(features['selection']),labels['selection'],reduction='none')
            return float((losses*w['selection']).sum()/w['selection'].sum())
    old_loss=validation(runtime.failure_head)
    head=FailureClassifier(1536,64).cuda()
    head.centre.copy_(features['train'].mean(0)); head.scale.copy_(features['train'].std(0).clamp_min(.01))
    optimizer=torch.optim.AdamW(head.parameters(),lr=.001,weight_decay=.01)
    best=float('inf'); stale=0; history=[]; state=None; began=time.perf_counter()
    for epoch in range(100):
        head.train(); order=torch.randperm(len(features['train']),device='cuda')
        for selected in order.split(64):
            optimizer.zero_grad(set_to_none=True)
            losses=torch.nn.functional.cross_entropy(head(features['train'][selected]),labels['train'][selected],reduction='none')
            loss=(losses*w['train'][selected]).sum()/w['train'][selected].sum()
            loss.backward(); torch.nn.utils.clip_grad_norm_(head.parameters(),1); optimizer.step()
        head.eval(); val=validation(head)
        history.append({'epoch':epoch+1,'selection_balanced_log_loss':val})
        if val<best-1e-4:
            best=val; stale=0; state={k:v.detach().clone() for k,v in head.state_dict().items()}
        else: stale+=1
        if stale>=12: break
    head.load_state_dict(state); head.eval(); torch.cuda.synchronize()
    detail={'baseline_selection_loss':old_loss,'candidate_selection_loss':best,'history':history,
            'training_seconds':time.perf_counter()-began,'selected_by_validation':best<old_loss}
    with torch.inference_mode(): normal_scores=head(features['calibration']).softmax(-1)[:,1].cpu().numpy()
    threshold=threshold_at_fpr(normal_scores[labels['calibration'].cpu().numpy()==0],.05)
    candidate=args.output/'checkpoint'; shutil.copytree(args.checkpoint,candidate)
    save_file({k:v.detach().cpu().contiguous() for k,v in head.state_dict().items()},str(candidate/'failure-head.safetensors'))
    config=json.loads((candidate/'failure-model.json').read_text(encoding='utf-8'))
    config.update(hidden_size=64,threshold=threshold,architecture='nonlinear frozen-encoder head')
    write_json(candidate/'failure-model.json',config); write_json(args.output/'training.json',detail)
    # Candidate is fixed and reloadable before test scores are obtained.
    fresh=JevletWithFailures.load(candidate,args.jevlet_repo,'cuda')
    scores=fresh.failure_scores([r['text'] for r in parts['test']])
    quality={}
    for app in ['all']+sorted({r['case'].split('_')[0] for r in parts['test']}):
        indices=[i for i,r in enumerate(parts['test']) if app=='all' or r['case'].split('_')[0]==app]
        quality[app]=metrics([bool(parts['test'][i]['label']) for i in indices],scores[indices],threshold)
    write_json(args.output/'results.json',{'selection':detail,'metrics':quality})
    write_json(args.output/'predictions.json',[{'case':r['case'],'start':r['start'],'truth':r['label'],'score':float(s)} for r,s in zip(parts['test'],scores)])
    print(json.dumps({'selected_by_validation':best<old_loss,'old_selection_loss':old_loss,'new_selection_loss':best,'metrics':quality},indent=2),flush=True)


if __name__=='__main__': main()
