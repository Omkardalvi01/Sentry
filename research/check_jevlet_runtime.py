"""Fail clearly before starting dependencies when Jevlet setup is incomplete."""
import os
from pathlib import Path

os.environ.setdefault('USE_TF', '0')
import torch
import transformers
import fastapi
import uvicorn
import sklearn

ROOT = Path(__file__).resolve().parents[1]
checkpoint = Path(os.environ.get('SENTRY_JEVLET_CHECKPOINT', str(ROOT/'.local-data/jevlet-models/bootstrap')))
repo = Path(os.environ.get('SENTRY_JEVLET_REPO', str(ROOT.parents[1]/'DL/mini_proj/jevlet')))
for name in ('jevlet/model.safetensors', 'jevlet/jevlet.json', 'baseline.pkl', 'models.json'):
    if not (checkpoint/name).is_file():
        raise SystemExit('Configure a trained SENTRY_JEVLET_CHECKPOINT; missing '+str(checkpoint/name))
if not (repo/'src/jevlet/model.py').is_file():
    raise SystemExit('Configure SENTRY_JEVLET_REPO to the local Jevlet source checkout')
device = os.environ.get('SENTRY_JEVLET_DEVICE', 'cuda')
if device.startswith('cuda') and not torch.cuda.is_available():
    raise SystemExit('CUDA unavailable: install CUDA PyTorch or explicitly configure SENTRY_JEVLET_DEVICE=cpu for inference')
print('Jevlet runtime ready: '+device+', checkpoint '+str(checkpoint))
