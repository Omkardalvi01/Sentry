"""Check adaptation boundaries, evidence policy and checkpoint identity."""
import copy
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest
import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'evaluation'))
from jevlet_request_adapter import RequestAdapter, RequestHead, request_text
from local_models import LocalDetector


def test_adapter_cannot_use_status_timing_identity_or_review_labels():
    event={'method':'GET','path':'/identity/vehicle/11111111-2222-3333-4444-555555555555',
           'request_body':'','status_code':200,'response_body':'Alice','response_time_ms':10,
           'request_headers':{'Authorization':'secret'},'review_label':0}
    other=copy.deepcopy(event)
    other.update(path='/identity/vehicle/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
                 status_code=500,response_body='Bob',response_time_ms=900,review_label=1,
                 request_headers={'Authorization':'different'})
    assert request_text(event)==request_text(other)
    assert all(value not in request_text(event) for value in ('Alice','secret','11111111'))
    assert request_text(event)!=request_text(event | {'request_body':'<script>alert(1)</script>'})


def test_scoped_head_uses_its_threshold_and_preserves_original_fallback():
    model=SimpleNamespace(predict=lambda text,q:{'answers':[{'probabilities':[.8,.2]}]})
    baseline=SimpleNamespace(profiles={},metadata={'temporal_features':False})
    detector=LocalDetector('jevlet',model,baseline,.1)
    adapter=RequestAdapter(None,None,{'scopes':{'app':{'prefixes':['/community/'],'threshold':.8}}})
    adapter.scores=lambda events:np.array([.7]*len(events))
    detector.request_adapter=adapter
    event={'method':'GET','path':'/community/posts','status_code':200}
    assert not detector.predict(event)['behavioral_anomaly']
    assert detector.predict(event)['threshold']==.8
    assert detector.predict(event | {'path':'/other'})['behavioral_anomaly']
    assert detector.predict(event | {'path':'/other'})['threshold']==.1
    assert adapter.scope(event | {'path':'/communityevil/posts'}) is None
    assert np.allclose(detector.score([event,event | {'path':'/other'}]),[.7,.2])


def test_adapter_rejects_encoder_mismatch_before_loading_weights(tmp_path):
    (tmp_path/'jevlet').mkdir()
    (tmp_path/'jevlet/model.safetensors').write_bytes(b'encoder')
    (tmp_path/'request-adapter.json').write_text(json.dumps({'encoder_sha256':'wrong'}))
    with pytest.raises(ValueError,match='different Jevlet encoder'):
        RequestAdapter.load(tmp_path,None)


@pytest.mark.skipif(not torch.cuda.is_available(),reason='CUDA device transfer regression')
def test_device_transfer_allows_cpu_scoring_after_cuda_loading():
    encoder=torch.nn.Linear(12,12).cuda()
    head=RequestHead(12).cuda().eval()
    detector=LocalDetector('jevlet',encoder,None,.5)
    detector.request_adapter=SimpleNamespace(head=head)
    detector.to('cpu')
    # A stranded CUDA head fails on the CPU features produced by the encoder.
    assert head(encoder(torch.zeros(1,12))).shape==(1,2)
