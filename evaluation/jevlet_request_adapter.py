"""Application adaptation on frozen Jevlet features; no ownership inference.

The original request and failure heads remain intact. A checkpoint can opt in
to a separately trained request head for explicit application path scopes.
"""
import hashlib
import json
import re

import torch
from torch import nn
from safetensors.torch import load_file

from local_models import questions


def request_text(event):
    """Use request evidence, excluding response outcomes, timing and identity.

This prevents local HTTP error codes and collection order from becoming label
shortcuts. UUIDs identify resources but do not establish their ownership.
"""
    path = re.sub(r'(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
                  '{uuid}', event.get('path') or '')
    return '\n'.join(('method: ' + (event.get('method') or ''),
                      'path: ' + path[:240],
                      'query: ' + (event.get('query_params') or '')[:480],
                      'request: ' + (event.get('request_body') or '')[:960]))


@torch.inference_mode()
def encode_requests(model, events, batch_size=16):
    from jevlet.data import collate, packed_items
    device = next(model.parameters()).device
    result = []
    for start in range(0, len(events), batch_size):
        items = packed_items(model.tokenizer,
                             [{'text': request_text(e), 'questions': questions()}
                              for e in events[start:start + batch_size]], model.max_length)
        batch = collate(items, model.tokenizer.pad_token_id)
        ids, attention = batch['input_ids'].to(device), batch['attention_mask'].to(device)
        hidden = model.encoder(input_ids=ids, attention_mask=attention).last_hidden_state.float()
        positions = torch.arange(ids.shape[1], device=device)[None, :]
        sep = torch.tensor([i['input_ids'].index(model.tokenizer.sep_token_id) for i in items], device=device)[:, None]
        mask = (positions > sep) & (positions < attention.sum(1)[:, None] - 1)
        mean = (hidden * mask[..., None]).sum(1) / mask.sum(1).clamp_min(1)[:, None]
        result.append(torch.cat((hidden[:, 0], mean), dim=1))
    return torch.cat(result)


class RequestHead(nn.Module):
    def __init__(self, size, hidden_size=128):
        super().__init__()
        self.register_buffer('centre', torch.zeros(size))
        self.register_buffer('scale', torch.ones(size))
        self.classifier = nn.Sequential(nn.Linear(size, hidden_size), nn.GELU(),
                                        nn.Dropout(0.1), nn.Linear(hidden_size, 2))

    def forward(self, features):
        return self.classifier((features.float() - self.centre) / self.scale)


class RequestAdapter:
    def __init__(self, model, head, config):
        self.model, self.head, self.config = model, head, config

    def scope(self, event):
        path = event.get('path') or ''
        for name, scope in self.config['scopes'].items():
            if any(path.startswith(prefix) for prefix in scope['prefixes']):
                return name
        return None

    def threshold(self, event):
        return self.config['scopes'][self.scope(event)]['threshold']

    @torch.inference_mode()
    def scores(self, events):
        return self.head(encode_requests(self.model, events)).softmax(-1)[:, 1].cpu().numpy()

    @classmethod
    def load(cls, directory, model):
        config = json.loads((directory / 'request-adapter.json').read_text(encoding='utf-8'))
        digest = hashlib.sha256((directory / 'jevlet/model.safetensors').read_bytes()).hexdigest()
        if config['encoder_sha256'] != digest:
            raise ValueError('Request adapter was trained with a different Jevlet encoder')
        if config['input_version'] != 'request-evidence-v1':
            raise ValueError('Unsupported request adapter input version')
        for scope in config['scopes'].values():
            if not scope['prefixes'] or any(not p.startswith('/') or p == '/' for p in scope['prefixes']):
                raise ValueError('Request adapter requires bounded application path prefixes')
            if not 0 <= scope['threshold'] <= 1:
                raise ValueError('Invalid request adapter threshold')
        device = next(model.parameters()).device
        head = RequestHead(config['feature_size'], config['hidden_size']).to(device)
        head.load_state_dict(load_file(str(directory / 'request-head.safetensors'), device=str(device)))
        return cls(model, head.eval(), config)
