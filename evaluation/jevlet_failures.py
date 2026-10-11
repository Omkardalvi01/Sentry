"""A separate GPU-trained service-window classifier using Jevlet's encoder.

The existing request detector is frozen. Failure labels describe a telemetry
window exposed to an injected fault, not a malicious request or verified RCA.
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
from safetensors.torch import load_file, save_file
from torch import nn

from compare_local_models import metrics, write_json
from local_models import LocalDetector, threshold_at_fpr


def failure_question():
    return [{'id': 'service_health', 'type': 'choice',
             'text': 'Classify the operational state of this service telemetry window.',
             'options': ['normal', 'service failure']}]


@torch.inference_mode()
def encode_windows(model, texts, batch_size=16):
    from jevlet.data import collate, packed_items
    device = next(model.parameters()).device
    encoded = []
    for start in range(0, len(texts), batch_size):
        requests = [{'text': text, 'questions': failure_question()} for text in texts[start:start + batch_size]]
        items = packed_items(model.tokenizer, requests, model.max_length)
        batch = collate(items, model.tokenizer.pad_token_id)
        ids, attention = batch['input_ids'].to(device), batch['attention_mask'].to(device)
        hidden = model.encoder(input_ids=ids, attention_mask=attention).last_hidden_state
        position = torch.arange(ids.shape[1], device=device)[None, :]
        first_sep = torch.tensor([item['input_ids'].index(model.tokenizer.sep_token_id) for item in items], device=device)[:, None]
        context_mask = (position > first_sep) & (position < attention.sum(1)[:, None] - 1)
        context_mean = (hidden.float() * context_mask[..., None]).sum(1) / context_mask.sum(1).clamp_min(1)[:, None]
        encoded.append(torch.cat((hidden[:, 0].float(), context_mean), dim=1))
    return torch.cat(encoded) if encoded else torch.empty((0, model.encoder.config.hidden_size * 2), device=device)


class FailureClassifier(nn.Module):
    def __init__(self, size, hidden_size=0):
        super().__init__()
        self.register_buffer('centre', torch.zeros(size))
        self.register_buffer('scale', torch.ones(size))
        self.classifier = (nn.Sequential(nn.Linear(size, hidden_size), nn.GELU(),
                           nn.Dropout(0.1), nn.Linear(hidden_size, 2))
                           if hidden_size else nn.Linear(size, 2))

    def forward(self, features):
        return self.classifier((features.float() - self.centre) / self.scale)


class JevletWithFailures:
    """Both outputs available locally; telemetry input is supplied separately."""
    def __init__(self, security, failure_head, failure_threshold):
        self.security, self.failure_head, self.failure_threshold = security, failure_head, failure_threshold

    @classmethod
    def load(cls, directory, jevlet_repo, device='cuda', fp16=False):
        directory = Path(directory)
        spec = json.loads((directory / 'failure-model.json').read_text(encoding='utf-8'))
        security = LocalDetector.load(directory, 'jevlet', jevlet_repo, device)
        if fp16:
            if device != 'cuda':
                raise ValueError('This reduced-precision experiment requires CUDA')
            security.model.half()
        head = FailureClassifier(spec['feature_size'], spec.get('hidden_size', 0)).to(device)
        head.load_state_dict(load_file(str(directory / 'failure-head.safetensors'), device=device))
        return cls(security, head.eval(), spec['threshold'])

    @torch.inference_mode()
    def failure_scores(self, texts, batch_size=16):
        features = encode_windows(self.security.model, texts, batch_size)
        return self.failure_head(features).float().softmax(-1)[:, 1].cpu().numpy()

    def predict(self, event=None, telemetry_text=None):
        if event is None and telemetry_text is None:
            raise ValueError('Supply request evidence or a service telemetry window')
        result = {}
        if event is not None:
            result['request_anomaly'] = self.security.predict(event)
        if telemetry_text is not None:
            score = float(self.failure_scores([telemetry_text], 1)[0])
            result['service_failure'] = {'fault_condition': score >= self.failure_threshold,
                                         'score': score, 'threshold': self.failure_threshold,
                                         'label_scope': 'telemetry window; not a malicious-request label'}
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--security-checkpoint', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--jevlet-repo', type=Path, default=Path('E:/clg/DL/mini_proj/jevlet'))
    parser.add_argument('--seeds', nargs='+', type=int, default=[42, 43, 44])
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Choose a fresh output directory')
    if not torch.cuda.is_available():
        parser.error('GPU training required; no CPU fallback')
    torch.set_num_threads(4)
    sys.path.insert(0, str(args.jevlet_repo / 'src'))
    data = json.loads(args.data.read_text(encoding='utf-8'))
    if data['source'] != 'phamquiluan/RCAEval':
        raise ValueError('Expected reviewed RCAEval window data')
    partitions = list(data['splits'])
    case_sets = [set(data['case_partitions'][name]) for name in partitions]
    text_sets = [set(r['text'] for r in data['splits'][name]) for name in partitions]
    if any(case_sets[i] & case_sets[j] or text_sets[i] & text_sets[j]
           for i in range(len(partitions)) for j in range(i)):
        raise ValueError('Incident or evidence leakage between partitions')
    args.output.mkdir(parents=True)
    detector = LocalDetector.load(args.security_checkpoint, 'jevlet', args.jevlet_repo, 'cuda')
    encoder_before = hashlib.sha256((args.security_checkpoint / 'jevlet/model.safetensors').read_bytes()).hexdigest()
    detector.model.requires_grad_(False)
    detector.model.eval()
    began = time.perf_counter()
    # Clone outside inference_mode so these fixed features can be saved by
    # autograd while training the separate head.
    features = {name: encode_windows(detector.model, [r['text'] for r in group]).detach().clone()
                for name, group in data['splits'].items()}
    labels = {name: torch.tensor([r['label'] for r in group], device='cuda', dtype=torch.long)
              for name, group in data['splits'].items()}
    feature_seconds = time.perf_counter() - began
    print(f'Frozen Jevlet CUDA features prepared in {feature_seconds:.1f} seconds.', flush=True)
    results = []
    for seed in args.seeds:
        torch.manual_seed(seed)
        directory = args.output / f'seed-{seed}'
        directory.mkdir()
        size = features['train'].shape[1]
        head = FailureClassifier(size).cuda()
        head.centre.copy_(features['train'].mean(0))
        head.scale.copy_(features['train'].std(0).clamp_min(0.01))
        counts = torch.bincount(labels['train'], minlength=2)
        criterion = nn.CrossEntropyLoss(weight=(counts.sum() / (2 * counts)).float())
        optimizer = torch.optim.AdamW(head.parameters(), lr=0.001, weight_decay=0.01)
        best, stale, history, state = float('inf'), 0, [], None
        began = time.perf_counter()
        torch.cuda.reset_peak_memory_stats()
        for epoch in range(80):
            head.train()
            order = torch.randperm(len(features['train']), device='cuda')
            for selected in order.split(64):
                optimizer.zero_grad(set_to_none=True)
                loss = criterion(head(features['train'][selected]), labels['train'][selected])
                loss.backward()
                torch.nn.utils.clip_grad_norm_(head.parameters(), 1)
                optimizer.step()
            head.eval()
            with torch.inference_mode():
                losses = nn.functional.cross_entropy(head(features['selection']), labels['selection'], reduction='none')
                selection_loss = float(torch.stack([losses[labels['selection'] == c].mean() for c in (0, 1)]).mean())
            if not np.isfinite(selection_loss):
                raise ValueError('Non-finite validation loss')
            history.append({'epoch': epoch + 1, 'balanced_selection_log_loss': selection_loss})
            if selection_loss < best - 1e-4:
                best, stale = selection_loss, 0
                state = {k: v.detach().clone() for k, v in head.state_dict().items()}
            else:
                stale += 1
            if stale >= 10:
                break
        torch.cuda.synchronize()
        training_seconds = time.perf_counter() - began
        head.load_state_dict(state)
        head.eval()
        with torch.inference_mode():
            scores = {name: head(values).softmax(-1)[:, 1].cpu().numpy() for name, values in features.items()}
        threshold = threshold_at_fpr(scores['calibration'][labels['calibration'].cpu().numpy() == 0], 0.05)
        quality = metrics(labels['test'].cpu().numpy().astype(bool), scores['test'], threshold)
        result = {'seed': seed, 'metrics': quality, 'history': history, 'head_train_seconds': training_seconds,
                  'device': str(next(head.parameters()).device), 'frozen_encoder': True,
                  'peak_cuda_allocated_bytes': int(torch.cuda.max_memory_allocated())}
        results.append(result)
        save_file({k: v.detach().cpu().contiguous() for k, v in head.state_dict().items()}, str(directory / 'failure-head.safetensors'))
        shutil.copytree(args.security_checkpoint / 'jevlet', directory / 'jevlet')
        for name in ('baseline.pkl', 'models.json'):
            shutil.copy2(args.security_checkpoint / name, directory / name)
        if hashlib.sha256((directory / 'jevlet/model.safetensors').read_bytes()).hexdigest() != encoder_before:
            raise ValueError('Existing request checkpoint changed')
        write_json(directory / 'failure-model.json', {'feature_size': size, 'threshold': threshold,
                   'encoder_sha256': encoder_before, 'training_device': 'cuda', 'frozen_encoder': True,
                   'label_policy': data['label_policy'], 'feature_policy': 'frozen CLS and context mean; standardization fitted only on training windows'})
        write_json(directory / 'test-predictions.json', [{'case': record['case'], 'start': record['start'],
                   'truth': record['label'], 'score': float(score), 'prediction': bool(score >= threshold)}
                   for record, score in zip(data['splits']['test'], scores['test'])])
        reloaded = JevletWithFailures.load(directory, args.jevlet_repo)
        check = reloaded.failure_scores([r['text'] for r in data['splits']['test']])
        if not np.allclose(check, scores['test'], atol=1e-6, rtol=1e-5):
            raise ValueError('Saved failure-head reload differs from training predictions')
        # Evaluate reduced precision at the unchanged normal-calibration threshold.
        reloaded.security.model.half()
        half_scores = reloaded.failure_scores([r['text'] for r in data['splits']['test']])
        result['fp16_metrics'] = metrics(labels['test'].cpu().numpy().astype(bool), half_scores, threshold)
        result['fp16_changed_decisions'] = int(np.sum((check >= threshold) != (half_scores >= threshold)))
        durations = []
        for text in [r['text'] for r in data['splits']['test'][:32]]:
            torch.cuda.synchronize()
            started = time.perf_counter()
            reloaded.failure_scores([text], 1)
            torch.cuda.synchronize()
            durations.append((time.perf_counter() - started) * 1000)
        result['warm_fp16_gpu_p50_ms'] = float(np.median(durations))
        result['warm_fp16_gpu_p95_ms'] = float(np.percentile(durations, 95))
        del reloaded
        torch.cuda.empty_cache()
        write_json(args.output / 'results.json', results)
        print(f'Failure head seed {seed}: F1 {quality["f1"]:.3f}, recall {quality["recall"]:.1%}, false alarms {quality["false_positive_rate"]:.1%}; head CUDA training {training_seconds:.1f}s.', flush=True)
    if any(parameter.grad is not None for parameter in detector.model.parameters()):
        raise ValueError('Frozen request detector received gradients')
    write_json(args.output / 'manifest.json', {'source': data['source'], 'revision': data['revision'],
               'window_data_sha256': hashlib.sha256(args.data.read_bytes()).hexdigest(),
               'case_partitions': data['case_partitions'], 'window_counts': {k: len(v) for k, v in data['splits'].items()},
               'label_policy': data['label_policy'], 'encoder_sha256': encoder_before,
               'feature_extraction_device': 'cuda', 'feature_extraction_seconds': feature_seconds,
               'gpu': torch.cuda.get_device_name(), 'seeds': args.seeds})
    report = '# Jevlet service-failure extension\n\n'
    report += 'A separate linear failure classifier was trained on CUDA using frozen Jevlet text features. The existing request-anomaly weights and threshold are preserved byte-for-byte.\n\n'
    report += 'RCAEval RE3: 90 code-fault incidents from Online Boutique, Sock Shop and Train Ticket. Whole incidents remain in one partition, duplicate evidence is removed across partitions. The first 3 minutes of each incident provide an earlier normal telemetry baseline and are excluded from labelled examples. Injection transition windows are excluded.\n\n'
    report += data['label_policy'] + '\n\n'
    report += '| Head seed | Precision | Recall | F1 | False-alarm rate | Reduced-precision changed decisions | GPU FP16 median ms/window |\n|---|---:|---:|---:|---:|---:|---:|\n'
    for result in results:
        m = result['metrics']
        report += f'| {result["seed"]} | {m["precision"]:.1%} | {m["recall"]:.1%} | {m["f1"]:.3f} | {m["false_positive_rate"]:.1%} | {result["fp16_changed_decisions"]} | {result["warm_fp16_gpu_p50_ms"]:.2f} |\n'
    report += '\nThese failure metrics cannot be compared directly with the earlier FUR-API security metrics: the task and inputs differ. A fault exposure label does not prove every request in that window failed. Cases from the same application/configuration can occur in different splits; this is incident generalization, not an unseen-application test. Time-series windows within a case remain correlated.\n\n'
    report += 'A 60-second telemetry window must be supplied separately from an HTTP request. This local extension does not wire aggregation into Kafka or activate a model in the live detector. Timing excludes window collection time, queueing and loading. Reduced precision needs normal-data recalibration before adoption.\n\n'
    report += 'Sources: [RCAEval paper](https://arxiv.org/abs/2412.17015), [original dataset](https://zenodo.org/records/14590730), [author-maintained Parquet mirror](https://huggingface.co/datasets/phamquiluan/RCAEval).\n'
    (args.output / 'REPORT.md').write_text(report, encoding='utf-8')
    print('Results: ' + str(args.output / 'REPORT.md'), flush=True)


if __name__ == '__main__':
    main()
