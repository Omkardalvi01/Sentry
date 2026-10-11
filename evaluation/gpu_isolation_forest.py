"""Experimental axis-aligned Isolation Forest built and scored with PyTorch.

Implements random subsampling, random varying-feature/uniform-threshold splits,
depth-limited isolation trees, and the original expected-path-length score.
This is a separate implementation, not a GPU backend for sklearn's estimator.
"""

import math
from pathlib import Path

import numpy as np
import torch


def expected_path_length(counts):
    n = counts.to(torch.float32)
    approximation = 2 * ((n - 1).clamp_min(1).log() + 0.5772156649015329) - 2 * (n - 1) / n.clamp_min(1)
    return torch.where(n <= 1, 0., torch.where(n == 2, 1., approximation))


class TorchIsolationForest:
    def __init__(self, n_estimators=100, max_samples=256, seed=42, device='cuda'):
        self.n_estimators, self.max_samples, self.seed = n_estimators, max_samples, seed
        self.device = torch.device(device)
        if self.device.type == 'cuda' and not torch.cuda.is_available():
            raise RuntimeError('CUDA requested but unavailable; no silent CPU fallback')

    @torch.inference_mode()
    def fit(self, values):
        x = torch.as_tensor(values, dtype=torch.float32, device=self.device)
        if x.ndim != 2 or len(x) < 2 or not torch.isfinite(x).all():
            raise ValueError('Expected at least two finite feature rows')
        self.samples = min(self.max_samples, len(x))
        self.max_depth = math.ceil(math.log2(self.samples))
        self.n_features = x.shape[1]
        node_count = 2 ** (self.max_depth + 1) - 1
        generator = torch.Generator(device=self.device).manual_seed(self.seed)
        sampled = torch.stack([torch.randperm(len(x), generator=generator, device=self.device)[:self.samples]
                               for _ in range(self.n_estimators)])
        data = x[sampled]
        shape = (self.n_estimators, node_count)
        self.features = torch.full(shape, -1, dtype=torch.long, device=self.device)
        self.thresholds = torch.zeros(shape, device=self.device)
        self.leaf_sizes = torch.zeros(shape, dtype=torch.long, device=self.device)
        nodes = torch.zeros((self.n_estimators, self.samples), dtype=torch.long, device=self.device)
        active = torch.ones_like(nodes, dtype=torch.bool)
        for depth in range(self.max_depth + 1):
            counts = torch.zeros(shape, dtype=torch.long, device=self.device)
            counts.scatter_add_(1, nodes, active.long())
            populated = counts > 0
            self.leaf_sizes = torch.where(populated, counts, self.leaf_sizes)
            if depth == self.max_depth:
                break
            indices = nodes.unsqueeze(-1).expand(-1, -1, self.n_features)
            bounds_shape = (*shape, self.n_features)
            low = torch.full(bounds_shape, float('inf'), device=self.device)
            high = torch.full(bounds_shape, -float('inf'), device=self.device)
            low.scatter_reduce_(1, indices, data.masked_fill(~active.unsqueeze(-1), float('inf')),
                                reduce='amin', include_self=True)
            high.scatter_reduce_(1, indices, data.masked_fill(~active.unsqueeze(-1), -float('inf')),
                                 reduce='amax', include_self=True)
            valid = (high > low) & populated.unsqueeze(-1)
            # Argmax of independent uniform draws chooses a varying feature uniformly.
            draws = torch.rand(bounds_shape, generator=generator, device=self.device).masked_fill(~valid, -1)
            feature = draws.argmax(-1)
            can_split = (counts > 1) & valid.any(-1)
            minimum = low.gather(2, feature.unsqueeze(-1)).squeeze(-1)
            maximum = high.gather(2, feature.unsqueeze(-1)).squeeze(-1)
            minimum, maximum = (torch.where(can_split, value, 0) for value in (minimum, maximum))
            threshold = minimum + (maximum - minimum) * torch.rand(shape, generator=generator, device=self.device)
            # Rounding must not put the threshold on the maximum (empty right child).
            threshold = torch.minimum(threshold, torch.nextafter(maximum, minimum))
            self.features = torch.where(populated, torch.where(can_split, feature, -1), self.features)
            self.thresholds = torch.where(populated, threshold, self.thresholds)
            sample_split = can_split.gather(1, nodes) & active
            sample_feature = feature.gather(1, nodes)
            right = data.gather(2, sample_feature.unsqueeze(-1)).squeeze(-1) > threshold.gather(1, nodes)
            nodes = torch.where(sample_split, nodes * 2 + 1 + right.long(), nodes)
            active = sample_split
        self.training_device = str(self.device)
        return self

    @torch.inference_mode()
    def score_samples(self, values, batch_size=4096):
        x = torch.as_tensor(values, dtype=torch.float32, device=self.device)
        if x.ndim != 2 or x.shape[1] != self.n_features or not torch.isfinite(x).all():
            raise ValueError('Invalid feature matrix')
        result = []
        normalization = expected_path_length(torch.tensor(self.samples, device=self.device))
        for chunk in x.split(batch_size):
            nodes = torch.zeros((self.n_estimators, len(chunk)), dtype=torch.long, device=self.device)
            depths = torch.zeros_like(nodes, dtype=torch.float32)
            expanded = chunk.unsqueeze(0).expand(self.n_estimators, -1, -1)
            for _ in range(self.max_depth):
                feature = self.features.gather(1, nodes)
                split = feature >= 0
                value = expanded.gather(2, feature.clamp_min(0).unsqueeze(-1)).squeeze(-1)
                right = value > self.thresholds.gather(1, nodes)
                nodes = torch.where(split, nodes * 2 + 1 + right.long(), nodes)
                depths += split
            paths = depths + expected_path_length(self.leaf_sizes.gather(1, nodes))
            result.append(-torch.pow(2., -paths.mean(0) / normalization))
        return torch.cat(result).cpu().numpy() if result else np.empty(0)

    def to(self, device):
        self.device = torch.device(device)
        for name in ('features', 'thresholds', 'leaf_sizes'):
            setattr(self, name, getattr(self, name).to(self.device))
        return self

    def save(self, path):
        torch.save({'format': 1, 'n_estimators': self.n_estimators, 'max_samples': self.max_samples,
                    'seed': self.seed, 'samples': self.samples, 'max_depth': self.max_depth,
                    'n_features': self.n_features, 'training_device': self.training_device,
                    **{name: getattr(self, name).cpu() for name in ('features', 'thresholds', 'leaf_sizes')}}, Path(path))

    @classmethod
    def load(cls, path, device='cpu'):
        saved = torch.load(path, map_location='cpu', weights_only=True)
        if saved['format'] != 1:
            raise ValueError('Unsupported forest checkpoint')
        model = cls(saved['n_estimators'], saved['max_samples'], saved['seed'], device)
        for name in ('samples', 'max_depth', 'n_features', 'training_device', 'features', 'thresholds', 'leaf_sizes'):
            setattr(model, name, saved[name])
        return model.to(device)
