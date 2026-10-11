"""Check isolation-tree invariants, anomaly ranking, and checkpoint portability."""

import sys
from pathlib import Path

import numpy as np
import pytest
import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'evaluation'))
from gpu_isolation_forest import TorchIsolationForest, expected_path_length
from local_models import normal_baseline
from detector import fit_model

DEVICE = 'cuda' if torch.cuda.is_available() else 'cpu'


def test_constant_data_is_unsplittable_and_scores_half():
    forest = TorchIsolationForest(n_estimators=10, device=DEVICE).fit(np.ones((300, 4)))
    assert (forest.features[:, 0] == -1).all()
    assert (forest.leaf_sizes[:, 0] == 256).all()
    np.testing.assert_allclose(forest.score_samples(np.ones((3, 4))), -.5)


def test_extreme_points_rank_above_training_distribution():
    values = np.random.default_rng(42).normal(0, 1, (500, 3))
    forest = TorchIsolationForest(n_estimators=100, device=DEVICE).fit(values)
    assert np.mean(-forest.score_samples(np.full((8, 3), 20))) > np.mean(-forest.score_samples(values)) + .15
    assert np.isfinite(forest.score_samples(values)).all()
    assert forest.training_device.startswith(DEVICE)


def test_gpu_checkpoint_has_identical_cpu_predictions(tmp_path):
    values = np.random.default_rng(19).normal(size=(256, 5))
    forest = TorchIsolationForest(n_estimators=20, device=DEVICE).fit(values)
    expected = forest.score_samples(values)
    path = tmp_path / 'forest.pt'
    forest.save(path)
    loaded = TorchIsolationForest.load(path, 'cpu')
    np.testing.assert_allclose(loaded.score_samples(values), expected, atol=1e-6)


def test_path_normalization_and_invalid_inputs():
    result = expected_path_length(torch.tensor([0, 1, 2, 256])).tolist()
    assert result[:3] == [0, 0, 1]
    assert result[3] > 10
    with pytest.raises(ValueError):
        TorchIsolationForest(device=DEVICE).fit([[float('nan')]])


def test_preprocessing_matches_production_normal_profiles():
    from test_detector import events
    training, validation = events(128)[:96], events(128)[96:]
    reference = fit_model(training, validation, graph=False)
    baseline = normal_baseline(training)
    assert baseline.profiles == reference.profiles
    assert baseline.metadata['temporal_features'] == reference.metadata['temporal_features']
    assert baseline.ml_model is None
