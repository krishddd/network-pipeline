"""Tests for core.seed — reproducibility seed plumbing."""

from __future__ import annotations

import os
import random


def test_seed_all_seeds_python_random():
    from network_pipeline.core.seed import current_seed, seed_all

    assert current_seed() is None
    seed_all(42)
    assert current_seed() == 42
    a = [random.random() for _ in range(5)]
    seed_all(42)
    b = [random.random() for _ in range(5)]
    assert a == b, "random.random() must be deterministic after seed_all"


def test_seed_all_sets_pythonhashseed_env():
    from network_pipeline.core.seed import seed_all

    seed_all(1234)
    assert os.environ["PYTHONHASHSEED"] == "1234"


def test_seed_all_none_is_noop():
    from network_pipeline.core.seed import current_seed, seed_all

    assert seed_all(None) is None
    assert current_seed() is None


def test_seed_all_rejects_non_int():
    import pytest

    from network_pipeline.core.seed import seed_all

    with pytest.raises(TypeError):
        seed_all("forty-two")  # type: ignore[arg-type]
