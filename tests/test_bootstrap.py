"""
Toy-example tests for the moving-block bootstrap (bootstrap_ci.py, revision 3).
Run (from the repository root):  python -m pytest -q
"""
import numpy as np

from experiments.bootstrap_ci import block_starts, f1, interval, resampled_sums


def naive_sums(x, starts, block):
    """Build each resample explicitly: concatenate the blocks, truncate to len(x), sum."""
    out = []
    for row in starts:
        s = np.concatenate([x[i:i + block] for i in row])[:len(x)]
        out.append(s.sum())
    return np.array(out)


def test_resampled_sums_match_explicit_concatenation():
    rng = np.random.default_rng(1)
    x = rng.integers(0, 2, size=103)            # 103 is not a multiple of the block length
    for block in (1, 7, 10, 103):
        st = block_starts(np.random.default_rng(2), len(x), block, 50)
        assert st.shape == (50, -(-103 // block)) and st.min() >= 0 and st.max() <= 103 - block
        assert np.array_equal(resampled_sums(x, st, block), naive_sums(x, st, block))


def test_f1_from_sums_equals_2pr_over_p_plus_r():
    tp, pos, fp, ign = 503, 594, 0, 814       # behaviour / fixed, Friday DEV (results/scoring_check/results.md)
    p, r = tp / (tp + fp), tp / pos
    assert abs(float(f1(tp, pos, fp)) - 200 * p * r / (p + r)) < 1e-9
    ps = tp / (tp + fp + ign)
    assert abs(float(f1(tp, pos, fp, ign)) - 200 * ps * r / (ps + r)) < 1e-9
    assert float(f1(0, 0, 0)) == 0.0


def test_identical_configurations_give_a_zero_paired_difference():
    rng = np.random.default_rng(3)
    pos = (rng.random(500) < 0.2).astype(int)
    tp = pos * (rng.random(500) < 0.6)
    fp = (1 - pos) * (rng.random(500) < 0.05)
    st = block_starts(np.random.default_rng(4), 500, 25, 200)
    a = f1(resampled_sums(tp, st, 25), resampled_sums(pos, st, 25), resampled_sums(fp, st, 25))
    assert np.all(a - a == 0) and interval(a - a) == (0.0, 0.0)


def test_interval_covers_the_point_and_seed_is_deterministic():
    rng = np.random.default_rng(5)
    pos = np.zeros(2000, int)
    pos[500:900] = 1                             # one clustered "attack", as in the captures
    tp = pos * (rng.random(2000) < 0.7)
    fp = (1 - pos) * (rng.random(2000) < 0.01)
    point = float(f1(tp.sum(), pos.sum(), fp.sum()))
    runs = []
    for _ in range(2):
        st = block_starts(np.random.default_rng(20261026), 2000, 60, 500)
        runs.append(f1(resampled_sums(tp, st, 60), resampled_sums(pos, st, 60), resampled_sums(fp, st, 60)))
    assert np.array_equal(runs[0], runs[1])
    lo, hi = interval(runs[0])
    assert lo < point < hi and hi - lo < 20
