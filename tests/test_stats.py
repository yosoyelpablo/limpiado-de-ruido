"""Unit tests for hushwatch.analysis.stats (checked against brute force and closed forms)."""

from __future__ import annotations

import itertools
import math
import random

import pytest

from hushwatch.analysis import stats


def brute_cdf(x: int, mu: float, k: float) -> float:
    return math.fsum(stats.nb_pmf(i, mu, k) for i in range(x + 1))


def rel_err(a: float, b: float) -> float:
    return abs(a - b) / max(abs(b), 1e-300)


# ---- negative binomial pmf -----------------------------------------------------------------------------------


@pytest.mark.parametrize("mu,k", [(0.3, 0.5), (4.0, 1.0), (25.0, 3.0), (500.0, 20.0), (7.5, 1000.0)])
def test_nb_pmf_sums_to_one_and_has_right_moments(mu: float, k: float) -> None:
    upper = int(mu + 60 * math.sqrt(mu + mu * mu / k) + 50)
    probs = [stats.nb_pmf(i, mu, k) for i in range(upper)]
    assert math.fsum(probs) == pytest.approx(1.0, abs=1e-9)
    mean = math.fsum(i * p for i, p in enumerate(probs))
    var = math.fsum((i - mean) ** 2 * p for i, p in enumerate(probs))
    assert mean == pytest.approx(mu, rel=1e-7)
    assert var == pytest.approx(mu + mu * mu / k, rel=1e-6)


def test_nb_pmf_known_values() -> None:
    # k = 1 is geometric: P(X = x) = (1 - p) p^x with p = mu / (1 + mu)
    mu = 3.0
    p = mu / (1 + mu)
    for x in range(10):
        assert stats.nb_pmf(x, mu, 1.0) == pytest.approx((1 - p) * p**x, rel=1e-12)
    # zero mass
    assert stats.nb_pmf(0, 10.0, 2.0) == pytest.approx((1 + 10 / 2) ** -2, rel=1e-12)


def test_nb_edge_cases() -> None:
    assert stats.nb_logpmf(-1, 3.0, 2.0) == -math.inf
    assert stats.nb_logpmf(0, 0.0, 2.0) == 0.0
    assert stats.nb_logpmf(3, 0.0, 2.0) == -math.inf
    assert stats.nb_logcdf(-1, 3.0, 2.0) == -math.inf
    assert stats.nb_logcdf(0, 0.0, 2.0) == 0.0
    assert stats.nb_cdf(math.inf, 5.0, 2.0) == 1.0
    assert stats.nb_cdf(2.7, 5.0, 2.0) == pytest.approx(stats.nb_cdf(2, 5.0, 2.0))
    for bad_mu, bad_k in [(-1.0, 1.0), (math.nan, 1.0), (math.inf, 1.0), (1.0, 0.0), (1.0, -2.0), (1.0, math.nan)]:
        with pytest.raises(ValueError):
            stats.nb_logpmf(1, bad_mu, bad_k)
        with pytest.raises(ValueError):
            stats.nb_logcdf(1, bad_mu, bad_k)
    with pytest.raises(ValueError):
        stats.nb_logcdf(math.nan, 1.0, 1.0)


# ---- negative binomial lower tail ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "x,mu,k",
    [
        (0, 5.0, 0.5),
        (3, 10.0, 2.0),
        (30, 10.0, 2.0),
        (10, 100.0, 5.0),
        (5, 1000.0, 5.0),
        (1500, 2000.0, 20.0),
        (49, 50.0, 50.0),
        (2, 3.0, 1000.0),
        (4, 7.3, 3.3),
        (100, 1e5, 3.0),
        (5, 0.3, 0.7),
    ],
)
def test_nb_cdf_matches_brute_force(x: int, mu: float, k: float) -> None:
    assert rel_err(stats.nb_cdf(x, mu, k), brute_cdf(x, mu, k)) < 1e-9


def test_nb_cdf_matches_incomplete_beta_identity() -> None:
    rng = random.Random(7)
    for _ in range(200):
        mu = math.exp(rng.uniform(-2, 7))
        k = math.exp(rng.uniform(math.log(0.5), math.log(1000)))
        x = rng.randint(0, int(2 * mu) + 3)
        via_beta = stats.betainc_reg(k, x + 1.0, k / (k + mu))
        assert rel_err(stats.nb_cdf(x, mu, k), via_beta) < 1e-8


def test_nb_logcdf_tiny_tails_do_not_underflow() -> None:
    value = stats.nb_logcdf(10, 1e6, 1000.0)
    assert math.isfinite(value) and value < -5000
    # a deep but representable tail agrees with brute force in log space
    assert stats.nb_logcdf(5, 1000.0, 5.0) == pytest.approx(math.log(brute_cdf(5, 1000.0, 5.0)), rel=1e-10)
    # monotone in x
    prev = -math.inf
    for x in range(0, 200, 7):
        cur = stats.nb_logcdf(x, 150.0, 4.0)
        assert cur >= prev
        prev = cur


def test_nb_cdf_large_counts_are_fast_and_sane() -> None:
    assert stats.nb_logcdf(3_000_000, 1e7, 1000.0) < -100
    assert stats.nb_cdf(10_000_000, 1e7, 1000.0) == pytest.approx(0.5, abs=0.01)
    assert stats.nb_cdf(12_000_000, 1e7, 1000.0) > 0.99


def test_poisson_limit_as_size_grows() -> None:
    for x, mu in [(5, 10.0), (50, 10.0), (500, 400.0), (0, 3.0), (12, 12.0)]:
        target = stats.poisson_cdf(x, mu)
        errors = [rel_err(stats.nb_cdf(x, mu, k), target) for k in (1e2, 1e4, 1e6, 1e9, 1e12)]
        assert errors[-1] < 1e-9
        assert errors[-2] < 1e-6
        assert all(b <= a + 1e-12 for a, b in itertools.pairwise(errors))
        assert stats.nb_cdf(x, mu, math.inf) == pytest.approx(target, rel=1e-12)
    assert stats.nb_log_p0(7.0, math.inf) == -7.0
    assert stats.nb_log_p0(7.0, 1e12) == pytest.approx(-7.0, rel=1e-9)


def test_poisson_cdf_matches_brute_force() -> None:
    for x, mu in [(0, 0.5), (3, 2.5), (20, 10.0), (100, 150.0), (400, 400.0)]:
        brute = math.fsum(math.exp(stats.poisson_logpmf(i, mu)) for i in range(x + 1))
        assert rel_err(stats.poisson_cdf(x, mu), brute) < 1e-10
    assert stats.poisson_logcdf(-1, 3.0) == -math.inf
    assert stats.poisson_logcdf(4, 0.0) == 0.0
    with pytest.raises(ValueError):
        stats.poisson_logcdf(1, -1.0)


def test_gammaincc_known_values() -> None:
    # Q(1, x) = exp(-x); Q(a, 0) = 1
    for x in (0.1, 1.0, 5.0, 40.0):
        assert stats.gammaincc_reg_log(1.0, x) == pytest.approx(-x, rel=1e-12)
    assert stats.gammaincc_reg_log(3.0, 0.0) == 0.0
    with pytest.raises(ValueError):
        stats.gammaincc_reg_log(0.0, 1.0)


def test_betainc_known_values() -> None:
    # I_x(1, 1) = x ; I_x(a, 1) = x^a ; symmetry I_x(a, b) = 1 - I_{1-x}(b, a)
    for x in (0.05, 0.3, 0.8):
        assert stats.betainc_reg(1.0, 1.0, x) == pytest.approx(x, rel=1e-12)
        assert stats.betainc_reg(3.5, 1.0, x) == pytest.approx(x**3.5, rel=1e-10)
        assert stats.betainc_reg(2.0, 5.0, x) + stats.betainc_reg(5.0, 2.0, 1 - x) == pytest.approx(1.0, abs=1e-12)
    assert stats.betainc_reg_log(2.0, 3.0, 0.0) == -math.inf
    assert stats.betainc_reg_log(2.0, 3.0, 1.0) == 0.0
    with pytest.raises(ValueError):
        stats.betainc_reg_log(0.0, 1.0, 0.5)
    with pytest.raises(ValueError):
        stats.betainc_reg_log(1.0, 1.0, 1.5)


# ---- P0 over buckets -----------------------------------------------------------------------------------------


def test_p0_matches_product_of_bucket_zero_probabilities() -> None:
    mus = [0.2, 3.0, 11.0, 0.0, 7.5]
    k = 2.5
    expected = math.fsum(math.log(stats.nb_pmf(0, mu, k)) for mu in mus)
    assert stats.log_p0_buckets(mus, k) == pytest.approx(expected, rel=1e-12)
    # partial buckets: thinning keeps the size
    weights = [1.0, 0.25, 1.0, 1.0, 0.5]
    thinned = math.fsum(stats.nb_log_p0(mu * w, k) for mu, w in zip(mus, weights, strict=True))
    assert stats.log_p0_buckets(mus, k, weights) == pytest.approx(thinned, rel=1e-12)
    assert stats.log_p0_buckets([4.0, 5.0], math.inf) == pytest.approx(-9.0)
    assert stats.log_p0_buckets([], 3.0) == 0.0
    with pytest.raises(ValueError):
        stats.log_p0_buckets([1.0], 0.0)


def test_overdispersion_makes_silence_less_surprising() -> None:
    poisson = stats.log_p0_buckets([5.0] * 6, math.inf)
    for k in (100.0, 10.0, 1.0, 0.5):
        value = stats.log_p0_buckets([5.0] * 6, k)
        assert value > poisson
        poisson = value


def test_p0_monte_carlo_agreement() -> None:
    rng = random.Random(3)
    mu, k, trials = 2.0, 1.5, 40_000
    zeros = 0
    for _ in range(trials):
        lam = rng.gammavariate(k, mu / k)
        zeros += rng.random() < math.exp(-lam)
    assert zeros / trials == pytest.approx(stats.nb_p0(mu, k), abs=0.01)


# ---- dispersion, sizes, summaries ----------------------------------------------------------------------------


def test_mom_size_recovers_the_true_size() -> None:
    rng = random.Random(11)
    for true_k in (1.0, 5.0, 30.0):
        mus = [rng.uniform(5, 50) for _ in range(20_000)]
        counts = []
        for mu in mus:
            lam = rng.gammavariate(true_k, mu / true_k)
            # Poisson via inversion (lam is moderate here)
            x, p, s, u = 0, math.exp(-lam), math.exp(-lam), rng.random()
            while u > s:
                x += 1
                p *= lam / x
                s += p
            counts.append(float(x))
        est = stats.mom_size(mus, counts)
        assert est == pytest.approx(true_k, rel=0.15)


def test_mom_size_clipping() -> None:
    assert stats.mom_size([5.0, 5.0], [5.0, 5.0]) == stats.K_MAX  # no excess variance -> Poisson
    assert stats.mom_size([1.0, 1.0], [0.0, 60.0]) == stats.K_MIN  # absurdly bursty -> clipped
    assert stats.mom_size_from_sums(0.0, 5.0) == stats.K_MAX
    assert stats.mom_size_from_sums(10.0, 1.0, lo=0.5, hi=5.0) == 5.0
    with pytest.raises(ValueError):
        stats.mom_size([1.0], [1.0, 2.0])


def test_matched_and_combined_sizes() -> None:
    # sum of n iid NB(mu, k) has variance n(mu + mu^2/k): size n*k
    assert stats.matched_size([4.0] * 10, 2.0) == pytest.approx(20.0)
    assert stats.matched_size([0.0, 0.0], 2.0) == math.inf
    assert stats.combine_sizes(10.0, 10.0) == pytest.approx(5.0)
    assert stats.combine_sizes(math.inf, 4.0) == pytest.approx(4.0)
    assert stats.combine_sizes(math.inf) == math.inf
    with pytest.raises(ValueError):
        stats.combine_sizes(0.0)


def test_trimmed_mean_and_median() -> None:
    assert stats.trimmed_mean([1, 2, 3, 4, 100], 0.2) == pytest.approx(3.0)
    assert stats.trimmed_mean(range(1, 11), 0.1) == pytest.approx(5.5)
    values = [10.0] * 9 + [0.0]  # one outage day out of 10 is trimmed
    assert stats.trimmed_mean(values, 0.1) == pytest.approx(10.0)
    assert stats.trimmed_mean([7.0], 0.1) == 7.0
    assert stats.trimmed_mean([1.0, 9.0], 0.49) == 5.0
    with pytest.raises(ValueError):
        stats.trimmed_mean([], 0.1)
    with pytest.raises(ValueError):
        stats.trimmed_mean([1.0], 0.5)
    assert stats.median([3, 1, 2]) == 2.0
    assert stats.median([4, 1, 2, 3]) == 2.5
    with pytest.raises(ValueError):
        stats.median([])


def test_smooth_circular_preserves_total_and_wraps() -> None:
    values = [0.0] * 23 + [24.0]
    smoothed = stats.smooth_circular(values)
    assert math.fsum(smoothed) == pytest.approx(24.0)
    assert smoothed[0] == pytest.approx(6.0)  # wraps around midnight
    assert smoothed[22] == pytest.approx(6.0)
    assert smoothed[23] == pytest.approx(12.0)
    assert stats.smooth_circular([]) == []
    with pytest.raises(ValueError):
        stats.smooth_circular([1.0, 2.0], kernel=(0.5, 0.5))


def test_clip_and_logaddexp() -> None:
    assert stats.clip(math.nan, 0.5, 10.0) == 0.5
    assert stats.clip(20.0, 0.5, 10.0) == 10.0
    assert stats.logaddexp(math.log(2.0), math.log(3.0)) == pytest.approx(math.log(5.0))
    assert stats.logaddexp(-math.inf, 1.5) == 1.5
    assert stats.logaddexp(-1000.0, -1000.0) == pytest.approx(-1000.0 + math.log(2.0))


# ---- monitorability ------------------------------------------------------------------------------------------


def test_t_min_matches_poisson_closed_form() -> None:
    # at alpha = 5e-6 a 1/h source needs ~12 h, 0.2/h ~61 h (Poisson)
    assert stats.t_min_hours(1.0, math.inf, 5e-6) == pytest.approx(-math.log(5e-6), rel=1e-12)
    assert stats.t_min_hours(0.2, math.inf, 5e-6) == pytest.approx(61.0, abs=0.1)
    assert stats.t_min_hours(1.0, 2.0, 5e-6) > stats.t_min_hours(1.0, 1000.0, 5e-6)
    assert stats.t_min_hours(0.0, 3.0, 1e-3) == math.inf
    assert stats.t_min_hours(math.nan, 3.0, 1e-3) == math.inf
    assert stats.t_min_hours(math.inf, 3.0, 1e-3) == 0.0
    with pytest.raises(ValueError):
        stats.t_min_hours(1.0, 1.0, 0.0)


# ---- multiple testing ----------------------------------------------------------------------------------------


def test_benjamini_hochberg_against_reference() -> None:
    p = [0.01, 0.04, 0.03, 0.005, 0.5, math.nan]
    q = stats.benjamini_hochberg(p)
    # reference computed by hand: sorted 0.005,0.01,0.03,0.04,0.5,1 (m = 6)
    assert q == pytest.approx([0.03, 0.06, 0.06, 0.03, 0.6, 1.0])
    assert stats.bh_reject(p, 0.05) == [True, False, False, True, False, False]
    assert stats.benjamini_hochberg([]) == []
    assert all(0.0 <= v <= 1.0 for v in stats.benjamini_hochberg([0.0, 1.0, 2.0, -1.0]))


def test_bh_controls_fdr_under_the_null() -> None:
    rng = random.Random(5)
    false_discoveries = 0
    for _ in range(300):
        p = [rng.random() for _ in range(100)]
        false_discoveries += any(stats.bh_reject(p, 0.05))
    assert false_discoveries / 300 < 0.1
