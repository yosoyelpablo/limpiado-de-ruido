"""Pure statistics for the silence engine (stdlib only, no scipy).

* Negative binomial (NB) log-pmf and lower-tail CDF, numerically stable in log space. The CDF goes through the
  regularized incomplete beta function (``P(X <= x) = I_p(k, x + 1)``, ``p = k / (k + mu)``) so it is exact and
  fast for large counts, and tiny tails (1e-300 and below) are returned as logarithms instead of underflowing.
* Poisson log-pmf / lower tail (the ``k -> inf`` limit), via the regularized upper incomplete gamma function.
* Probability of zero events (``P0``) over hour buckets, the quantity behind SILENT, gaps and "rule went dark".
* Method-of-moments dispersion with clipping, moment-matched size of a sum, 10% trimmed mean, median.
* ``t_min``: hours of normal traffic needed before a silence becomes statistically detectable (monitorability).
* Benjamini-Hochberg q-values / rejections.

NB parameterization used everywhere: mean ``mu``, size ``k`` (a.k.a. ``r``), variance ``mu + mu**2 / k``.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence

__all__ = [
    "K_MAX",
    "K_MIN",
    "benjamini_hochberg",
    "betainc_reg",
    "betainc_reg_log",
    "bh_reject",
    "clip",
    "combine_sizes",
    "gammaincc_reg_log",
    "log_p0_buckets",
    "logaddexp",
    "matched_size",
    "median",
    "mom_size",
    "mom_size_from_sums",
    "nb_cdf",
    "nb_log_p0",
    "nb_logcdf",
    "nb_logpmf",
    "nb_p0",
    "nb_pmf",
    "poisson_cdf",
    "poisson_logcdf",
    "poisson_logpmf",
    "smooth_circular",
    "t_min_hours",
    "trimmed_mean",
]

K_MIN = 0.5  # most overdispersed size we accept (very bursty sources)
K_MAX = 1000.0  # practically Poisson

_EPS = 1e-15
_FPMIN = 1e-300
_LOG_TINY = math.log(5e-324)


def clip(value: float, lo: float, hi: float) -> float:
    """Clamp ``value`` into ``[lo, hi]`` (NaN becomes ``lo``)."""
    if not value >= lo:  # also catches NaN
        return lo
    return hi if value > hi else value


def logaddexp(a: float, b: float) -> float:
    """``log(exp(a) + exp(b))`` without overflow/underflow."""
    if a == -math.inf:
        return b
    if b == -math.inf:
        return a
    hi, lo = (a, b) if a >= b else (b, a)
    return hi + math.log1p(math.exp(lo - hi))


def _check_params(mu: float, k: float) -> None:
    if not (mu >= 0.0) or math.isinf(mu):  # rejects NaN and inf
        raise ValueError(f"mean must be finite and >= 0, got {mu!r}")
    if not (k > 0.0):  # rejects NaN, 0 and negatives (inf is the Poisson limit)
        raise ValueError(f"size must be > 0, got {k!r}")


def _log_rising(k: float, x: int) -> float:
    """``lgamma(k + x) - lgamma(k)``; exact summation for small ``x`` keeps precision when ``k >> x``."""
    if x <= 0:
        return 0.0
    if x <= 1000:
        return math.fsum(math.log(k + i) for i in range(x))
    return math.lgamma(k + x) - math.lgamma(k)


# ---- Poisson ---------------------------------------------------------------------------------------------------


def poisson_logpmf(x: int, mu: float) -> float:
    """``log P(X = x)`` for ``X ~ Poisson(mu)``."""
    if not (mu >= 0.0) or math.isinf(mu):
        raise ValueError(f"mean must be finite and >= 0, got {mu!r}")
    if x < 0:
        return -math.inf
    if mu == 0.0:
        return 0.0 if x == 0 else -math.inf
    return x * math.log(mu) - mu - math.lgamma(x + 1.0)


def poisson_logcdf(x: int, mu: float) -> float:
    """``log P(X <= x)`` for ``X ~ Poisson(mu)`` (= log Q(x + 1, mu), regularized upper incomplete gamma)."""
    if not (mu >= 0.0) or math.isinf(mu):
        raise ValueError(f"mean must be finite and >= 0, got {mu!r}")
    if x < 0:
        return -math.inf
    if mu == 0.0:
        return 0.0
    return gammaincc_reg_log(x + 1.0, mu)


def poisson_cdf(x: int, mu: float) -> float:
    """``P(X <= x)`` for ``X ~ Poisson(mu)``."""
    return math.exp(poisson_logcdf(x, mu))


def gammaincc_reg_log(a: float, x: float) -> float:
    """``log Q(a, x)``: log of the regularized upper incomplete gamma function (Numerical Recipes gser/gcf)."""
    if not (a > 0.0):
        raise ValueError(f"a must be > 0, got {a!r}")
    if not (x >= 0.0):
        raise ValueError(f"x must be >= 0, got {x!r}")
    if x == 0.0:
        return 0.0
    log_prefix = -x + a * math.log(x) - math.lgamma(a)
    max_iter = min(1_000_000, int(20.0 * math.sqrt(a + x)) + 500)
    if x < a + 1.0:
        # Series for the lower function P(a, x); Q = 1 - P.
        ap = a
        total = delta = 1.0 / a
        for _ in range(max_iter):
            ap += 1.0
            delta *= x / ap
            total += delta
            if abs(delta) < abs(total) * _EPS:
                break
        lower = math.exp(log_prefix + math.log(total))
        return math.log1p(-lower) if lower < 1.0 else _LOG_TINY
    # Continued fraction for Q(a, x) (modified Lentz).
    b = x + 1.0 - a
    c = 1.0 / _FPMIN
    d = 1.0 / b
    h = d
    for i in range(1, max_iter):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < _FPMIN:
            d = _FPMIN
        c = b + an / c
        if abs(c) < _FPMIN:
            c = _FPMIN
        d = 1.0 / d
        step = d * c
        h *= step
        if abs(step - 1.0) < _EPS:
            break
    return log_prefix + math.log(h)


# ---- incomplete beta -------------------------------------------------------------------------------------------


def _lbeta(a: float, b: float) -> float:
    """``log B(a, b)``; when one argument is a small integer the rising factorial is summed exactly, which avoids
    the catastrophic cancellation of ``lgamma(a) - lgamma(a + b)`` for huge ``a`` (NB size -> Poisson limit)."""
    if float(b).is_integer() and b <= 1000.0 and a > b:
        return math.lgamma(b) - _log_rising(a, int(b))
    if float(a).is_integer() and a <= 1000.0 and b > a:
        return math.lgamma(a) - _log_rising(b, int(a))
    return math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)


def _betacf(a: float, b: float, x: float) -> float:
    """Continued fraction for the incomplete beta function (modified Lentz, Numerical Recipes betacf)."""
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < _FPMIN:
        d = _FPMIN
    d = 1.0 / d
    h = d
    max_iter = min(300_000, int(20.0 * math.sqrt(max(a, b))) + 300)
    for m in range(1, max_iter + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < _FPMIN:
            d = _FPMIN
        c = 1.0 + aa / c
        if abs(c) < _FPMIN:
            c = _FPMIN
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < _FPMIN:
            d = _FPMIN
        c = 1.0 + aa / c
        if abs(c) < _FPMIN:
            c = _FPMIN
        d = 1.0 / d
        step = d * c
        h *= step
        if abs(step - 1.0) < _EPS:
            break
    return h


def betainc_reg_log(
    a: float,
    b: float,
    x: float,
    y: float | None = None,
    *,
    log_x: float | None = None,
    log_y: float | None = None,
) -> float:
    """``log I_x(a, b)``, the log regularized incomplete beta function.

    ``y`` (= ``1 - x``), ``log_x`` and ``log_y`` may be passed when the caller can compute them more precisely
    than this function could (e.g. ``log_x = -log1p(mu / k)`` for an NB with a huge size).
    """
    if not (a > 0.0 and b > 0.0):
        raise ValueError(f"a and b must be > 0, got {a!r}, {b!r}")
    if y is None:
        y = 1.0 - x
    if not (x >= 0.0 and y >= 0.0):
        raise ValueError(f"x must be in [0, 1], got {x!r}")
    if x <= 0.0:
        return -math.inf
    if y <= 0.0:
        return 0.0
    lx = math.log(x) if log_x is None else log_x
    ly = math.log(y) if log_y is None else log_y
    log_front = a * lx + b * ly - _lbeta(a, b)
    if x < (a + 1.0) / (a + b + 2.0):
        return log_front + math.log(_betacf(a, b, x)) - math.log(a)
    upper = math.exp(log_front + math.log(_betacf(b, a, y)) - math.log(b))  # I_y(b, a) = 1 - I_x(a, b)
    return math.log1p(-upper) if upper < 1.0 else _LOG_TINY


def betainc_reg(a: float, b: float, x: float) -> float:
    """``I_x(a, b)``, the regularized incomplete beta function."""
    return math.exp(betainc_reg_log(a, b, x))


# ---- negative binomial -----------------------------------------------------------------------------------------


def nb_logpmf(x: int, mu: float, k: float) -> float:
    """``log P(X = x)`` for ``X ~ NB(mean=mu, size=k)``; ``k = inf`` is the Poisson limit."""
    _check_params(mu, k)
    if x < 0:
        return -math.inf
    if mu == 0.0:
        return 0.0 if x == 0 else -math.inf
    if math.isinf(k):
        return poisson_logpmf(x, mu)
    return _log_rising(k, x) - math.lgamma(x + 1.0) - k * math.log1p(mu / k) + x * (math.log(mu) - math.log(k + mu))


def nb_pmf(x: int, mu: float, k: float) -> float:
    """``P(X = x)`` for ``X ~ NB(mu, k)``."""
    return math.exp(nb_logpmf(x, mu, k))


def nb_logcdf(x: int | float, mu: float, k: float) -> float:
    """``log P(X <= x)`` (lower tail, inclusive) for ``X ~ NB(mu, k)``. Non-integer ``x`` is floored."""
    _check_params(mu, k)
    if x != x:
        raise ValueError("x must not be NaN")
    if x < 0:
        return -math.inf
    if mu == 0.0 or math.isinf(x):
        return 0.0
    n = math.floor(x)
    if math.isinf(k):
        return poisson_logcdf(n, mu)
    summed = _nb_logcdf_by_summation(n, mu, k)
    if summed is not None:
        return summed
    total = k + mu
    return betainc_reg_log(
        k, n + 1.0, k / total, mu / total, log_x=-math.log1p(mu / k), log_y=math.log(mu) - math.log(total)
    )


_SUM_MAX_TERMS = 200_000


def _nb_logcdf_by_summation(n: int, mu: float, k: float) -> float | None:
    """Exact tail summation anchored at the pmf of ``n`` (no cancellation for any size, including ``k -> inf``).

    Below the mode the pmf decreases going left, so ``P(X <= n) = pmf(n) * sum_j r_j`` with ratios < 1. Above the
    mode the upper tail decreases going right, so ``P(X <= n) = 1 - pmf(n + 1) * sum_j s_j``. Returns ``None``
    when the tail is too wide to sum cheaply (the caller then uses the incomplete beta function).
    """
    q = mu / (k + mu)  # pmf(i + 1) / pmf(i) = (k + i) / (i + 1) * q
    mode = math.floor((k - 1.0) * mu / k) if k > 1.0 else 0
    if n <= mode:
        acc = 1.0
        term = 1.0
        for i in range(n, 0, -1):
            term *= i / ((k + i - 1.0) * q)
            acc += term
            if term < 1e-17 * acc:
                break
            if n - i > _SUM_MAX_TERMS:
                return None
        return nb_logpmf(n, mu, k) + math.log(acc)
    acc = 1.0
    term = 1.0
    i = n + 1
    while True:
        term *= (k + i) / (i + 1.0) * q
        acc += term
        if term < 1e-17 * acc:
            break
        i += 1
        if i - n > _SUM_MAX_TERMS:
            return None
    upper = math.exp(nb_logpmf(n + 1, mu, k) + math.log(acc))
    return math.log1p(-upper) if upper < 1.0 else _LOG_TINY


def nb_cdf(x: int | float, mu: float, k: float) -> float:
    """``P(X <= x)`` for ``X ~ NB(mu, k)``."""
    return math.exp(nb_logcdf(x, mu, k))


def nb_log_p0(mu: float, k: float) -> float:
    """``log P(X = 0) = -k log(1 + mu/k)`` (``-mu`` in the Poisson limit)."""
    _check_params(mu, k)
    if mu == 0.0:
        return 0.0
    if math.isinf(k):
        return -mu
    return -k * math.log1p(mu / k)


def nb_p0(mu: float, k: float) -> float:
    """``P(X = 0)`` for ``X ~ NB(mu, k)``."""
    return math.exp(nb_log_p0(mu, k))


def log_p0_buckets(mus: Iterable[float], k: float, weights: Iterable[float] | None = None) -> float:
    """``log P0 = sum_b -k log(1 + w_b mu_b / k)``: probability of zero events over independent NB buckets.

    ``weights`` (default 1) are the covered fraction of each bucket (partial first/last hour of a gap). Thinning a
    gamma-mixed Poisson bucket keeps the same size, so a fraction ``w`` of a bucket has ``P0 = (1 + w mu/k)^-k``.
    """
    if not (k > 0.0):
        raise ValueError(f"size must be > 0, got {k!r}")
    total = 0.0
    if weights is None:
        for mu in mus:
            if mu > 0.0:
                total += -mu if math.isinf(k) else -k * math.log1p(mu / k)
        return total
    for mu, w in zip(mus, weights, strict=True):
        eff = mu * w
        if eff > 0.0:
            total += -eff if math.isinf(k) else -k * math.log1p(eff / k)
    return total


def mom_size_from_sums(num: float, den: float, lo: float = K_MIN, hi: float = K_MAX) -> float:
    """Clip ``num / den`` into ``[lo, hi]``; a non-positive ``den`` (no excess variance) means Poisson (``hi``)."""
    if not (den > 0.0) or not (num > 0.0):
        return hi
    return clip(num / den, lo, hi)


def mom_size(mus: Sequence[float], counts: Sequence[float], lo: float = K_MIN, hi: float = K_MAX) -> float:
    """Method-of-moments NB size on residuals: ``k = sum(mu^2) / sum((c - mu)^2 - c)``, clipped to [lo, hi]."""
    if len(mus) != len(counts):
        raise ValueError("mus and counts must have the same length")
    num = math.fsum(m * m for m in mus)
    den = math.fsum((c - m) * (c - m) - c for m, c in zip(mus, counts, strict=True))
    return mom_size_from_sums(num, den, lo, hi)


def matched_size(mus: Iterable[float], k: float) -> float:
    """Size of the NB moment-matched to a sum of independent ``NB(mu_b, k)``: ``(sum mu)^2 / sum(mu^2 / k)``."""
    if not (k > 0.0):
        raise ValueError(f"size must be > 0, got {k!r}")
    s1 = 0.0
    s2 = 0.0
    for mu in mus:
        s1 += mu
        s2 += mu * mu
    if s2 <= 0.0 or math.isinf(k):
        return math.inf
    return s1 * s1 * k / s2


def combine_sizes(*sizes: float) -> float:
    """Combine independent multiplicative gamma effects: relative variances add, ``1/K = sum 1/k_i``."""
    inv = 0.0
    for size in sizes:
        if not (size > 0.0):
            raise ValueError(f"sizes must be > 0, got {size!r}")
        if not math.isinf(size):
            inv += 1.0 / size
    return math.inf if inv == 0.0 else 1.0 / inv


# ---- robust summaries ------------------------------------------------------------------------------------------


def trimmed_mean(values: Iterable[float], proportion: float = 0.1) -> float:
    """Mean after dropping ``floor(n * proportion)`` values from each end (``proportion`` in [0, 0.5))."""
    data = sorted(values)
    n = len(data)
    if n == 0:
        raise ValueError("trimmed_mean of an empty sequence")
    if not (0.0 <= proportion < 0.5):
        raise ValueError("proportion must be in [0, 0.5)")
    cut = int(n * proportion)
    if 2 * cut >= n:
        cut = (n - 1) // 2
    kept = data[cut : n - cut]
    return math.fsum(kept) / len(kept)


def median(values: Iterable[float]) -> float:
    """Median (average of the two middle values for even length)."""
    data = sorted(values)
    n = len(data)
    if n == 0:
        raise ValueError("median of an empty sequence")
    mid = n // 2
    return float(data[mid]) if n % 2 else (data[mid - 1] + data[mid]) / 2.0


def smooth_circular(values: Sequence[float], kernel: Sequence[float] = (0.25, 0.5, 0.25)) -> list[float]:
    """Circular convolution with an odd-length kernel (``±1 h`` smoothing of a daily/weekly profile)."""
    n = len(values)
    width = len(kernel)
    if width % 2 != 1:
        raise ValueError("kernel length must be odd")
    if n == 0:
        return []
    half = width // 2
    if width == 3:  # the common ±1 h case, without per-element generator overhead
        a, b, c = kernel
        return [a * values[i - 1] + b * values[i] + c * values[(i + 1) % n] for i in range(n)]
    return [math.fsum(kernel[j] * values[(i + j - half) % n] for j in range(width)) for i in range(n)]


# ---- monitorability --------------------------------------------------------------------------------------------


def t_min_hours(rate: float, k: float, alpha: float) -> float:
    """Hours of silence at a steady hourly ``rate`` needed before ``P0 < alpha`` (``inf`` for a zero rate).

    Poisson: ``-ln(alpha) / rate``; overdispersion (small ``k``) makes it longer.
    """
    if not (0.0 < alpha < 1.0):
        raise ValueError("alpha must be in (0, 1)")
    if not (rate > 0.0):  # zero, negative or NaN: silence is never detectable
        return math.inf
    if math.isinf(rate):
        return 0.0
    per_hour = -nb_log_p0(rate, k)
    if per_hour <= 0.0:
        return math.inf
    return -math.log(alpha) / per_hour


# ---- multiple testing ------------------------------------------------------------------------------------------


def benjamini_hochberg(pvalues: Sequence[float]) -> list[float]:
    """Benjamini-Hochberg adjusted p-values (q-values), in the input order. NaN p-values are treated as 1."""
    m = len(pvalues)
    if m == 0:
        return []
    cleaned = [p if p == p else 1.0 for p in pvalues]
    order = sorted(range(m), key=lambda i: cleaned[i])
    q = [1.0] * m
    running = 1.0
    for rank in range(m, 0, -1):
        idx = order[rank - 1]
        value = min(1.0, max(0.0, cleaned[idx]) * m / rank)
        running = min(running, value)
        q[idx] = running
    return q


def bh_reject(pvalues: Sequence[float], q: float) -> list[bool]:
    """Which hypotheses Benjamini-Hochberg rejects at false discovery rate ``q``."""
    return [value <= q for value in benjamini_hochberg(pvalues)]
