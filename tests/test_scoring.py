from keylog_audit.indicators.base import IndicatorHit
from keylog_audit.scoring import score_hits, THRESHOLDS


def hit(weight):
    return IndicatorHit(indicator_id="x", weight=weight, reason="r", evidence="e")


def test_no_hits_is_none_level():
    result = score_hits([])
    assert result.level == "none"
    assert result.score == 0
    assert result.hit_count == 0


def test_single_low_weight_hit_is_low():
    result = score_hits([hit(1)])
    assert result.level == "low"


def test_hits_summing_to_medium_threshold():
    result = score_hits([hit(THRESHOLDS["medium"])])
    assert result.level == "medium"


def test_hits_summing_to_high_threshold():
    result = score_hits([hit(THRESHOLDS["high"])])
    assert result.level == "high"


def test_hits_just_below_medium_threshold_stays_low():
    result = score_hits([hit(THRESHOLDS["medium"] - 1)])
    assert result.level == "low"


def test_multiple_hits_combine():
    result = score_hits([hit(2), hit(3)])
    assert result.score == 5
    assert result.hit_count == 2
    assert result.level == "medium"


def test_score_and_hit_count_independent():
    """Many weak hits can outscore one strong hit — the sum is what
    matters, not the count."""
    many_weak = score_hits([hit(1)] * 5)
    one_strong = score_hits([hit(4)])
    assert many_weak.score > one_strong.score
    assert many_weak.hit_count > one_strong.hit_count
