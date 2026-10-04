"""
scoring.py — turns a list of IndicatorHits for one process into a
confidence level. Deliberately simple and fully transparent (sum of
documented weights, then thresholded) rather than any kind of opaque
scoring — the whole point of this project is that a person can see
exactly why a process was flagged, so the scoring has to be equally
inspectable.

This produces a CONFIDENCE LEVEL for further review, never a verdict.
Even "high" means "multiple documented indicators co-occurred, a human
should look at this", not "this is confirmed to be a keylogger".
"""
from __future__ import annotations
from dataclasses import dataclass

# Thresholds are on the SUM of hit weights (see each indicator's `weight`).
# Kept in one place, documented, and covered by tests — not tuned per
# scenario after the fact.
THRESHOLDS = {
    "high": 8,
    "medium": 4,
    "low": 1,
}


@dataclass
class ConfidenceResult:
    level: str          # "none" | "low" | "medium" | "high"
    score: int
    hit_count: int


def score_hits(hits: list) -> ConfidenceResult:
    total = sum(h.weight for h in hits)
    if total >= THRESHOLDS["high"]:
        level = "high"
    elif total >= THRESHOLDS["medium"]:
        level = "medium"
    elif total >= THRESHOLDS["low"]:
        level = "low"
    else:
        level = "none"
    return ConfidenceResult(level=level, score=total, hit_count=len(hits))
