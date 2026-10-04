"""
base.py — the shared shape every indicator returns. An indicator never
says "this is a keylogger" — it reports one specific, documented,
narrow fact about a process (its path, its startup registration, which
files it has open, etc.) with a weight and a plain-language reason.
Combining hits into an overall confidence is scoring.py's job, not any
individual indicator's.
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class IndicatorHit:
    indicator_id: str
    weight: int                # relative strength of this single signal — see scoring.py
    reason: str                  # plain-language, specific to THIS process
    evidence: str                  # the literal fact observed (a path, a registry value, an fd target)

    def to_dict(self) -> dict:
        return {
            "indicator_id": self.indicator_id, "weight": self.weight,
            "reason": self.reason, "evidence": self.evidence,
        }


INDICATOR_CATALOG = {}  # populated by each indicator module's register() call, for list-indicators


def register(indicator_id: str, description: str, platforms: tuple, needs_permission: str = None):
    INDICATOR_CATALOG[indicator_id] = {
        "description": description, "platforms": platforms, "needs_permission": needs_permission,
    }
