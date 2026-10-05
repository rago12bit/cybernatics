"""CVSS 4.0 scoring for manual findings (plan §43.2: "severity from a CVSS 4.0 calculator, with the
vector stored alongside the score").

The arithmetic is the `cvss` library's (RedHatProductSecurity/cvss, LGPL-3.0), which implements
FIRST's CVSS v4.0 lookup tables; nothing here re-derives a score. The calculator screen asks the
API for every score rather than computing one in the browser, so there is exactly one
implementation whose answer becomes the severity.
"""

from __future__ import annotations

from dataclasses import dataclass

from cvss import CVSS4, CVSSError

from core.models import Severity
from core.scoring.severity import from_cvss

BASE_METRICS = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
MAX_VECTOR = 300


class CvssError(ValueError):
    """Not a CVSS 4.0 vector that can be scored; the message says why."""


@dataclass(frozen=True)
class Cvss4Score:
    vector: str  # normalized: metrics in the specification's order
    score: float
    rating: str  # FIRST's word: None, Low, Medium, High, Critical
    severity: Severity  # ours: a 0.0 score ("None") is Info

    def to_dict(self) -> dict[str, object]:
        return {"vector": self.vector, "score": self.score, "rating": self.rating,
                "severity": self.severity.value}  # fmt: skip


def score(vector: str) -> Cvss4Score:
    vector = (vector or "").strip()
    if len(vector) > MAX_VECTOR:
        raise CvssError("the vector is too long")
    try:
        c = CVSS4(vector)
        value = float(c.base_score)
        rating = str(c.severity)
        clean = str(c.clean_vector())
    except CVSSError as exc:
        raise CvssError(str(exc)) from None
    return Cvss4Score(clean, value, rating, from_cvss(value) if value > 0 else Severity.INFO)
