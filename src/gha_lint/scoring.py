"""Compliance scoring: weighted deduction + A–F grade from lint findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import Finding, Severity

DEFAULT_WEIGHTS: dict[Severity, int] = {
    Severity.ERROR: 10,
    Severity.WARN: 3,
    Severity.INFO: 1,
}

DEFAULT_BASE_SCORE = 100


@dataclass
class ScoreResult:
    """Result of a compliance score calculation."""

    score: int
    total_deductions: int
    breakdown: dict[str, int] = field(default_factory=dict)
    per_file: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the score to a plain dict."""
        return {
            "score": self.score,
            "total_deductions": self.total_deductions,
            "breakdown": self.breakdown,
            "per_file": self.per_file,
        }

    def grade(self) -> str:
        """Map the numeric score to a letter grade A/B/C/D/F."""
        if self.score >= 90:
            return "A"
        if self.score >= 80:
            return "B"
        if self.score >= 70:
            return "C"
        if self.score >= 60:
            return "D"
        return "F"


def calculate_score(
    findings: list[Finding],
    base_score: int = DEFAULT_BASE_SCORE,
    weights: dict[Severity, int] | None = None,
    min_score: int = 0,
    max_score: int = 100,
) -> ScoreResult:
    """Compute a weighted 0-100 compliance score from a list of findings."""
    weights = weights or DEFAULT_WEIGHTS

    breakdown: dict[str, int] = {sev.value: 0 for sev in Severity}
    per_file: dict[str, int] = {}
    total_deductions = 0

    for f in findings:
        weight = weights.get(f.severity, 0)
        total_deductions += weight
        breakdown[f.severity.value] = breakdown.get(f.severity.value, 0) + weight
        per_file[f.file] = per_file.get(f.file, 0) + weight

    score = base_score - total_deductions
    score = max(min_score, min(max_score, score))

    return ScoreResult(
        score=score,
        total_deductions=total_deductions,
        breakdown=breakdown,
        per_file=per_file,
    )


def format_score(result: ScoreResult) -> str:
    """Render a :class:`ScoreResult` as a human-readable Rich-formatted string."""
    color = "green" if result.score >= 80 else "yellow" if result.score >= 60 else "red"
    lines = [
        f"[bold]Compliance Score:[/bold] [{color}]{result.score}/100 "
        f"(Grade: {result.grade()})[/{color}]",
        f"  Total deductions: {result.total_deductions}",
        "  Breakdown by severity:",
    ]
    for sev in sorted(Severity, key=lambda s: s.to_int(), reverse=True):
        count = result.breakdown.get(sev.value, 0)
        if count > 0:
            lines.append(f"    - {sev.value}: {count} pts")
    if result.per_file:
        lines.append("  Top files by deductions:")
        top_files = sorted(result.per_file.items(), key=lambda x: x[1], reverse=True)[:5]
        for fname, pts in top_files:
            lines.append(f"    - {fname}: {pts} pts")
    return "\n".join(lines)
