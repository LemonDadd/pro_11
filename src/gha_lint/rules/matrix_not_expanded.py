"""Rule: emit info finding when a job uses strategy.matrix (no expansion performed)."""

from __future__ import annotations

from ..models import Finding, WorkflowModel
from .base import BaseRule, RuleInfo, Severity


class MatrixExpandWarningRule(BaseRule):
    """Note that matrix jobs are not expanded by gha-lint."""

    info = RuleInfo(
        rule_id="matrix_not_expanded",
        description=(
            "Note that matrix jobs are not expanded by gha-lint; "
            "findings may only reflect the first matrix combination."
        ),
        default_severity=Severity.WARN,
        category="correctness",
    )

    def evaluate(self, workflow: WorkflowModel) -> list[Finding]:
        findings: list[Finding] = []
        for job in workflow.jobs:
            if job.strategy and "matrix" in job.strategy:
                msg = (
                    f"Job '{job.id}' uses strategy.matrix. "
                    "gha-lint does not expand matrices; rules run against the unexpanded definition."
                )
                findings.append(self._make_finding(workflow, job.line, msg))
        return findings
