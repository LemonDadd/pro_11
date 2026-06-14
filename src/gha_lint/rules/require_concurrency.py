"""Rule: require concurrency configuration for deploy workflows."""

from __future__ import annotations

from ..models import Finding, WorkflowModel
from .base import BaseRule, RuleInfo, Severity


class RequireConcurrencyRule(BaseRule):
    """Require concurrency setting for production/deploy workflows."""

    info = RuleInfo(
        rule_id="require_concurrency",
        description="Require concurrency setting for production/deploy workflows.",
        default_severity=Severity.INFO,
        category="correctness",
    )

    def evaluate(self, workflow: WorkflowModel) -> list[Finding]:
        findings: list[Finding] = []
        if workflow.concurrency is None:
            msg = (
                "Workflow has no concurrency configuration. "
                "Consider adding concurrency to prevent overlapping runs for deploy workflows."
            )
            findings.append(self._make_finding(workflow, 1, msg))
        return findings
