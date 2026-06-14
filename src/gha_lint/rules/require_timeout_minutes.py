"""Rule: require timeout-minutes on every job."""

from __future__ import annotations

from ..models import Finding, WorkflowModel
from .base import BaseRule, RuleInfo, Severity


class RequireTimeoutMinutesRule(BaseRule):
    """Require timeout-minutes on jobs to prevent runaway workflows."""

    info = RuleInfo(
        rule_id="require_timeout_minutes",
        description="Require timeout-minutes on jobs to prevent runaway workflows.",
        default_severity=Severity.WARN,
        category="cost",
    )

    def evaluate(self, workflow: WorkflowModel) -> list[Finding]:
        findings: list[Finding] = []
        default_timeout: int = self.policy.default_timeout_minutes
        for job in workflow.jobs:
            if job.uses_workflow:
                continue
            if job.timeout_minutes is None:
                msg = (
                    f"Job '{job.id}' is missing timeout-minutes. "
                    f"Recommended default: {default_timeout} minutes."
                )
                findings.append(self._make_finding(workflow, job.line, msg))
        return findings
