"""Rule: block a configurable list of specific actions."""

from __future__ import annotations

from ..models import Finding, WorkflowModel
from .base import BaseRule, RuleInfo, Severity


class ForbiddenActionsRule(BaseRule):
    """Block a list of specific actions (e.g. outdated versions)."""

    info = RuleInfo(
        rule_id="forbidden_actions",
        description="Block a list of specific actions (e.g. outdated versions).",
        default_severity=Severity.ERROR,
        category="security",
    )

    def evaluate(self, workflow: WorkflowModel) -> list[Finding]:
        findings: list[Finding] = []
        forbidden: list[str] = self.config.params.get("items", [])
        if not forbidden:
            return findings

        for job in workflow.jobs:
            for step in job.steps:
                if step.uses and step.uses in forbidden:
                    msg = f"Action '{step.uses}' is forbidden by policy."
                    findings.append(self._make_finding(workflow, step.line, msg, step.uses))
        return findings
