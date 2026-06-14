"""Rule: actions must be pinned to a full 40-char SHA."""

from __future__ import annotations

from ..models import Finding, WorkflowModel
from .base import SHA_PATTERN, BaseRule, RuleInfo, Severity


class ActionsMustPinShaRule(BaseRule):
    """Require actions to be pinned to a full 40-char SHA instead of tags or branches."""

    info = RuleInfo(
        rule_id="actions_must_pin_sha",
        description="Require actions to be pinned to a full 40-char SHA instead of tags or branches.",
        default_severity=Severity.ERROR,
        category="security",
    )

    def evaluate(self, workflow: WorkflowModel) -> list[Finding]:
        findings: list[Finding] = []
        for job in workflow.jobs:
            for step in job.steps:
                if step.uses and not self._is_allowed(step.uses):
                    ref = self._extract_ref(step.uses)
                    if ref and not SHA_PATTERN.match(ref):
                        msg = (
                            f"Action '{step.uses}' must be pinned to a full 40-char SHA, "
                            f"got '@{ref}'."
                        )
                        findings.append(self._make_finding(workflow, step.line, msg, step.uses))
            if job.uses_workflow and not self._is_allowed(job.uses_workflow):
                ref = self._extract_ref(job.uses_workflow)
                if ref and not SHA_PATTERN.match(ref):
                    msg = (
                        f"Reusable workflow '{job.uses_workflow}' must be pinned to a full "
                        f"40-char SHA, got '@{ref}'."
                    )
                    findings.append(self._make_finding(workflow, job.line, msg, job.uses_workflow))
        return findings

    def _is_allowed(self, uses: str) -> bool:
        action_name = uses.split("@")[0] if "@" in uses else uses
        return self.policy.is_action_allowed(action_name)

    @staticmethod
    def _extract_ref(uses: str) -> str | None:
        if "@" not in uses:
            return None
        return uses.rsplit("@", 1)[1]
