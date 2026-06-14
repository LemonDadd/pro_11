"""Rule: require top-level and job-level permissions to be restrictive."""

from __future__ import annotations

from typing import Any

from ..models import Finding, WorkflowModel
from .base import WRITE_ALL_SCOPES, BaseRule, RuleInfo, Severity


class PermissionsDefaultReadRule(BaseRule):
    """Require top-level permissions to be restrictive (not write-all)."""

    info = RuleInfo(
        rule_id="permissions_default_read",
        description="Require top-level permissions to be restrictive (not write-all).",
        default_severity=Severity.WARN,
        category="security",
    )

    def evaluate(self, workflow: WorkflowModel) -> list[Finding]:
        findings: list[Finding] = []

        if workflow.permissions is None:
            msg = (
                "Missing top-level permissions. "
                "Set 'permissions: read-all' or scoped permissions for least privilege."
            )
            findings.append(self._make_finding(workflow, 1, msg))
        elif self._is_write_all(workflow.permissions):
            msg = (
                "Top-level permissions are too permissive (write-all). "
                "Use scoped permissions or read-all."
            )
            findings.append(self._make_finding(workflow, 1, msg))

        for job in workflow.jobs:
            if job.uses_workflow:
                continue
            if job.permissions is not None and self._is_write_all(job.permissions):
                msg = (
                    f"Job '{job.id}' permissions are too permissive (write-all). "
                    "Use scoped permissions."
                )
                findings.append(self._make_finding(workflow, job.line, msg))

        return findings

    @staticmethod
    def _is_write_all(permissions: Any) -> bool:
        if isinstance(permissions, str):
            return permissions.lower() in WRITE_ALL_SCOPES
        if isinstance(permissions, dict):
            return all(
                isinstance(v, str) and v.lower() == "write"
                for v in permissions.values()
            )
        return False
