"""Rule: enforce secret name naming convention (default: UPPER_SNAKE_CASE)."""

from __future__ import annotations

import re

from ..models import Finding, Job, WorkflowModel
from .base import SECRET_REF_PATTERN, BaseRule, RuleInfo, Severity


class SecretsNamingRule(BaseRule):
    """Enforce secret name naming convention (default: UPPER_SNAKE_CASE)."""

    info = RuleInfo(
        rule_id="secrets_naming",
        description="Enforce secret name naming convention (default: UPPER_SNAKE_CASE).",
        default_severity=Severity.WARN,
        category="style",
    )

    def evaluate(self, workflow: WorkflowModel) -> list[Finding]:
        findings: list[Finding] = []
        pattern = re.compile(self.policy.secrets_naming_pattern)

        for job in workflow.jobs:
            secret_names = self._extract_secrets(job)
            for name, line in secret_names:
                if not pattern.match(name):
                    msg = (
                        f"Secret name '{name}' does not match pattern "
                        f"'{self.policy.secrets_naming_pattern}'."
                    )
                    findings.append(self._make_finding(workflow, line, msg))
        return findings

    @staticmethod
    def _extract_secrets(job: Job) -> list[tuple[str, int]]:
        names: list[tuple[str, int]] = []

        if isinstance(job.secrets, dict):
            for k in job.secrets.keys():
                if isinstance(k, str):
                    names.append((k, job.line))

        if job.secrets == "inherit":
            pass

        for step in job.steps:
            if step.run:
                for m in SECRET_REF_PATTERN.finditer(step.run):
                    names.append((m.group(1), step.line))
            for v in step.with_.values():
                if isinstance(v, str):
                    for m in SECRET_REF_PATTERN.finditer(v):
                        names.append((m.group(1), step.line))

        return names
