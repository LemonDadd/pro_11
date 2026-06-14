"""Rule: forbid piping curl output into a shell interpreter."""

from __future__ import annotations

from ..models import Finding, WorkflowModel
from .base import CURL_BASH_PATTERN, BaseRule, RuleInfo, Severity


class ForbidCurlPipeBashRule(BaseRule):
    """Forbid piping curl output directly into bash/sh for security reasons."""

    info = RuleInfo(
        rule_id="forbid_curl_pipe_bash",
        description="Forbid piping curl output directly into bash/sh for security reasons.",
        default_severity=Severity.ERROR,
        category="security",
    )

    def evaluate(self, workflow: WorkflowModel) -> list[Finding]:
        findings: list[Finding] = []
        for job in workflow.jobs:
            for step in job.steps:
                if step.run and CURL_BASH_PATTERN.search(step.run):
                    msg = "Piping curl output into a shell interpreter is forbidden."
                    snippet = step.run.splitlines()[0] if step.run else None
                    findings.append(self._make_finding(workflow, step.line, msg, snippet))
        return findings
