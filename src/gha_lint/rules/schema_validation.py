"""Rule: validate workflow structure against GitHub Actions schema subset."""

from __future__ import annotations

from ..models import Finding, Severity, WorkflowModel
from .base import BaseRule, RuleInfo


class SchemaValidationRule(BaseRule):
    """Validate workflow structure against GitHub Actions schema subset."""

    info = RuleInfo(
        rule_id="schema_validation",
        description="Validate workflow structure against GitHub Actions schema subset.",
        default_severity=Severity.ERROR,
        category="schema",
    )

    def evaluate(self, workflow: WorkflowModel) -> list[Finding]:
        from ..schema import validate_workflow_schema

        if not workflow.raw:
            return []

        base_findings: list[Finding] = validate_workflow_schema(
            workflow.file_path, workflow.raw
        )
        results: list[Finding] = []
        for f in base_findings:
            f.severity = self._map_severity(f.severity)
            results.append(f)
        return results

    def _map_severity(self, original: Severity) -> Severity:
        base_level = self.severity.to_int()
        original_level = original.to_int()
        if original_level >= base_level:
            return original
        return self.severity
