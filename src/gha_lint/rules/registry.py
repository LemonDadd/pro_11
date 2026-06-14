"""Rule registry, RuleEngine, and helper utilities (explain_rule, get_rule_by_id)."""

from __future__ import annotations

from ..models import Finding, WorkflowModel
from ..policy import Policy, RuleConfig
from .base import BaseRule, RuleInfo
from . import (
    actions_must_pin_sha,
    forbid_curl_pipe_bash,
    require_timeout_minutes,
    permissions_default_read,
    secrets_naming,
    forbidden_actions,
    require_concurrency,
    schema_validation,
    matrix_not_expanded,
)

ALL_RULES: list[type[BaseRule]] = [
    actions_must_pin_sha.ActionsMustPinShaRule,
    forbid_curl_pipe_bash.ForbidCurlPipeBashRule,
    require_timeout_minutes.RequireTimeoutMinutesRule,
    permissions_default_read.PermissionsDefaultReadRule,
    secrets_naming.SecretsNamingRule,
    forbidden_actions.ForbiddenActionsRule,
    require_concurrency.RequireConcurrencyRule,
    schema_validation.SchemaValidationRule,
    matrix_not_expanded.MatrixExpandWarningRule,
]


def get_rule_by_id(rule_id: str) -> type[BaseRule] | None:
    """Look up a rule class by its rule_id string."""
    for cls in ALL_RULES:
        if cls.info.rule_id == rule_id:
            return cls
    return None


def explain_rule(rule_id: str) -> str | None:
    """Return a human-readable description string for a rule, or None if unknown."""
    cls = get_rule_by_id(rule_id)
    if cls is None:
        return None
    info: RuleInfo = cls.info
    return (
        f"Rule: {info.rule_id}\n"
        f"Category: {info.category}\n"
        f"Default severity: {info.default_severity.value}\n"
        f"Description: {info.description}"
    )


class RuleEngine:
    """Evaluates all enabled rules against a set of parsed workflows."""

    def __init__(self, policy: Policy) -> None:
        self.policy: Policy = policy
        self.rules: list[BaseRule] = []
        for cls in ALL_RULES:
            cfg: RuleConfig = policy.get_rule(cls.info.rule_id)
            rule: BaseRule = cls(cfg, policy)
            if rule.enabled():
                self.rules.append(rule)

    def evaluate(self, workflow: WorkflowModel) -> list[Finding]:
        """Run every enabled rule against a single workflow."""
        all_findings: list[Finding] = []
        for rule in self.rules:
            all_findings.extend(rule.evaluate(workflow))
        return all_findings

    def evaluate_all(self, workflows: list[WorkflowModel]) -> list[Finding]:
        """Run every enabled rule against a collection of workflows."""
        all_findings: list[Finding] = []
        for wf in workflows:
            all_findings.extend(self.evaluate(wf))
        return all_findings
