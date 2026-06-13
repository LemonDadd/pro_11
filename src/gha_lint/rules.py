from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from .models import Finding, Job, Severity, WorkflowModel
from .policy import Policy, RuleConfig

SHA_PATTERN = re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE)
VERSION_TAG_PATTERN = re.compile(r"^@v\d+(\.\d+)*(\-.*)?$|^@(main|master|develop)$")
CURL_BASH_PATTERN = re.compile(r"\bcurl\b.*\|\s*(?:bash|sh|zsh)\b", re.IGNORECASE)
SECRET_REF_PATTERN = re.compile(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}")
REUSABLE_WORKFLOW_PATTERN = re.compile(r"^([^@]+)@(.+)$")

WRITE_ALL_SCOPES = {"write-all", "all"}


@dataclass
class RuleInfo:
    rule_id: str
    description: str
    default_severity: Severity
    category: str


class BaseRule(ABC):
    info: RuleInfo

    def __init__(self, config: RuleConfig, policy: Policy):
        self.config = config
        self.policy = policy
        self.severity = config.severity or self.info.default_severity

    def enabled(self) -> bool:
        return self.config.enabled

    @abstractmethod
    def evaluate(self, workflow: WorkflowModel) -> list[Finding]:
        ...

    def _make_finding(
        self,
        workflow: WorkflowModel,
        line: int,
        message: str,
        snippet: str | None = None,
    ) -> Finding:
        return Finding(
            file=workflow.file_path,
            line=line,
            rule_id=self.info.rule_id,
            severity=self.severity,
            message=message,
            snippet=snippet,
        )


class ActionsMustPinShaRule(BaseRule):
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


class ForbidCurlPipeBashRule(BaseRule):
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


class RequireTimeoutMinutesRule(BaseRule):
    info = RuleInfo(
        rule_id="require_timeout_minutes",
        description="Require timeout-minutes on jobs to prevent runaway workflows.",
        default_severity=Severity.WARN,
        category="cost",
    )

    def evaluate(self, workflow: WorkflowModel) -> list[Finding]:
        findings: list[Finding] = []
        default_timeout = self.policy.default_timeout_minutes
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


class PermissionsDefaultReadRule(BaseRule):
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


class SecretsNamingRule(BaseRule):
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


class ForbiddenActionsRule(BaseRule):
    info = RuleInfo(
        rule_id="forbidden_actions",
        description="Block a list of specific actions (e.g. outdated versions).",
        default_severity=Severity.ERROR,
        category="security",
    )

    def evaluate(self, workflow: WorkflowModel) -> list[Finding]:
        findings: list[Finding] = []
        forbidden = self.config.params.get("items", [])
        if not forbidden:
            return findings

        for job in workflow.jobs:
            for step in job.steps:
                if step.uses and step.uses in forbidden:
                    msg = f"Action '{step.uses}' is forbidden by policy."
                    findings.append(self._make_finding(workflow, step.line, msg, step.uses))
        return findings


class RequireConcurrencyRule(BaseRule):
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


class SchemaValidationRule(BaseRule):
    info = RuleInfo(
        rule_id="schema_validation",
        description="Validate workflow structure against GitHub Actions schema subset.",
        default_severity=Severity.ERROR,
        category="schema",
    )

    def evaluate(self, workflow: WorkflowModel) -> list[Finding]:
        from .schema import validate_workflow_schema

        if not workflow.raw:
            return []

        base_findings = validate_workflow_schema(workflow.file_path, workflow.raw)
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


class MatrixExpandWarningRule(BaseRule):
    info = RuleInfo(
        rule_id="matrix_not_expanded",
        description="Note that matrix jobs are not expanded by gha-lint; "
                    "findings may only reflect the first matrix combination.",
        default_severity=Severity.INFO,
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


ALL_RULES: list[type[BaseRule]] = [
    ActionsMustPinShaRule,
    ForbidCurlPipeBashRule,
    RequireTimeoutMinutesRule,
    PermissionsDefaultReadRule,
    SecretsNamingRule,
    ForbiddenActionsRule,
    RequireConcurrencyRule,
    SchemaValidationRule,
    MatrixExpandWarningRule,
]


def get_rule_by_id(rule_id: str) -> type[BaseRule] | None:
    for cls in ALL_RULES:
        if cls.info.rule_id == rule_id:
            return cls
    return None


def explain_rule(rule_id: str) -> str | None:
    cls = get_rule_by_id(rule_id)
    if cls is None:
        return None
    info = cls.info
    return (
        f"Rule: {info.rule_id}\n"
        f"Category: {info.category}\n"
        f"Default severity: {info.default_severity.value}\n"
        f"Description: {info.description}"
    )


class RuleEngine:
    def __init__(self, policy: Policy):
        self.policy = policy
        self.rules: list[BaseRule] = []
        for cls in ALL_RULES:
            cfg = policy.get_rule(cls.info.rule_id)
            rule = cls(cfg, policy)
            if rule.enabled():
                self.rules.append(rule)

    def evaluate(self, workflow: WorkflowModel) -> list[Finding]:
        all_findings: list[Finding] = []
        for rule in self.rules:
            all_findings.extend(rule.evaluate(workflow))
        return all_findings

    def evaluate_all(self, workflows: list[WorkflowModel]) -> list[Finding]:
        all_findings: list[Finding] = []
        for wf in workflows:
            all_findings.extend(self.evaluate(wf))
        return all_findings
