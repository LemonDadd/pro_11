"""Rule base classes, shared constants, and common regex patterns."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..models import Finding, Severity, WorkflowModel
from ..policy import Policy, RuleConfig

SHA_PATTERN: re.Pattern[str] = re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE)
VERSION_TAG_PATTERN: re.Pattern[str] = re.compile(
    r"^@v\d+(\.\d+)*(\-.*)?$|^@(main|master|develop)$"
)
CURL_BASH_PATTERN: re.Pattern[str] = re.compile(
    r"\bcurl\b.*\|\s*(?:bash|sh|zsh)\b", re.IGNORECASE
)
SECRET_REF_PATTERN: re.Pattern[str] = re.compile(
    r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}"
)
REUSABLE_WORKFLOW_PATTERN: re.Pattern[str] = re.compile(r"^([^@]+)@(.+)$")

WRITE_ALL_SCOPES: set[str] = {"write-all", "all"}


@dataclass(frozen=True)
class RuleInfo:
    """Metadata describing a lint rule."""

    rule_id: str
    description: str
    default_severity: Severity
    category: str


class BaseRule(ABC):
    """Abstract base class for all lint rules."""

    info: RuleInfo

    def __init__(self, config: RuleConfig, policy: Policy) -> None:
        self.config: RuleConfig = config
        self.policy: Policy = policy
        self.severity: Severity = config.severity or self.info.default_severity

    def enabled(self) -> bool:
        """Return whether this rule is enabled per policy configuration."""
        return self.config.enabled

    @abstractmethod
    def evaluate(self, workflow: WorkflowModel) -> list[Finding]:
        """Evaluate the rule against a parsed workflow and return findings."""
        ...

    def _make_finding(
        self,
        workflow: WorkflowModel,
        line: int,
        message: str,
        snippet: str | None = None,
    ) -> Finding:
        """Construct a Finding using this rule's metadata."""
        return Finding(
            file=workflow.file_path,
            line=line,
            rule_id=self.info.rule_id,
            severity=self.severity,
            message=message,
            snippet=snippet,
        )
