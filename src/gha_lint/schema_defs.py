"""Shared definitions and constants used by GHA workflow schema validation."""

from __future__ import annotations

from dataclasses import dataclass

from .models import Severity

KNOWN_TOP_LEVEL_KEYS: frozenset[str] = frozenset({
    "name",
    "on",
    "jobs",
    "permissions",
    "concurrency",
    "env",
    "defaults",
    "run-name",
})

KNOWN_JOB_KEYS: frozenset[str] = frozenset({
    "name",
    "runs-on",
    "steps",
    "permissions",
    "timeout-minutes",
    "uses",
    "with",
    "secrets",
    "needs",
    "strategy",
    "if",
    "env",
    "defaults",
    "outputs",
    "environment",
    "concurrency",
    "continue-on-error",
    "container",
    "services",
})

KNOWN_STEP_KEYS: frozenset[str] = frozenset({
    "name",
    "id",
    "uses",
    "run",
    "with",
    "env",
    "if",
    "shell",
    "working-directory",
    "continue-on-error",
    "timeout-minutes",
    "permissions",
})

VALID_ON_EVENTS: frozenset[str] = frozenset({
    "push",
    "pull_request",
    "pull_request_target",
    "schedule",
    "workflow_dispatch",
    "workflow_run",
    "workflow_call",
    "create",
    "delete",
    "deployment",
    "deployment_status",
    "fork",
    "gollum",
    "issue_comment",
    "issues",
    "label",
    "milestone",
    "page_build",
    "project",
    "project_card",
    "project_column",
    "public",
    "registry_package",
    "release",
    "status",
    "watch",
    "check_run",
    "check_suite",
    "repository_dispatch",
    "merge_group",
})


@dataclass
class SchemaIssue:
    """A single structural issue detected during workflow schema validation."""

    rule_id: str
    message: str
    severity: Severity
    line: int = 1
