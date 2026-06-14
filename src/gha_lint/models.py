"""Core data models used throughout gha-lint (findings, severity, workflow AST)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Severity of a lint finding: ERROR (fatal) / WARN / INFO."""

    ERROR = "error"
    WARN = "warn"
    INFO = "info"

    def to_int(self) -> int:
        """Map severity to an integer for comparison/sorting (higher = more severe)."""
        return {"error": 2, "warn": 1, "info": 0}[self.value]


@dataclass
class Location:
    """A single source location: file path + line number + optional column."""

    file: str
    line: int
    column: int | None = None


@dataclass
class Finding:
    """A single lint finding reported by a rule."""

    file: str
    line: int
    rule_id: str
    severity: Severity
    message: str
    column: int | None = None
    snippet: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        result: dict[str, Any] = {
            "file": self.file,
            "line": self.line,
            "ruleId": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
        }
        if self.column is not None:
            result["column"] = self.column
        if self.snippet is not None:
            result["snippet"] = self.snippet
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Deserialize a dict previously produced by :meth:`to_dict`."""
        return cls(
            file=data["file"],
            line=data["line"],
            rule_id=data["ruleId"],
            severity=Severity(data["severity"]),
            message=data["message"],
            column=data.get("column"),
            snippet=data.get("snippet"),
        )

    def to_github_annotation(self) -> str:
        """Format as a GitHub Actions workflow command annotation."""
        severity = "error" if self.severity == Severity.ERROR else "warning"
        line_part = f"line={self.line}"
        file_part = f"file={self.file}"
        title_part = f"title={self.rule_id}"
        return f"::{severity} {file_part},{line_part},{title_part}::{self.message}"


@dataclass
class Step:
    """A single step inside a workflow job."""

    id: str | None = None
    name: str | None = None
    uses: str | None = None
    run: str | None = None
    with_: dict[str, Any] = field(default_factory=dict)
    permissions: Any = None
    line: int = 1
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Job:
    """A single job definition inside a workflow."""

    id: str
    name: str | None = None
    steps: list[Step] = field(default_factory=list)
    permissions: Any = None
    timeout_minutes: int | None = None
    uses_workflow: str | None = None
    with_: dict[str, Any] = field(default_factory=dict)
    secrets: Any = None
    needs: list[str] = field(default_factory=list)
    strategy: dict[str, Any] = field(default_factory=dict)
    runs_on: Any = None
    line: int = 1


@dataclass
class WorkflowModel:
    """An in-memory representation of a parsed GitHub Actions workflow file."""

    file_path: str
    name: str | None = None
    on: dict[str, Any] | list[str] = field(default_factory=dict)
    permissions: Any = None
    jobs: list[Job] = field(default_factory=list)
    concurrency: Any = None
    defaults: dict[str, Any] = field(default_factory=dict)
    env: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
