"""Output formatters for gha-lint findings (table / json / sarif / github annotations)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from rich.console import Console
from rich.table import Table

from .models import Finding, Severity
from .rules import ALL_RULES


class OutputFormat(str, Enum):
    """Supported lint-report output formats."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"
    GITHUB = "github"


@dataclass
class ScanSummary:
    """Aggregate counts of findings grouped by severity."""

    total: int = 0
    errors: int = 0
    warnings: int = 0
    infos: int = 0

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> "ScanSummary":
        """Build a summary from a list of findings."""
        s = cls(total=len(findings))
        for f in findings:
            if f.severity == Severity.ERROR:
                s.errors += 1
            elif f.severity == Severity.WARN:
                s.warnings += 1
            elif f.severity == Severity.INFO:
                s.infos += 1
        return s

    def should_fail(self, fail_on: Severity = Severity.ERROR) -> bool:
        """Return True if the exit code should be non-zero given a severity threshold."""
        threshold = fail_on.to_int()
        for count, sev in [
            (self.errors, Severity.ERROR),
            (self.warnings, Severity.WARN),
            (self.infos, Severity.INFO),
        ]:
            if count > 0 and sev.to_int() >= threshold:
                return True
        return False


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    """Return findings sorted by file + line for deterministic reports."""
    return sorted(findings, key=lambda f: (f.file, f.line))


def format_table(findings: list[Finding], console: Console | None = None) -> str:
    """Render findings as a human-readable Rich table (prints to console)."""
    c = console or Console()
    if not findings:
        c.print("[green]✓ No issues found![/green]")
        return ""

    table = Table(title="gha-lint Findings", show_lines=False)
    table.add_column("File", style="cyan", overflow="fold")
    table.add_column("Line", justify="right", style="magenta")
    table.add_column("Severity", justify="center")
    table.add_column("Rule", style="yellow")
    table.add_column("Message", overflow="fold")

    severity_styles: dict[Severity, str] = {
        Severity.ERROR: "[bold red]ERROR[/bold red]",
        Severity.WARN: "[bold yellow]WARN[/bold yellow]",
        Severity.INFO: "[bold blue]INFO[/bold blue]",
    }

    findings_sorted = sorted(
        findings,
        key=lambda f: (f.severity.to_int(), f.file, f.line),
        reverse=True,
    )

    for f in findings_sorted:
        table.add_row(
            f.file,
            str(f.line),
            severity_styles.get(f.severity, f.severity.value),
            f.rule_id,
            f.message,
        )

    c.print(table)
    summary = ScanSummary.from_findings(findings)
    c.print(
        f"[bold]Summary:[/bold] "
        f"[red]{summary.errors} error(s)[/red], "
        f"[yellow]{summary.warnings} warning(s)[/yellow], "
        f"[blue]{summary.infos} info(s)[/blue]"
    )
    return ""


def format_json(findings: list[Finding]) -> str:
    """Render findings as a JSON report."""
    output: dict[str, Any] = {
        "findings": [f.to_dict() for f in _sort_findings(findings)],
        "summary": {
            "total": len(findings),
            "errors": sum(1 for f in findings if f.severity == Severity.ERROR),
            "warnings": sum(1 for f in findings if f.severity == Severity.WARN),
            "infos": sum(1 for f in findings if f.severity == Severity.INFO),
        },
    }
    return json.dumps(output, indent=2, ensure_ascii=False)


def format_sarif(findings: list[Finding]) -> str:
    """Render findings as a SARIF 2.1.0 report."""
    rules: list[dict[str, Any]] = []
    for rule_cls in ALL_RULES:
        info = rule_cls.info
        rules.append({
            "id": info.rule_id,
            "name": info.rule_id,
            "shortDescription": {"text": info.description},
            "fullDescription": {"text": info.description},
            "defaultConfiguration": {
                "level": Severity(info.default_severity.value).to_sarif_level()
            },
            "helpUri": "",
            "properties": {
                "category": info.category,
            },
        })

    results: list[dict[str, Any]] = []
    for f in _sort_findings(findings):
        result: dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": f.severity.to_sarif_level(),
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {"startLine": f.line},
                    }
                }
            ],
        }
        if f.column is not None:
            result["locations"][0]["physicalLocation"]["region"]["startColumn"] = f.column
        if f.snippet is not None:
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": f.snippet
            }
        results.append(result)

    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "gha-lint",
                        "version": "0.1.0",
                        "informationUri": "",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def format_github(findings: list[Finding]) -> str:
    """Render findings as GitHub Actions workflow-command annotations."""
    lines = [f.to_github_annotation() for f in _sort_findings(findings)]
    return "\n".join(lines)


class Formatter:
    """Public dispatcher for all supported output formats."""

    @staticmethod
    def format(
        findings: list[Finding],
        fmt: OutputFormat,
        console: Console | None = None,
    ) -> str:
        """Render ``findings`` according to ``fmt``, delegating to a strategy function."""
        if fmt == OutputFormat.TABLE:
            return format_table(findings, console)
        if fmt == OutputFormat.JSON:
            return format_json(findings)
        if fmt == OutputFormat.SARIF:
            return format_sarif(findings)
        if fmt == OutputFormat.GITHUB:
            return format_github(findings)
        raise ValueError(f"Unknown format: {fmt}")


def _severity_to_sarif(self: Severity) -> str:
    """Return the SARIF level string for a Severity value."""
    return {
        Severity.ERROR: "error",
        Severity.WARN: "warning",
        Severity.INFO: "note",
    }[self]


setattr(Severity, "to_sarif_level", _severity_to_sarif)
