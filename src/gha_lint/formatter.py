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
    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"
    GITHUB = "github"


@dataclass
class ScanSummary:
    total: int = 0
    errors: int = 0
    warnings: int = 0
    infos: int = 0

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> "ScanSummary":
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
        threshold = fail_on.to_int()
        for f in [
            (self.errors, Severity.ERROR),
            (self.warnings, Severity.WARN),
            (self.infos, Severity.INFO),
        ]:
            count, sev = f
            if count > 0 and sev.to_int() >= threshold:
                return True
        return False


class Formatter:
    @staticmethod
    def format(findings: list[Finding], fmt: OutputFormat, console: Console | None = None) -> str:
        if fmt == OutputFormat.TABLE:
            return Formatter._format_table(findings, console)
        if fmt == OutputFormat.JSON:
            return Formatter._format_json(findings)
        if fmt == OutputFormat.SARIF:
            return Formatter._format_sarif(findings)
        if fmt == OutputFormat.GITHUB:
            return Formatter._format_github(findings)
        raise ValueError(f"Unknown format: {fmt}")

    @staticmethod
    def _format_table(findings: list[Finding], console: Console | None = None) -> str:
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

        severity_styles = {
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

    @staticmethod
    def _format_json(findings: list[Finding]) -> str:
        output: dict[str, Any] = {
            "findings": [f.to_dict() for f in sorted(findings, key=lambda x: (x.file, x.line))],
            "summary": {
                "total": len(findings),
                "errors": sum(1 for f in findings if f.severity == Severity.ERROR),
                "warnings": sum(1 for f in findings if f.severity == Severity.WARN),
                "infos": sum(1 for f in findings if f.severity == Severity.INFO),
            },
        }
        return json.dumps(output, indent=2, ensure_ascii=False)

    @staticmethod
    def _format_sarif(findings: list[Finding]) -> str:
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
        for f in sorted(findings, key=lambda x: (x.file, x.line)):
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

        sarif = {
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

    @staticmethod
    def _format_github(findings: list[Finding]) -> str:
        lines = []
        for f in sorted(findings, key=lambda x: (x.file, x.line)):
            lines.append(f.to_github_annotation())
        return "\n".join(lines)


def _severity_to_sarif(self: Severity) -> str:
    return {
        Severity.ERROR: "error",
        Severity.WARN: "warning",
        Severity.INFO: "note",
    }[self]


setattr(Severity, "to_sarif_level", _severity_to_sarif)
