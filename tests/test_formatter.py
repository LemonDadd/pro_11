from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
import yaml

from gha_lint.formatter import Formatter, OutputFormat, ScanSummary
from gha_lint.models import Finding, Severity
from gha_lint.parser import WorkflowParser
from gha_lint.policy import Policy
from gha_lint.rules import RuleEngine


@pytest.fixture
def sample_findings() -> list[Finding]:
    return [
        Finding(
            file=".github/workflows/ci.yml",
            line=10,
            rule_id="actions_must_pin_sha",
            severity=Severity.ERROR,
            message="Action uses @v4",
            snippet="actions/checkout@v4",
        ),
        Finding(
            file=".github/workflows/ci.yml",
            line=20,
            rule_id="require_timeout_minutes",
            severity=Severity.WARN,
            message="Missing timeout",
        ),
        Finding(
            file=".github/workflows/deploy.yml",
            line=5,
            rule_id="require_concurrency",
            severity=Severity.INFO,
            message="No concurrency",
        ),
    ]


class TestScanSummary:
    def test_counts(self, sample_findings: list[Finding]):
        s = ScanSummary.from_findings(sample_findings)
        assert s.total == 3
        assert s.errors == 1
        assert s.warnings == 1
        assert s.infos == 1

    def test_should_fail_default(self, sample_findings: list[Finding]):
        s = ScanSummary.from_findings(sample_findings)
        assert s.should_fail(Severity.ERROR) is True

    def test_should_fail_on_warn(self, sample_findings: list[Finding]):
        s = ScanSummary.from_findings(sample_findings)
        assert s.should_fail(Severity.WARN) is True

    def test_no_errors_should_not_fail(self):
        s = ScanSummary(total=0, errors=0, warnings=0, infos=0)
        assert s.should_fail(Severity.ERROR) is False


class TestFormatterJSON:
    def test_format_json_structure(self, sample_findings: list[Finding]):
        output = Formatter.format(sample_findings, OutputFormat.JSON)
        data = json.loads(output)
        assert "findings" in data
        assert "summary" in data
        assert len(data["findings"]) == 3
        assert data["summary"]["total"] == 3

    def test_empty_json(self):
        output = Formatter.format([], OutputFormat.JSON)
        data = json.loads(output)
        assert data["findings"] == []
        assert data["summary"]["total"] == 0


class TestFormatterSARIF:
    def test_format_sarif_structure(self, sample_findings: list[Finding]):
        output = Formatter.format(sample_findings, OutputFormat.SARIF)
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "gha-lint"
        assert len(run["results"]) == 3
        assert len(run["tool"]["driver"]["rules"]) >= 7

    def test_sarif_result_severity_mapping(self, sample_findings: list[Finding]):
        output = Formatter.format(sample_findings, OutputFormat.SARIF)
        data = json.loads(output)
        levels = {r["level"] for r in data["runs"][0]["results"]}
        assert "error" in levels
        assert "warning" in levels
        assert "note" in levels


class TestFormatterGitHub:
    def test_format_github(self, sample_findings: list[Finding]):
        output = Formatter.format(sample_findings, OutputFormat.GITHUB)
        lines = output.strip().splitlines()
        assert len(lines) == 3
        assert all(
            line.startswith("::error") or line.startswith("::warning") for line in lines
        )
        assert "file=.github/workflows/ci.yml" in lines[0]
        assert "line=10" in lines[0]

    def test_empty_github(self):
        assert Formatter.format([], OutputFormat.GITHUB) == ""


class TestIntegrationWithEngine:
    def test_end_to_end_json(self):
        tmp = Path(tempfile.mkdtemp())
        wf_dir = tmp / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        content = {
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {"uses": "actions/checkout@v4"},
                        {"run": "curl https://example.com | bash"},
                    ],
                }
            }
        }
        (wf_dir / "ci.yml").write_text(yaml.dump(content))

        parser = WorkflowParser(tmp)
        workflows = list(parser.parse_all())
        policy = Policy.load()
        engine = RuleEngine(policy)
        findings = engine.evaluate_all(workflows)
        output = Formatter.format(findings, OutputFormat.JSON)
        data = json.loads(output)
        assert data["summary"]["total"] > 0
