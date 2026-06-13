from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml

from gha_lint.models import Severity
from gha_lint.parser import WorkflowParser
from gha_lint.policy import Policy
from gha_lint.rules import MatrixExpandWarningRule, RuleEngine, SchemaValidationRule


@pytest.fixture
def temp_repo_root() -> Path:
    tmp = Path(tempfile.mkdtemp())
    (tmp / ".github" / "workflows").mkdir(parents=True)
    return tmp


def _write_wf(root: Path, name: str, content: dict) -> Path:
    wf_dir = root / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    wf_path = wf_dir / name
    wf_path.write_text(yaml.dump(content), encoding="utf-8")
    return wf_path


class TestPathResolution:
    def test_repo_root_discovers_workflows(self, temp_repo_root: Path):
        _write_wf(temp_repo_root, "a.yml", {"on": ["push"], "jobs": {"b": {"runs-on": "u"}}})
        parser = WorkflowParser(temp_repo_root)
        files = parser.find_workflow_files()
        assert len(files) == 1
        assert files[0].name == "a.yml"

    def test_workflows_dir_directly(self, temp_repo_root: Path):
        _write_wf(temp_repo_root, "a.yml", {"on": ["push"], "jobs": {"b": {"runs-on": "u"}}})
        workflows_dir = temp_repo_root / ".github" / "workflows"
        parser = WorkflowParser(workflows_dir)
        files = parser.find_workflow_files()
        assert len(files) == 1
        assert files[0].name == "a.yml"

    def test_single_file(self, temp_repo_root: Path):
        wf_path = _write_wf(temp_repo_root, "a.yml", {"on": ["push"], "jobs": {"b": {"runs-on": "u"}}})
        parser = WorkflowParser(wf_path)
        files = parser.find_workflow_files()
        assert len(files) == 1
        assert files[0].name == "a.yml"

    def test_non_workflow_yaml_ignored_at_root(self, temp_repo_root: Path):
        (temp_repo_root / "policy.yaml").write_text("foo: bar", encoding="utf-8")
        _write_wf(temp_repo_root, "ci.yml", {"on": ["push"], "jobs": {"b": {"runs-on": "u"}}})
        parser = WorkflowParser(temp_repo_root)
        files = parser.find_workflow_files()
        assert len(files) == 1
        assert files[0].name == "ci.yml"


class TestSchemaValidation:
    @pytest.fixture
    def policy(self) -> Policy:
        return Policy.load()

    def test_valid_workflow_no_schema_errors(self, temp_repo_root: Path, policy: Policy):
        _write_wf(temp_repo_root, "valid.yml", {
            "name": "CI",
            "on": ["push"],
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"run": "echo hi"}],
                }
            },
        })
        wf = WorkflowParser(temp_repo_root).parse_file(
            temp_repo_root / ".github" / "workflows" / "valid.yml"
        )
        rule = SchemaValidationRule(policy.get_rule("schema_validation"), policy)
        findings = rule.evaluate(wf)
        schema_errors = [f for f in findings if f.severity == Severity.ERROR]
        assert len(schema_errors) == 0

    def test_missing_jobs_triggers_error(self, temp_repo_root: Path, policy: Policy):
        wf_path = temp_repo_root / ".github" / "workflows" / "bad.yml"
        wf_path.parent.mkdir(parents=True, exist_ok=True)
        wf_path.write_text("name: foo\non: push\n", encoding="utf-8")
        wf = WorkflowParser(temp_repo_root).parse_file(wf_path)
        rule = SchemaValidationRule(policy.get_rule("schema_validation"), policy)
        findings = rule.evaluate(wf)
        rule_ids = {f.rule_id for f in findings}
        assert "schema_missing_jobs" in rule_ids

    def test_missing_on_triggers_error(self, temp_repo_root: Path, policy: Policy):
        wf_path = temp_repo_root / ".github" / "workflows" / "bad.yml"
        wf_path.parent.mkdir(parents=True, exist_ok=True)
        wf_path.write_text("name: foo\njobs:\n  build:\n    runs-on: u\n", encoding="utf-8")
        wf = WorkflowParser(temp_repo_root).parse_file(wf_path)
        rule = SchemaValidationRule(policy.get_rule("schema_validation"), policy)
        findings = rule.evaluate(wf)
        rule_ids = {f.rule_id for f in findings}
        assert "schema_missing_on" in rule_ids

    def test_step_without_uses_or_run(self, temp_repo_root: Path, policy: Policy):
        _write_wf(temp_repo_root, "bad.yml", {
            "on": ["push"],
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"name": "bad step"}],
                }
            },
        })
        wf = list(WorkflowParser(temp_repo_root).parse_all())[0]
        rule = SchemaValidationRule(policy.get_rule("schema_validation"), policy)
        findings = rule.evaluate(wf)
        rule_ids = {f.rule_id for f in findings}
        assert "schema_step_missing_action" in rule_ids

    def test_reusable_workflow_with_steps(self, temp_repo_root: Path, policy: Policy):
        _write_wf(temp_repo_root, "bad.yml", {
            "on": ["push"],
            "jobs": {
                "call": {
                    "uses": "org/wf.yml@v1",
                    "steps": [{"run": "echo"}],
                }
            },
        })
        wf = list(WorkflowParser(temp_repo_root).parse_all())[0]
        rule = SchemaValidationRule(policy.get_rule("schema_validation"), policy)
        findings = rule.evaluate(wf)
        rule_ids = {f.rule_id for f in findings}
        assert "schema_job_reusable_with_steps" in rule_ids


class TestMatrixRule:
    def test_matrix_triggers_info(self, temp_repo_root: Path):
        _write_wf(temp_repo_root, "matrix.yml", {
            "on": ["push"],
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "strategy": {
                        "matrix": {
                            "version": ["3.9", "3.10"],
                        }
                    },
                    "steps": [{"run": "echo hi"}],
                }
            },
        })
        wf = list(WorkflowParser(temp_repo_root).parse_all())[0]
        policy = Policy.load()
        rule = MatrixExpandWarningRule(policy.get_rule("matrix_not_expanded"), policy)
        findings = rule.evaluate(wf)
        assert len(findings) == 1
        assert findings[0].rule_id == "matrix_not_expanded"
        assert "strategy.matrix" in findings[0].message

    def test_no_matrix_no_finding(self, temp_repo_root: Path):
        _write_wf(temp_repo_root, "plain.yml", {
            "on": ["push"],
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"run": "echo hi"}],
                }
            },
        })
        wf = list(WorkflowParser(temp_repo_root).parse_all())[0]
        policy = Policy.load()
        rule = MatrixExpandWarningRule(policy.get_rule("matrix_not_expanded"), policy)
        findings = rule.evaluate(wf)
        assert len(findings) == 0


class TestIntegrationWithNewRules:
    def test_engine_includes_new_rules(self, temp_repo_root: Path):
        _write_wf(temp_repo_root, "wf.yml", {
            "on": ["push"],
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "strategy": {"matrix": {"os": ["u", "m"]}},
                    "steps": [{"uses": "actions/checkout@v4"}],
                }
            },
        })
        policy = Policy.load()
        engine = RuleEngine(policy)
        workflows = list(WorkflowParser(temp_repo_root).parse_all())
        findings = engine.evaluate_all(workflows)
        rule_ids = {f.rule_id for f in findings}
        assert "actions_must_pin_sha" in rule_ids
        assert "matrix_not_expanded" in rule_ids
