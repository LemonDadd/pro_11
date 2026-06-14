from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml

from gha_lint.models import Severity
from gha_lint.parser import WorkflowParser
from gha_lint.policy import Policy
from gha_lint.rules import (
    ActionsMustPinShaRule,
    MatrixExpandWarningRule,
    RuleEngine,
    SchemaValidationRule,
)
from gha_lint.dependency import build_dependency_graph, cycle_findings_from_graph
from gha_lint.scoring import calculate_score


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

    def test_scan_merges_cycle_findings(self, temp_repo_root: Path):
        """End-to-end: scan must include reusable_cycle findings from dependency graph."""
        _write_wf(temp_repo_root, "a.yml", {
            "on": ["workflow_call", "push"],
            "jobs": {
                "call_b": {
                    "uses": "owner/repo/.github/workflows/b.yml@v1",
                }
            },
        })
        _write_wf(temp_repo_root, "b.yml", {
            "on": ["workflow_call"],
            "jobs": {
                "call_a": {
                    "uses": "./.github/workflows/a.yml@main",
                }
            },
        })
        workflows = list(WorkflowParser(temp_repo_root).parse_all())
        policy = Policy.load()
        engine = RuleEngine(policy)

        # Simulate scan flow: evaluate rules + add cycle findings
        findings = engine.evaluate_all(workflows)
        from gha_lint.dependency import build_dependency_graph, cycle_findings_from_graph
        graph = build_dependency_graph(workflows)
        findings.extend(cycle_findings_from_graph(graph))

        rule_ids = {f.rule_id for f in findings}
        assert "reusable_cycle" in rule_ids
        cycle_f = [f for f in findings if f.rule_id == "reusable_cycle"]
        assert len(cycle_f) == 1
        assert cycle_f[0].severity == Severity.ERROR
        # cycle findings should impact scoring and exit code logic
        from gha_lint.scoring import calculate_score
        score = calculate_score(findings)
        assert score.score < 100
        from gha_lint.formatter import ScanSummary
        summary = ScanSummary.from_findings(findings)
        assert summary.should_fail(Severity.ERROR) is True


class TestDependencyGraph:
    def test_simple_call(self, temp_repo_root: Path):
        _write_wf(temp_repo_root, "caller.yml", {
            "on": ["push"],
            "jobs": {
                "call": {
                    "uses": "org/repo/.github/workflows/build.yml@v1",
                }
            },
        })
        _write_wf(temp_repo_root, "build.yml", {
            "on": ["workflow_call"],
            "jobs": {"build": {"runs-on": "u", "steps": [{"run": "echo"}]}},
        })
        workflows = list(WorkflowParser(temp_repo_root).parse_all())
        graph = build_dependency_graph(workflows)
        assert len(graph.edges) == 1
        assert graph.edges[0].callee_ref == "org/repo/.github/workflows/build.yml@v1"
        assert graph.edges[0].caller_job == "call"

    def test_no_cycles_for_unrelated(self, temp_repo_root: Path):
        _write_wf(temp_repo_root, "a.yml", {
            "on": ["push"],
            "jobs": {"call": {"uses": "external/build.yml@v1"}},
        })
        _write_wf(temp_repo_root, "b.yml", {
            "on": ["workflow_call"],
            "jobs": {"build": {"runs-on": "u", "steps": [{"run": "echo"}]}},
        })
        workflows = list(WorkflowParser(temp_repo_root).parse_all())
        graph = build_dependency_graph(workflows)
        cycles = graph.detect_cycles()
        assert len(cycles) == 0

    def test_self_cycle_via_manual_graph(self):
        from gha_lint.dependency import DependencyGraph, WorkflowCallEdge

        graph = DependencyGraph()
        graph.workflows = {"wf_a": None}  # type: ignore
        graph.edges = [
            WorkflowCallEdge(
                caller_file="wf_a",
                callee_ref="wf_a",
                caller_job="call",
                line=5,
            )
        ]
        cycles = graph.detect_cycles()
        assert len(cycles) == 1
        assert cycles[0] == ["wf_a", "wf_a"]

    def test_two_node_cycle_via_manual_graph(self):
        from gha_lint.dependency import DependencyGraph, WorkflowCallEdge

        graph = DependencyGraph()
        graph.workflows = {"wf_a": None, "wf_b": None}  # type: ignore
        graph.edges = [
            WorkflowCallEdge(caller_file="wf_a", callee_ref="wf_b", caller_job="c1", line=1),
            WorkflowCallEdge(caller_file="wf_b", callee_ref="wf_a", caller_job="c2", line=2),
        ]
        cycles = graph.detect_cycles()
        assert len(cycles) == 1
        assert "wf_a" in cycles[0]
        assert "wf_b" in cycles[0]

    def test_cycle_findings(self):
        from gha_lint.dependency import DependencyGraph, WorkflowCallEdge

        graph = DependencyGraph()
        graph.workflows = {"wf_a": None, "wf_b": None}  # type: ignore
        graph.edges = [
            WorkflowCallEdge(caller_file="wf_a", callee_ref="wf_b", caller_job="c1", line=5),
            WorkflowCallEdge(caller_file="wf_b", callee_ref="wf_a", caller_job="c2", line=10),
        ]
        findings = cycle_findings_from_graph(graph)
        assert len(findings) >= 1
        assert findings[0].rule_id == "reusable_cycle"
        assert findings[0].severity == Severity.ERROR

    def test_to_mermaid(self, temp_repo_root: Path):
        _write_wf(temp_repo_root, "caller.yml", {
            "on": ["push"],
            "jobs": {"call": {"uses": "org/build.yml@v1"}},
        })
        workflows = list(WorkflowParser(temp_repo_root).parse_all())
        graph = build_dependency_graph(workflows)
        mermaid = graph.to_mermaid()
        assert "flowchart LR" in mermaid
        assert "-->" in mermaid

    def test_to_dict(self, temp_repo_root: Path):
        _write_wf(temp_repo_root, "a.yml", {
            "on": ["push"],
            "jobs": {"call": {"uses": "org/wf@v1"}},
        })
        workflows = list(WorkflowParser(temp_repo_root).parse_all())
        graph = build_dependency_graph(workflows)
        d = graph.to_dict()
        assert "workflows" in d
        assert "edges" in d
        assert "cycles" in d
        assert "roots" in d
        assert "leaves" in d

    def test_local_callee_resolution(self, temp_repo_root: Path):
        _write_wf(temp_repo_root, "caller.yml", {
            "on": ["push"],
            "jobs": {
                "call": {
                    "uses": "myorg/myrepo/.github/workflows/build.yml@v1",
                }
            },
        })
        _write_wf(temp_repo_root, "build.yml", {
            "on": ["workflow_call"],
            "jobs": {"build": {"runs-on": "u", "steps": [{"run": "echo"}]}},
        })
        workflows = list(WorkflowParser(temp_repo_root).parse_all())
        graph = build_dependency_graph(workflows)
        assert len(graph.edges) == 1
        edge = graph.edges[0]
        assert edge.callee_ref == "myorg/myrepo/.github/workflows/build.yml@v1"
        assert edge.callee_file is not None
        assert edge.callee_file.endswith("build.yml")
        assert Path(edge.callee_file).name == "build.yml"

    def test_local_relative_callee_resolution(self, temp_repo_root: Path):
        _write_wf(temp_repo_root, "caller.yml", {
            "on": ["push"],
            "jobs": {
                "call": {
                    "uses": "./.github/workflows/build.yml@main",
                }
            },
        })
        _write_wf(temp_repo_root, "build.yml", {
            "on": ["workflow_call"],
            "jobs": {"build": {"runs-on": "u", "steps": [{"run": "echo"}]}},
        })
        workflows = list(WorkflowParser(temp_repo_root).parse_all())
        graph = build_dependency_graph(workflows)
        edge = graph.edges[0]
        assert edge.callee_file is not None
        assert Path(edge.callee_file).name == "build.yml"

    def test_two_node_local_cycle_detected(self, temp_repo_root: Path):
        _write_wf(temp_repo_root, "a.yml", {
            "on": ["workflow_call", "push"],
            "jobs": {
                "call_b": {
                    "uses": "owner/repo/.github/workflows/b.yml@v1",
                }
            },
        })
        _write_wf(temp_repo_root, "b.yml", {
            "on": ["workflow_call"],
            "jobs": {
                "call_a": {
                    "uses": "./.github/workflows/a.yml@main",
                }
            },
        })
        workflows = list(WorkflowParser(temp_repo_root).parse_all())
        assert len(workflows) == 2
        graph = build_dependency_graph(workflows)
        cycles = graph.detect_cycles()
        assert len(cycles) == 1, f"Expected 1 cycle, got {len(cycles)}: {cycles}"
        cycle = cycles[0]
        assert "a.yml" in cycle[0] or "a.yml" in cycle[1]
        assert "b.yml" in cycle[0] or "b.yml" in cycle[1]

        # cycle findings should also work
        findings = cycle_findings_from_graph(graph)
        assert len(findings) == 1
        assert findings[0].rule_id == "reusable_cycle"
        assert findings[0].severity == Severity.ERROR
        assert "a.yml" in findings[0].message and "b.yml" in findings[0].message


class TestAllowlist:
    def test_allowed_org_skips_pin_check(self, temp_repo_root: Path):
        _write_wf(temp_repo_root, "wf.yml", {
            "on": ["push"],
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"uses": "myorg/internal-action@v2"}],
                }
            },
        })
        policy = Policy.load()
        policy.allowed_orgs = ["myorg"]
        wf = list(WorkflowParser(temp_repo_root).parse_all())[0]
        rule = ActionsMustPinShaRule(policy.get_rule("actions_must_pin_sha"), policy)
        findings = rule.evaluate(wf)
        assert len(findings) == 0

    def test_allowed_action_skips_pin_check(self, temp_repo_root: Path):
        _write_wf(temp_repo_root, "wf.yml", {
            "on": ["push"],
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"uses": "myorg/special-action@main"}],
                }
            },
        })
        policy = Policy.load()
        policy.allowed_actions = ["myorg/special-action"]
        wf = list(WorkflowParser(temp_repo_root).parse_all())[0]
        rule = ActionsMustPinShaRule(policy.get_rule("actions_must_pin_sha"), policy)
        findings = rule.evaluate(wf)
        assert len(findings) == 0

    def test_unrelated_action_still_flagged(self, temp_repo_root: Path):
        _write_wf(temp_repo_root, "wf.yml", {
            "on": ["push"],
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"uses": "otherorg/action@v1"}],
                }
            },
        })
        policy = Policy.load()
        policy.allowed_orgs = ["myorg"]
        wf = list(WorkflowParser(temp_repo_root).parse_all())[0]
        rule = ActionsMustPinShaRule(policy.get_rule("actions_must_pin_sha"), policy)
        findings = rule.evaluate(wf)
        assert len(findings) == 1

    def test_policy_loads_allowlist_from_yaml(self):
        yaml_content = """
rules:
  actions_must_pin_sha: error
allowed_actions:
  - myorg/special-action
allowed_orgs:
  - myorg
  - otherorg
"""
        policy = Policy._from_yaml(yaml_content)
        assert policy.allowed_actions == ["myorg/special-action"]
        assert policy.allowed_orgs == ["myorg", "otherorg"]

    def test_policy_roundtrip_allowlist(self):
        policy = Policy.load()
        policy.allowed_orgs = ["myorg"]
        policy.allowed_actions = ["myorg/action1"]
        yaml_text = policy.to_yaml()
        p2 = Policy._from_yaml(yaml_text)
        assert p2.allowed_orgs == ["myorg"]
        assert p2.allowed_actions == ["myorg/action1"]


class TestScoring:
    def test_perfect_score(self):
        result = calculate_score([])
        assert result.score == 100
        assert result.grade() == "A"
        assert result.total_deductions == 0

    def test_error_deduction(self):
        from gha_lint.models import Finding

        findings = [
            Finding(
                file="wf.yml",
                line=1,
                rule_id="r1",
                severity=Severity.ERROR,
                message="x",
            )
        ]
        result = calculate_score(findings)
        assert result.score == 90
        assert result.total_deductions == 10
        assert result.grade() == "A"

    def test_mixed_severities(self):
        from gha_lint.models import Finding

        findings = [
            Finding(file="wf.yml", line=1, rule_id="r1", severity=Severity.ERROR, message="x"),
            Finding(file="wf.yml", line=2, rule_id="r2", severity=Severity.WARN, message="x"),
            Finding(file="wf.yml", line=3, rule_id="r3", severity=Severity.INFO, message="x"),
        ]
        result = calculate_score(findings)
        assert result.total_deductions == 14
        assert result.score == 86
        assert result.grade() == "B"

    def test_floor_at_zero(self):
        from gha_lint.models import Finding

        findings = [
            Finding(file="wf.yml", line=i, rule_id="r", severity=Severity.ERROR, message="x")
            for i in range(20)
        ]
        result = calculate_score(findings)
        assert result.score == 0
        assert result.grade() == "F"

    def test_per_file_breakdown(self):
        from gha_lint.models import Finding

        findings = [
            Finding(file="a.yml", line=1, rule_id="r1", severity=Severity.ERROR, message="x"),
            Finding(file="a.yml", line=2, rule_id="r2", severity=Severity.WARN, message="x"),
            Finding(file="b.yml", line=1, rule_id="r3", severity=Severity.WARN, message="x"),
        ]
        result = calculate_score(findings)
        assert result.per_file["a.yml"] == 13
        assert result.per_file["b.yml"] == 3

    def test_to_dict(self):
        result = calculate_score([])
        d = result.to_dict()
        assert d["score"] == 100
        assert "breakdown" in d
        assert "per_file" in d
