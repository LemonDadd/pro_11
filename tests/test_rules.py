from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml

from gha_lint.models import Severity
from gha_lint.parser import WorkflowParser
from gha_lint.policy import Policy, RuleConfig
from gha_lint.rules import (
    ActionsMustPinShaRule,
    ForbidCurlPipeBashRule,
    ForbiddenActionsRule,
    PermissionsDefaultReadRule,
    RequireConcurrencyRule,
    RequireTimeoutMinutesRule,
    RuleEngine,
    SecretsNamingRule,
    explain_rule,
    get_rule_by_id,
)


@pytest.fixture
def temp_workflow_dir() -> Path:
    tmp = Path(tempfile.mkdtemp())
    (tmp / ".github" / "workflows").mkdir(parents=True)
    return tmp


@pytest.fixture
def default_policy() -> Policy:
    return Policy.load()


def _write_workflow(dir_path: Path, name: str, content: dict) -> Path:
    wf_path = dir_path / ".github" / "workflows" / name
    wf_path.parent.mkdir(parents=True, exist_ok=True)
    wf_path.write_text(yaml.dump(content), encoding="utf-8")
    return wf_path


class TestParser:
    def test_parse_basic_workflow(self, temp_workflow_dir: Path):
        content = {
            "name": "CI",
            "on": ["push"],
            "permissions": "read-all",
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "timeout-minutes": 30,
                    "steps": [
                        {"uses": "actions/checkout@v4"},
                        {"run": "echo hello"},
                    ],
                }
            },
        }
        wf_path = _write_workflow(temp_workflow_dir, "ci.yml", content)
        parser = WorkflowParser(temp_workflow_dir)
        wf = parser.parse_file(wf_path)

        assert wf.name == "CI"
        assert wf.permissions == "read-all"
        assert len(wf.jobs) == 1
        assert wf.jobs[0].id == "build"
        assert wf.jobs[0].timeout_minutes == 30
        assert len(wf.jobs[0].steps) == 2
        assert wf.jobs[0].steps[0].uses == "actions/checkout@v4"
        assert wf.jobs[0].steps[1].run == "echo hello"

    def test_find_workflow_files(self, temp_workflow_dir: Path):
        _write_workflow(temp_workflow_dir, "a.yml", {"on": ["push"]})
        _write_workflow(temp_workflow_dir, "b.yaml", {"on": ["push"]})
        parser = WorkflowParser(temp_workflow_dir)
        files = parser.find_workflow_files()
        assert len(files) == 2

    def test_parse_reusable_workflow(self, temp_workflow_dir: Path):
        content = {
            "jobs": {
                "caller": {
                    "uses": "org/repo/.github/workflows/ci.yml@main",
                    "with": {"foo": "bar"},
                    "secrets": "inherit",
                }
            }
        }
        wf_path = _write_workflow(temp_workflow_dir, "caller.yml", content)
        wf = WorkflowParser(temp_workflow_dir).parse_file(wf_path)
        assert wf.jobs[0].uses_workflow == "org/repo/.github/workflows/ci.yml@main"
        assert wf.jobs[0].secrets == "inherit"
        assert wf.jobs[0].with_ == {"foo": "bar"}


class TestPolicy:
    def test_load_default_policy(self):
        p = Policy.load()
        assert "actions_must_pin_sha" in p.rules
        assert p.rules["actions_must_pin_sha"].severity == Severity.ERROR
        assert p.secrets_naming_pattern == "^[A-Z0-9_]+$"
        assert p.default_timeout_minutes == 360

    def test_rule_config_parse_string_severity(self):
        cfg = RuleConfig.parse("warn")
        assert cfg.enabled is True
        assert cfg.severity == Severity.WARN

    def test_rule_config_parse_list(self):
        cfg = RuleConfig.parse(["actions/checkout@v3"])
        assert cfg.enabled is True
        assert cfg.params["items"] == ["actions/checkout@v3"]

    def test_rule_config_parse_disabled(self):
        cfg = RuleConfig.parse(False)
        assert cfg.enabled is False

    def test_get_disabled_rule(self):
        p = Policy.load()
        cfg = p.get_rule("nonexistent_rule")
        assert cfg.enabled is False

    def test_roundtrip_yaml(self):
        p = Policy.load()
        yaml_text = p.to_yaml()
        p2 = Policy._from_yaml(yaml_text)
        assert p2.secrets_naming_pattern == p.secrets_naming_pattern
        assert set(p2.rules.keys()) == set(p.rules.keys())


class TestActionsMustPinShaRule:
    def test_tag_ref_triggers(self, temp_workflow_dir: Path, default_policy: Policy):
        content = {
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"uses": "actions/checkout@v4"}],
                }
            }
        }
        wf_path = _write_workflow(temp_workflow_dir, "wf.yml", content)
        wf = WorkflowParser(temp_workflow_dir).parse_file(wf_path)
        rule = ActionsMustPinShaRule(default_policy.get_rule("actions_must_pin_sha"), default_policy)
        findings = rule.evaluate(wf)
        assert len(findings) == 1
        assert findings[0].rule_id == "actions_must_pin_sha"

    def test_sha_ref_passes(self, temp_workflow_dir: Path, default_policy: Policy):
        content = {
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {"uses": "actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11"}
                    ],
                }
            }
        }
        wf_path = _write_workflow(temp_workflow_dir, "wf.yml", content)
        wf = WorkflowParser(temp_workflow_dir).parse_file(wf_path)
        rule = ActionsMustPinShaRule(default_policy.get_rule("actions_must_pin_sha"), default_policy)
        findings = rule.evaluate(wf)
        assert len(findings) == 0

    def test_reusable_workflow_branch_triggers(self, temp_workflow_dir: Path, default_policy: Policy):
        content = {
            "jobs": {
                "caller": {"uses": "org/wf.yml@main"},
            }
        }
        wf_path = _write_workflow(temp_workflow_dir, "wf.yml", content)
        wf = WorkflowParser(temp_workflow_dir).parse_file(wf_path)
        rule = ActionsMustPinShaRule(default_policy.get_rule("actions_must_pin_sha"), default_policy)
        findings = rule.evaluate(wf)
        assert len(findings) == 1


class TestForbidCurlPipeBashRule:
    def test_curl_bash_triggers(self, temp_workflow_dir: Path, default_policy: Policy):
        content = {
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"run": "curl https://x.com/install | bash"}],
                }
            }
        }
        wf_path = _write_workflow(temp_workflow_dir, "wf.yml", content)
        wf = WorkflowParser(temp_workflow_dir).parse_file(wf_path)
        rule = ForbidCurlPipeBashRule(default_policy.get_rule("forbid_curl_pipe_bash"), default_policy)
        findings = rule.evaluate(wf)
        assert len(findings) == 1

    def test_safe_run_passes(self, temp_workflow_dir: Path, default_policy: Policy):
        content = {
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"run": "echo hello"}],
                }
            }
        }
        wf_path = _write_workflow(temp_workflow_dir, "wf.yml", content)
        wf = WorkflowParser(temp_workflow_dir).parse_file(wf_path)
        rule = ForbidCurlPipeBashRule(default_policy.get_rule("forbid_curl_pipe_bash"), default_policy)
        findings = rule.evaluate(wf)
        assert len(findings) == 0


class TestRequireTimeoutMinutesRule:
    def test_missing_timeout_triggers(self, temp_workflow_dir: Path, default_policy: Policy):
        content = {
            "jobs": {
                "build": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo"}]},
            }
        }
        wf_path = _write_workflow(temp_workflow_dir, "wf.yml", content)
        wf = WorkflowParser(temp_workflow_dir).parse_file(wf_path)
        rule = RequireTimeoutMinutesRule(default_policy.get_rule("require_timeout_minutes"), default_policy)
        findings = rule.evaluate(wf)
        assert len(findings) == 1

    def test_present_timeout_passes(self, temp_workflow_dir: Path, default_policy: Policy):
        content = {
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "timeout-minutes": 30,
                    "steps": [{"run": "echo"}],
                },
            }
        }
        wf_path = _write_workflow(temp_workflow_dir, "wf.yml", content)
        wf = WorkflowParser(temp_workflow_dir).parse_file(wf_path)
        rule = RequireTimeoutMinutesRule(default_policy.get_rule("require_timeout_minutes"), default_policy)
        findings = rule.evaluate(wf)
        assert len(findings) == 0

    def test_reusable_workflow_skipped(self, temp_workflow_dir: Path, default_policy: Policy):
        content = {
            "jobs": {
                "caller": {"uses": "org/wf.yml@sha"},
            }
        }
        wf_path = _write_workflow(temp_workflow_dir, "wf.yml", content)
        wf = WorkflowParser(temp_workflow_dir).parse_file(wf_path)
        rule = RequireTimeoutMinutesRule(default_policy.get_rule("require_timeout_minutes"), default_policy)
        findings = rule.evaluate(wf)
        assert len(findings) == 0


class TestPermissionsDefaultReadRule:
    def test_no_permissions_triggers(self, temp_workflow_dir: Path, default_policy: Policy):
        content = {
            "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo"}]}}
        }
        wf_path = _write_workflow(temp_workflow_dir, "wf.yml", content)
        wf = WorkflowParser(temp_workflow_dir).parse_file(wf_path)
        rule = PermissionsDefaultReadRule(default_policy.get_rule("permissions_default_read"), default_policy)
        findings = rule.evaluate(wf)
        assert len(findings) == 1

    def test_write_all_triggers(self, temp_workflow_dir: Path, default_policy: Policy):
        content = {
            "permissions": "write-all",
            "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo"}]}},
        }
        wf_path = _write_workflow(temp_workflow_dir, "wf.yml", content)
        wf = WorkflowParser(temp_workflow_dir).parse_file(wf_path)
        rule = PermissionsDefaultReadRule(default_policy.get_rule("permissions_default_read"), default_policy)
        findings = rule.evaluate(wf)
        assert len(findings) == 1

    def test_read_all_passes(self, temp_workflow_dir: Path, default_policy: Policy):
        content = {
            "permissions": "read-all",
            "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo"}]}},
        }
        wf_path = _write_workflow(temp_workflow_dir, "wf.yml", content)
        wf = WorkflowParser(temp_workflow_dir).parse_file(wf_path)
        rule = PermissionsDefaultReadRule(default_policy.get_rule("permissions_default_read"), default_policy)
        findings = rule.evaluate(wf)
        assert len(findings) == 0


class TestSecretsNamingRule:
    def test_bad_name_in_run(self, temp_workflow_dir: Path, default_policy: Policy):
        content = {
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"run": "echo ${{ secrets.badName }}"}],
                }
            }
        }
        wf_path = _write_workflow(temp_workflow_dir, "wf.yml", content)
        wf = WorkflowParser(temp_workflow_dir).parse_file(wf_path)
        rule = SecretsNamingRule(default_policy.get_rule("secrets_naming"), default_policy)
        findings = rule.evaluate(wf)
        assert len(findings) == 1

    def test_good_name_passes(self, temp_workflow_dir: Path, default_policy: Policy):
        content = {
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"run": "echo ${{ secrets.GOOD_NAME }}"}],
                }
            }
        }
        wf_path = _write_workflow(temp_workflow_dir, "wf.yml", content)
        wf = WorkflowParser(temp_workflow_dir).parse_file(wf_path)
        rule = SecretsNamingRule(default_policy.get_rule("secrets_naming"), default_policy)
        findings = rule.evaluate(wf)
        assert len(findings) == 0


class TestForbiddenActionsRule:
    def test_forbidden_action_triggers(self, temp_workflow_dir: Path, default_policy: Policy):
        content = {
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"uses": "actions/checkout@v3"}],
                }
            }
        }
        wf_path = _write_workflow(temp_workflow_dir, "wf.yml", content)
        wf = WorkflowParser(temp_workflow_dir).parse_file(wf_path)
        rule = ForbiddenActionsRule(default_policy.get_rule("forbidden_actions"), default_policy)
        findings = rule.evaluate(wf)
        assert len(findings) == 1

    def test_allowed_action_passes(self, temp_workflow_dir: Path, default_policy: Policy):
        content = {
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"uses": "actions/checkout@v4"}],
                }
            }
        }
        wf_path = _write_workflow(temp_workflow_dir, "wf.yml", content)
        wf = WorkflowParser(temp_workflow_dir).parse_file(wf_path)
        rule = ForbiddenActionsRule(default_policy.get_rule("forbidden_actions"), default_policy)
        findings = rule.evaluate(wf)
        assert len(findings) == 0


class TestRequireConcurrencyRule:
    def test_missing_concurrency_triggers(self, temp_workflow_dir: Path, default_policy: Policy):
        content = {
            "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo"}]}}
        }
        wf_path = _write_workflow(temp_workflow_dir, "wf.yml", content)
        wf = WorkflowParser(temp_workflow_dir).parse_file(wf_path)
        rule = RequireConcurrencyRule(default_policy.get_rule("require_concurrency"), default_policy)
        findings = rule.evaluate(wf)
        assert len(findings) == 1

    def test_present_concurrency_passes(self, temp_workflow_dir: Path, default_policy: Policy):
        content = {
            "concurrency": {"group": "ci-${{ github.ref }}"},
            "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo"}]}},
        }
        wf_path = _write_workflow(temp_workflow_dir, "wf.yml", content)
        wf = WorkflowParser(temp_workflow_dir).parse_file(wf_path)
        rule = RequireConcurrencyRule(default_policy.get_rule("require_concurrency"), default_policy)
        findings = rule.evaluate(wf)
        assert len(findings) == 0


class TestRuleEngine:
    def test_engine_collects_all_findings(self, temp_workflow_dir: Path, default_policy: Policy):
        content = {
            "jobs": {
                "build": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {"uses": "actions/checkout@v3"},
                        {"run": "curl https://x | bash"},
                    ],
                }
            }
        }
        wf_path = _write_workflow(temp_workflow_dir, "wf.yml", content)
        wf = WorkflowParser(temp_workflow_dir).parse_file(wf_path)
        engine = RuleEngine(default_policy)
        findings = engine.evaluate(wf)
        rule_ids = {f.rule_id for f in findings}
        assert "actions_must_pin_sha" in rule_ids
        assert "forbid_curl_pipe_bash" in rule_ids
        assert "forbidden_actions" in rule_ids


class TestRuleMeta:
    def test_explain_rule(self):
        text = explain_rule("actions_must_pin_sha")
        assert text is not None
        assert "actions_must_pin_sha" in text

    def test_explain_unknown_rule(self):
        assert explain_rule("unknown_rule") is None

    def test_get_rule_by_id(self):
        assert get_rule_by_id("actions_must_pin_sha") is not None
        assert get_rule_by_id("does_not_exist") is None
