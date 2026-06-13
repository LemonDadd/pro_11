from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import Severity

DEFAULT_POLICY_YAML = """# gha-lint default policy
rules:
  actions_must_pin_sha: error
  forbid_curl_pipe_bash: error
  require_timeout_minutes: warn
  permissions_default_read: warn
  secrets_naming: warn
  forbidden_actions:
    - actions/checkout@v3
  require_concurrency: info

secrets_naming_pattern: '^[A-Z0-9_]+$'
default_timeout_minutes: 360
"""


@dataclass
class RuleConfig:
    severity: Severity | None = None
    params: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True

    @classmethod
    def parse(cls, value: Any) -> "RuleConfig":
        if value is None or value is False:
            return cls(enabled=False)
        if value is True:
            return cls()
        if isinstance(value, str):
            try:
                return cls(severity=Severity(value))
            except ValueError:
                return cls(params={"value": value})
        if isinstance(value, list):
            return cls(params={"items": value})
        if isinstance(value, dict):
            cfg = cls()
            if "severity" in value:
                cfg.severity = Severity(value["severity"])
            for k, v in value.items():
                if k != "severity":
                    cfg.params[k] = v
            return cfg
        return cls(params={"value": value})


@dataclass
class Policy:
    rules: dict[str, RuleConfig] = field(default_factory=dict)
    secrets_naming_pattern: str = "^[A-Z0-9_]+$"
    default_timeout_minutes: int = 360

    def get_rule(self, rule_id: str) -> RuleConfig:
        if rule_id not in self.rules:
            return RuleConfig(enabled=False)
        return self.rules[rule_id]

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Policy":
        if path is None:
            return cls._from_yaml(DEFAULT_POLICY_YAML)
        path = Path(path)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        return cls._from_yaml(content)

    @classmethod
    def _from_yaml(cls, content: str) -> "Policy":
        data = yaml.safe_load(content) or {}
        policy = cls()

        if "secrets_naming_pattern" in data:
            policy.secrets_naming_pattern = str(data["secrets_naming_pattern"])
        if "default_timeout_minutes" in data:
            policy.default_timeout_minutes = int(data["default_timeout_minutes"])

        rules_raw = data.get("rules", {})
        if isinstance(rules_raw, dict):
            for rule_id, value in rules_raw.items():
                policy.rules[rule_id] = RuleConfig.parse(value)

        return policy

    def to_yaml(self) -> str:
        rules_dict: dict[str, Any] = {}
        for rule_id, cfg in self.rules.items():
            if not cfg.enabled:
                rules_dict[rule_id] = False
            elif cfg.params and "items" in cfg.params:
                rules_dict[rule_id] = cfg.params["items"]
            elif cfg.params and "value" in cfg.params:
                rules_dict[rule_id] = cfg.params["value"]
            elif cfg.severity:
                rules_dict[rule_id] = cfg.severity.value
            else:
                rules_dict[rule_id] = True

        out: dict[str, Any] = {
            "rules": rules_dict,
            "secrets_naming_pattern": self.secrets_naming_pattern,
            "default_timeout_minutes": self.default_timeout_minutes,
        }
        return yaml.dump(out, sort_keys=False, default_flow_style=False)
