"""Lint rules for GitHub Actions workflows.

Public exports (kept for backward compatibility):
- BaseRule, RuleInfo, shared regex patterns
- RuleEngine, ALL_RULES, explain_rule, get_rule_by_id
- All concrete rule classes
"""

from __future__ import annotations

from .base import (
    BaseRule,
    CURL_BASH_PATTERN,
    REUSABLE_WORKFLOW_PATTERN,
    RuleInfo,
    SECRET_REF_PATTERN,
    SHA_PATTERN,
    VERSION_TAG_PATTERN,
    WRITE_ALL_SCOPES,
)
from .registry import ALL_RULES, RuleEngine, explain_rule, get_rule_by_id
from .actions_must_pin_sha import ActionsMustPinShaRule
from .forbid_curl_pipe_bash import ForbidCurlPipeBashRule
from .forbidden_actions import ForbiddenActionsRule
from .matrix_not_expanded import MatrixExpandWarningRule
from .permissions_default_read import PermissionsDefaultReadRule
from .require_concurrency import RequireConcurrencyRule
from .require_timeout_minutes import RequireTimeoutMinutesRule
from .schema_validation import SchemaValidationRule
from .secrets_naming import SecretsNamingRule

__all__ = [
    "ALL_RULES",
    "ActionsMustPinShaRule",
    "BaseRule",
    "CURL_BASH_PATTERN",
    "ForbidCurlPipeBashRule",
    "ForbiddenActionsRule",
    "MatrixExpandWarningRule",
    "PermissionsDefaultReadRule",
    "REUSABLE_WORKFLOW_PATTERN",
    "RequireConcurrencyRule",
    "RequireTimeoutMinutesRule",
    "RuleEngine",
    "RuleInfo",
    "SECRET_REF_PATTERN",
    "SHA_PATTERN",
    "SchemaValidationRule",
    "SecretsNamingRule",
    "VERSION_TAG_PATTERN",
    "WRITE_ALL_SCOPES",
    "explain_rule",
    "get_rule_by_id",
]
