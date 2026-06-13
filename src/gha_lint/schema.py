from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import Finding, Severity

KNOWN_TOP_LEVEL_KEYS = {
    "name",
    "on",
    "jobs",
    "permissions",
    "concurrency",
    "env",
    "defaults",
    "jobs.",
    "strateg",
    "run-name",
    "env",
    "defaults",
    "concurrency",
}

KNOWN_JOB_KEYS = {
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
    "runs-on",
    "name",
}

KNOWN_STEP_KEYS = {
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
    "name",
}

VALID_ON_EVENTS = {
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
}


@dataclass
class SchemaIssue:
    rule_id: str
    message: str
    severity: Severity
    line: int = 1


class WorkflowSchemaValidator:
    def __init__(self, file_path: str, raw: dict[str, Any]):
        self.file_path = file_path
        self.raw = raw
        self.issues: list[SchemaIssue] = []

    def validate(self) -> list[SchemaIssue]:
        self._validate_top_level()
        self._validate_on()
        self._validate_jobs()
        return self.issues

    def _add_issue(self, rule_id: str, message: str, severity: Severity, line: int = 1) -> None:
        self.issues.append(SchemaIssue(rule_id=rule_id, message=message, severity=severity, line=line))

    def _get_line(self, data: dict[str, Any], default: int = 1) -> int:
        return int(data.get("__line__", default))

    def _validate_top_level(self) -> None:
        raw = self.raw
        line = self._get_line(raw)

        if not isinstance(raw, dict):
            self._add_issue(
                "schema_top_level_type",
                "Workflow file must be a YAML mapping at the top level.",
                Severity.ERROR,
                line,
            )
            return

        has_on = "on" in raw or True in raw
        if not has_on:
            self._add_issue(
                "schema_missing_on",
                "Workflow is missing 'on' (trigger) definition.",
                Severity.ERROR,
                line,
            )

        if "jobs" not in raw:
            self._add_issue(
                "schema_missing_jobs",
                "Workflow is missing 'jobs' section.",
                Severity.ERROR,
                line,
            )

        if isinstance(raw.get("jobs"), dict) and len(raw.get("jobs", {})) == 0:
            self._add_issue(
                "schema_empty_jobs",
                "Workflow has an empty 'jobs' section.",
                Severity.WARN,
                self._get_line(raw.get("jobs", {}), line),
            )

        known_top = {
            "name", "on", "jobs", "permissions", "concurrency", "env", "defaults",
            "run-name",
        }
        for key in raw.keys():
            if isinstance(key, bool) and key is True:
                continue
            if isinstance(key, str) and key.startswith("__"):
                continue
            if isinstance(key, str) and key not in known_top:
                self._add_issue(
                    "schema_unknown_top_key",
                    f"Unknown top-level key: '{key}'.",
                    Severity.INFO,
                    line,
                )

    def _validate_on(self) -> None:
        on_val = self.raw.get("on", self.raw.get(True))
        if on_val is None:
            return

        on_line = self._get_line(self.raw, 1)

        if isinstance(on_val, str):
            if on_val not in VALID_ON_EVENTS:
                self._add_issue(
                    "schema_unknown_event",
                    f"Unknown event name: '{on_val}'.",
                    Severity.WARN,
                    on_line,
                )
        elif isinstance(on_val, list):
            for i, event in enumerate(on_val):
                if isinstance(event, str) and event not in VALID_ON_EVENTS:
                    self._add_issue(
                        "schema_unknown_event",
                        f"Unknown event name: '{event}'.",
                        Severity.WARN,
                        on_line + i,
                    )
        elif isinstance(on_val, dict):
            for event in on_val.keys():
                if event not in VALID_ON_EVENTS and not event.startswith("__"):
                    self._add_issue(
                        "schema_unknown_event",
                        f"Unknown event name: '{event}'.",
                        Severity.WARN,
                        on_line,
                    )
        else:
            self._add_issue(
                "schema_invalid_on",
                "'on' must be a string, list, or mapping.",
                Severity.ERROR,
                on_line,
            )

    def _validate_jobs(self) -> None:
        jobs_raw = self.raw.get("jobs")
        if jobs_raw is None:
            return
        if not isinstance(jobs_raw, dict):
            self._add_issue(
                "schema_jobs_type",
                "'jobs' must be a mapping.",
                Severity.ERROR,
                self._get_line(self.raw),
            )
            return

        jobs_line = self._get_line(jobs_raw, self._get_line(self.raw))
        for job_id, job_raw in jobs_raw.items():
            if isinstance(job_raw, dict):
                self._validate_job(job_id, job_raw, jobs_line)
            else:
                self._add_issue(
                    "schema_job_type",
                    f"Job '{job_id}' must be a mapping.",
                    Severity.ERROR,
                    jobs_line,
                )

    def _validate_job(self, job_id: str, job_raw: dict[str, Any], parent_line: int) -> None:
        line = self._get_line(job_raw, parent_line)

        uses = job_raw.get("uses")
        runs_on = job_raw.get("runs-on")
        steps = job_raw.get("steps")

        if uses is None and runs_on is None:
            self._add_issue(
                "schema_job_missing_runs_on",
                f"Job '{job_id}' must specify 'runs-on' (or 'uses' for reusable workflows).",
                Severity.ERROR,
                line,
            )

        if uses is not None:
            if not isinstance(uses, str):
                self._add_issue(
                    "schema_job_uses_type",
                    f"Job '{job_id}' 'uses' must be a string.",
                    Severity.ERROR,
                    line,
                )
            if steps is not None:
                self._add_issue(
                    "schema_job_reusable_with_steps",
                    f"Job '{job_id}' is a reusable workflow caller and cannot have 'steps'.",
                    Severity.ERROR,
                    line,
                )
            if runs_on is not None:
                self._add_issue(
                    "schema_job_reusable_with_runs_on",
                    f"Job '{job_id}' is a reusable workflow caller and should not have 'runs-on'.",
                    Severity.WARN,
                    line,
                )
        else:
            if steps is None:
                self._add_issue(
                    "schema_job_missing_steps",
                    f"Job '{job_id}' has no 'steps'.",
                    Severity.WARN,
                    line,
                )
            elif not isinstance(steps, list):
                self._add_issue(
                    "schema_steps_type",
                    f"Job '{job_id}' 'steps' must be a list.",
                    Severity.ERROR,
                    line,
                )
            else:
                for i, step in enumerate(steps):
                    if isinstance(step, dict):
                        self._validate_step(job_id, step, line + i)
                    else:
                        self._add_issue(
                            "schema_step_type",
                            f"Job '{job_id}' step {i + 1} must be a mapping.",
                            Severity.ERROR,
                            line + i,
                        )

        if job_raw.get("timeout-minutes") is not None:
            timeout = job_raw["timeout-minutes"]
            if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
                self._add_issue(
                    "schema_timeout_type",
                    f"Job '{job_id}' 'timeout-minutes' must be a number.",
                    Severity.ERROR,
                    line,
                )

    def _validate_step(self, job_id: str, step_raw: dict[str, Any], line: int) -> None:
        uses = step_raw.get("uses")
        run = step_raw.get("run")

        if uses is None and run is None:
            self._add_issue(
                "schema_step_missing_action",
                f"Step in job '{job_id}' must have 'uses' or 'run'.",
                Severity.ERROR,
                self._get_line(step_raw, line),
            )

        if uses is not None and run is not None:
            self._add_issue(
                "schema_step_both_uses_run",
                f"Step in job '{job_id}' cannot have both 'uses' and 'run'.",
                Severity.ERROR,
                self._get_line(step_raw, line),
            )

        if uses is not None and not isinstance(uses, str):
            self._add_issue(
                "schema_step_uses_type",
                "Step 'uses' must be a string.",
                Severity.ERROR,
                self._get_line(step_raw, line),
            )

        if run is not None and not isinstance(run, str):
            self._add_issue(
                "schema_step_run_type",
                "Step 'run' must be a string.",
                Severity.ERROR,
                self._get_line(step_raw, line),
            )

        if step_raw.get("with") is not None and not isinstance(step_raw["with"], dict):
            self._add_issue(
                "schema_step_with_type",
                "Step 'with' must be a mapping.",
                Severity.ERROR,
                self._get_line(step_raw, line),
            )


def validate_workflow_schema(file_path: str, raw: dict[str, Any]) -> list[Finding]:
    validator = WorkflowSchemaValidator(file_path, raw)
    issues = validator.validate()
    return [
        Finding(
            file=file_path,
            line=issue.line,
            rule_id=issue.rule_id,
            severity=issue.severity,
            message=issue.message,
        )
        for issue in issues
    ]
