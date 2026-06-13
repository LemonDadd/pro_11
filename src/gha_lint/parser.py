from __future__ import annotations

import glob
from pathlib import Path
from typing import Any, Iterator

import yaml

from .models import Job, Step, WorkflowModel


class LineLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: LineLoader, node: yaml.MappingNode) -> dict[str, Any]:
    loader.flatten_mapping(node)
    mapping: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=False)
        value = loader.construct_object(value_node, deep=False)
        if isinstance(value, dict):
            value["__line__"] = key_node.start_mark.line + 1
        if isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    item["__line__"] = value_node.value[i][0].start_mark.line + 1 \
                        if value_node.value and i < len(value_node.value) \
                        else key_node.start_mark.line + 1
        mapping[key] = value
    mapping["__line__"] = node.start_mark.line + 1
    return mapping


LineLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def _get_line(data: dict[str, Any], default: int = 1) -> int:
    return int(data.pop("__line__", default))


def _clean_dict(d: Any) -> Any:
    if isinstance(d, dict):
        return {k: _clean_dict(v) for k, v in d.items() if not k.startswith("__")}
    if isinstance(d, list):
        return [_clean_dict(item) for item in d]
    return d


class WorkflowParser:
    def __init__(self, root_path: str | Path):
        self.root_path = Path(root_path)
        self.scan_root, self.search_patterns = self._resolve_scan_targets(self.root_path)

    @staticmethod
    def _resolve_scan_targets(root: Path) -> tuple[Path, list[Path]]:
        if root.is_file():
            if root.suffix.lower() in {".yml", ".yaml"}:
                return root.parent, [root]
            return root.parent, []

        root = root.resolve()

        is_workflows_dir = (
            root.name == "workflows"
            and root.parent.name == ".github"
        )

        patterns: list[Path]
        if is_workflows_dir:
            patterns = [
                root / "*.yml",
                root / "*.yaml",
            ]
        else:
            patterns = [
                root / ".github" / "workflows" / "*.yml",
                root / ".github" / "workflows" / "*.yaml",
            ]

        files: list[Path] = []
        for p in patterns:
            files.extend(Path(fp) for fp in glob.glob(str(p)))
        return root, files

    def find_workflow_files(self) -> list[Path]:
        return sorted(self.search_patterns)

    def parse_file(self, file_path: str | Path) -> WorkflowModel:
        file_path = Path(file_path)
        with open(file_path, "r", encoding="utf-8") as f:
            raw = yaml.load(f, Loader=LineLoader) or {}

        model = self._build_model(file_path, raw)
        model.raw = raw
        return model

    def parse_all(self) -> Iterator[WorkflowModel]:
        for file_path in self.find_workflow_files():
            yield self.parse_file(file_path)

    def _build_model(self, file_path: Path, raw: dict[str, Any]) -> WorkflowModel:
        line = _get_line(raw)

        workflow = WorkflowModel(
            file_path=str(file_path),
            name=raw.get("name"),
            on=raw.get("on", raw.get(True, {})),
            permissions=raw.get("permissions"),
            concurrency=_clean_dict(raw.get("concurrency")),
            defaults=_clean_dict(raw.get("defaults", {})),
            env=_clean_dict(raw.get("env", {})),
        )

        jobs_raw = raw.get("jobs", {})
        if isinstance(jobs_raw, dict):
            jobs_line = _get_line(jobs_raw, line)
            for job_id, job_raw in jobs_raw.items():
                if isinstance(job_raw, dict):
                    workflow.jobs.append(self._parse_job(job_id, job_raw, jobs_line))

        return workflow

    def _parse_job(self, job_id: str, raw: dict[str, Any], parent_line: int) -> Job:
        line = _get_line(raw, parent_line)

        job = Job(
            id=job_id,
            name=raw.get("name"),
            permissions=raw.get("permissions"),
            timeout_minutes=raw.get("timeout-minutes"),
            uses_workflow=raw.get("uses"),
            with_=_clean_dict(raw.get("with", {})) if isinstance(raw.get("with"), dict) else {},
            secrets=raw.get("secrets"),
            needs=self._parse_needs(raw.get("needs")),
            strategy=_clean_dict(raw.get("strategy", {})) if isinstance(raw.get("strategy"), dict) else {},
            runs_on=raw.get("runs-on"),
            line=line,
        )

        steps_raw = raw.get("steps", [])
        if isinstance(steps_raw, list):
            for step_raw in steps_raw:
                if isinstance(step_raw, dict):
                    step_line = _get_line(step_raw, line)
                    job.steps.append(self._parse_step(step_raw, step_line))

        return job

    def _parse_step(self, raw: dict[str, Any], line: int) -> Step:
        step = Step(
            id=raw.get("id"),
            name=raw.get("name"),
            uses=raw.get("uses"),
            run=raw.get("run"),
            with_=_clean_dict(raw.get("with", {})) if isinstance(raw.get("with"), dict) else {},
            permissions=raw.get("permissions"),
            line=line,
            raw={k: v for k, v in raw.items() if not k.startswith("__")},
        )
        return step

    @staticmethod
    def _parse_needs(needs: Any) -> list[str]:
        if needs is None:
            return []
        if isinstance(needs, str):
            return [needs]
        if isinstance(needs, list):
            return [n for n in needs if isinstance(n, str)]
        return []
