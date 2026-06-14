"""Resolve workflow file paths from repository root, workflows dir, or a single file."""

from __future__ import annotations

import glob
from pathlib import Path


def _is_workflows_directory(path: Path) -> bool:
    """Return True if path directly points at a `.github/workflows` directory."""
    return path.is_dir() and path.name == "workflows" and path.parent.name == ".github"


def resolve_workflow_files(path: Path) -> list[Path]:
    """Resolve a user-supplied path into a sorted list of workflow YAML files.

    Supports three modes:
    1. A single workflow file (must end in .yml or .yaml)
    2. A `.github/workflows` directory (scans *.yml / *.yaml inside)
    3. A repository root (scans <root>/.github/workflows/*.yml|yaml)
    """
    path = path.resolve()

    if path.is_file():
        if path.suffix.lower() in {".yml", ".yaml"}:
            return [path]
        return []

    if _is_workflows_directory(path):
        patterns = [path / "*.yml", path / "*.yaml"]
    else:
        patterns = [
            path / ".github" / "workflows" / "*.yml",
            path / ".github" / "workflows" / "*.yaml",
        ]

    files: list[Path] = []
    for pattern in patterns:
        files.extend(Path(fp) for fp in glob.glob(str(pattern)))
    return sorted(files)


def describe_path_scope(path: Path) -> str:
    """Return a short human-readable description of what ``path`` is targeting."""
    path = path.resolve()
    if path.is_file():
        return f"single file: {path.name}"
    if _is_workflows_directory(path):
        return f"workflows directory: {path}"
    return f"repository root: {path}"
