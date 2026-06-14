"""Reusable workflow dependency graph construction and cycle detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Finding, Severity, WorkflowModel


def _extract_workflow_basename(callee_ref: str) -> str | None:
    """Extract the workflow filename (e.g. ``build.yml``) from a ``uses`` ref.

    Supports GitHub Actions reusable workflow references like::

        owner/repo/.github/workflows/build.yml@v1
        ./.github/workflows/build.yml@main
        ./build.yml
        org/build.yml@v1
    """
    # Strip @ref suffix
    at_idx = callee_ref.find("@")
    if at_idx != -1:
        callee_ref = callee_ref[:at_idx]

    # Case 1: .github/workflows/<name>
    marker = ".github/workflows/"
    idx = callee_ref.find(marker)
    if idx != -1:
        return callee_ref[idx + len(marker):]

    # Case 2: ./<name> or <org>/<name>
    slash_idx = callee_ref.rfind("/")
    if slash_idx != -1:
        return callee_ref[slash_idx + 1:]

    # Case 3: just a name
    if callee_ref.endswith((".yml", ".yaml")):
        return callee_ref
    return None


def _resolve_callee_to_local(
    callee_ref: str,
    local_workflow_files: list[str],
) -> str | None:
    """Resolve a ``uses`` ref to a local workflow file path if possible.

    ``local_workflow_files`` should be a list of absolute or relative paths to
    all workflow files in the current repository (e.g. from ``WorkflowParser``).
    """
    basename = _extract_workflow_basename(callee_ref)
    if basename is None:
        return None

    for wf_path in local_workflow_files:
        if Path(wf_path).name == basename:
            return wf_path
    return None


@dataclass
class WorkflowCallEdge:
    """A single `job.uses:` reference from a caller workflow to a callee workflow."""

    caller_file: str
    callee_ref: str
    caller_job: str
    line: int
    callee_file: str | None = None


@dataclass
class DependencyGraph:
    """Directed graph of reusable workflow call relationships."""

    workflows: dict[str, WorkflowModel] = field(default_factory=dict)
    edges: list[WorkflowCallEdge] = field(default_factory=list)
    cycles: list[list[str]] = field(default_factory=list)

    def add_workflow(self, wf: WorkflowModel) -> None:
        """Register a workflow (call before :func:`build_dependency_graph` extracts edges)."""
        self.workflows[wf.file_path] = wf

    def get_callers(self, callee: str) -> list[str]:
        """Return all caller files that reference the given callee (local file path or ref)."""
        callers: list[str] = []
        for e in self.edges:
            if e.callee_file == callee or e.callee_ref == callee:
                callers.append(e.caller_file)
        return callers

    def get_callees(self, caller: str) -> list[str]:
        """Return all local callee file paths invoked by the given caller file."""
        callees: list[str] = []
        for e in self.edges:
            if e.caller_file == caller:
                target = e.callee_file if e.callee_file is not None else e.callee_ref
                callees.append(target)
        return callees

    def detect_cycles(self) -> list[list[str]]:
        """Find all cycles using DFS. Cached after the first call."""
        if self.cycles:
            return self.cycles

        nodes: set[str] = self._build_node_set()
        visited: set[str] = set()
        in_stack: set[str] = set()
        path: list[str] = []
        cycles: list[list[str]] = []

        def dfs(node: str) -> None:
            if node in in_stack:
                idx = path.index(node)
                cycles.append(path[idx:] + [node])
                return
            if node in visited:
                return
            visited.add(node)
            in_stack.add(node)
            path.append(node)
            for neighbor in self.get_callees(node):
                dfs(neighbor)
            path.pop()
            in_stack.remove(node)

        for node in sorted(nodes):
            dfs(node)

        self.cycles = cycles
        return cycles

    def _build_node_set(self) -> set[str]:
        nodes: set[str] = set(self.workflows.keys())
        for e in self.edges:
            target = e.callee_file if e.callee_file is not None else e.callee_ref
            nodes.add(target)
        return nodes

    def leaf_workflows(self) -> list[str]:
        """Return workflows that are never called by any other workflow."""
        callees: set[str] = set()
        for e in self.edges:
            target = e.callee_file if e.callee_file is not None else e.callee_ref
            callees.add(target)
        return sorted([w for w in self.workflows if w not in callees])

    def root_workflows(self) -> list[str]:
        """Return workflows that never call any other workflow."""
        callers: set[str] = {e.caller_file for e in self.edges}
        return sorted([w for w in self.workflows if w not in callers])

    def to_dict(self) -> dict[str, Any]:
        """Serialize the graph to a JSON-friendly dictionary."""
        return {
            "workflows": sorted(self.workflows.keys()),
            "edges": [
                {
                    "caller": e.caller_file,
                    "callee": e.callee_ref,
                    "callee_file": e.callee_file,
                    "job": e.caller_job,
                    "line": e.line,
                }
                for e in sorted(self.edges, key=lambda x: (x.caller_file, x.caller_job))
            ],
            "cycles": self.detect_cycles(),
            "roots": self.root_workflows(),
            "leaves": self.leaf_workflows(),
        }

    def to_mermaid(self) -> str:
        """Render the graph as a Mermaid flowchart source string."""
        lines: list[str] = ["flowchart LR"]
        seen: set[tuple[str, str]] = set()
        for e in sorted(self.edges, key=lambda x: (x.caller_file, x.caller_job)):
            caller = self._mermaid_id(e.caller_file)
            callee = e.callee_file if e.callee_file is not None else e.callee_ref
            callee_id = self._mermaid_id(callee)
            if (caller, callee_id) not in seen:
                lines.append(f"    {caller} --> {callee_id}")
                seen.add((caller, callee_id))
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _mermaid_id(s: str) -> str:
        s = s.replace("/", "_").replace(".", "_").replace("-", "_").replace("@", "_")
        return s.replace(" ", "_")


def build_dependency_graph(workflows: list[WorkflowModel]) -> DependencyGraph:
    """Build a dependency graph from a collection of parsed workflows.

    Each ``job.uses:`` reference is resolved to a local workflow file path when
    it points to a workflow in the same repository.
    """
    graph = DependencyGraph()

    # First pass: register all workflows
    for wf in workflows:
        graph.add_workflow(wf)

    # Second pass: extract edges and resolve callee refs to local paths
    local_files = list(graph.workflows.keys())
    for wf in workflows:
        for job in wf.jobs:
            if job.uses_workflow:
                callee_file = _resolve_callee_to_local(job.uses_workflow, local_files)
                graph.edges.append(WorkflowCallEdge(
                    caller_file=wf.file_path,
                    callee_ref=job.uses_workflow,
                    caller_job=job.id,
                    line=job.line,
                    callee_file=callee_file,
                ))

    return graph


def cycle_findings_from_graph(graph: DependencyGraph) -> list[Finding]:
    """Convert detected cycles into Finding objects."""
    findings: list[Finding] = []
    cycles: list[list[str]] = graph.detect_cycles()
    for cycle in cycles:
        if len(cycle) < 2:
            continue
        edge: WorkflowCallEdge | None = None
        for e in graph.edges:
            callee = e.callee_file if e.callee_file is not None else e.callee_ref
            if e.caller_file == cycle[0] and callee == cycle[1]:
                edge = e
                break
        line = edge.line if edge else 1
        file_ = edge.caller_file if edge else cycle[0]
        findings.append(Finding(
            file=file_,
            line=line,
            rule_id="reusable_cycle",
            severity=Severity.ERROR,
            message=f"Circular dependency in reusable workflow call chain: {' → '.join(cycle)}",
        ))
    return findings
