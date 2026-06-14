"""Reusable workflow dependency graph construction and cycle detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import Finding, Severity, WorkflowModel


@dataclass
class WorkflowCallEdge:
    """A single `job.uses:` reference from a caller workflow to a callee workflow."""

    caller_file: str
    callee_ref: str
    caller_job: str
    line: int


@dataclass
class DependencyGraph:
    """Directed graph of reusable workflow call relationships."""

    workflows: dict[str, WorkflowModel] = field(default_factory=dict)
    edges: list[WorkflowCallEdge] = field(default_factory=list)
    cycles: list[list[str]] = field(default_factory=list)

    def add_workflow(self, wf: WorkflowModel) -> None:
        """Register a workflow and extract all outgoing call edges from its jobs."""
        self.workflows[wf.file_path] = wf
        for job in wf.jobs:
            if job.uses_workflow:
                self.edges.append(WorkflowCallEdge(
                    caller_file=wf.file_path,
                    callee_ref=job.uses_workflow,
                    caller_job=job.id,
                    line=job.line,
                ))

    def get_callers(self, callee: str) -> list[str]:
        """Return all caller files that reference the given callee reference."""
        return [e.caller_file for e in self.edges if e.callee_ref == callee]

    def get_callees(self, caller: str) -> list[str]:
        """Return all callee references invoked by the given caller file."""
        return [e.callee_ref for e in self.edges if e.caller_file == caller]

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
            nodes.add(e.callee_ref)
        return nodes

    def leaf_workflows(self) -> list[str]:
        """Return workflows that are never called by any other workflow."""
        callees: set[str] = {e.callee_ref for e in self.edges}
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
            callee = self._mermaid_id(e.callee_ref)
            if (caller, callee) not in seen:
                lines.append(f"    {caller} --> {callee}")
                seen.add((caller, callee))
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _mermaid_id(s: str) -> str:
        s = s.replace("/", "_").replace(".", "_").replace("-", "_").replace("@", "_")
        return s.replace(" ", "_")


def build_dependency_graph(workflows: list[WorkflowModel]) -> DependencyGraph:
    """Build a dependency graph from a collection of parsed workflows."""
    graph = DependencyGraph()
    for wf in workflows:
        graph.add_workflow(wf)
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
            if e.caller_file == cycle[0] and e.callee_ref == cycle[1]:
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
