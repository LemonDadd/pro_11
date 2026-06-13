from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .formatter import Formatter, OutputFormat, ScanSummary
from .models import Severity, WorkflowModel
from .parser import WorkflowParser
from .policy import DEFAULT_POLICY_YAML, Policy
from .rules import RuleEngine, explain_rule
from .scoring import calculate_score, format_score

app = typer.Typer(
    name="gha-lint",
    help="Lint GitHub Actions workflow files with custom policy rules.",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()
err_console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"gha-lint {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """gha-lint: Lint GitHub Actions workflows with custom policy rules."""
    pass


@app.command()
def scan(
    path: Path = typer.Option(
        Path("."),
        "--path",
        "-p",
        help="Repository root, workflows directory, or a single workflow file.",
        exists=True,
        readable=True,
    ),
    policy: Optional[Path] = typer.Option(
        None,
        "--policy",
        "-P",
        help="Path to policy.yaml file. Uses built-in defaults if omitted.",
        exists=True,
        readable=True,
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.TABLE,
        "--format",
        "-f",
        help="Output format: table, json, sarif, or github (annotations).",
    ),
    fail_on: Severity = typer.Option(
        Severity.ERROR,
        "--fail-on",
        "-F",
        help="Minimum severity that triggers a non-zero exit code (error/warn/info).",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write output to file instead of stdout (for non-table formats).",
    ),
    show_score: bool = typer.Option(
        False,
        "--score",
        "-s",
        help="Show compliance score (0-100) alongside findings.",
    ),
) -> None:
    """Scan workflow files for policy violations."""
    try:
        policy_obj = Policy.load(policy) if policy else Policy.load()
    except Exception as e:
        err_console.print(f"[red]Error loading policy: {e}[/red]")
        raise typer.Exit(code=2)

    engine = RuleEngine(policy_obj)

    workflows: list[WorkflowModel] = []
    parser = WorkflowParser(path)

    if path.is_file():
        try:
            workflows.append(parser.parse_file(path))
        except Exception as e:
            err_console.print(f"[red]Error parsing {path}: {e}[/red]")
            raise typer.Exit(code=2)
    else:
        wf_files = parser.find_workflow_files()
        if not wf_files:
            err_console.print(f"[yellow]No workflow files found at path: {path}[/yellow]")
        for wf_file in wf_files:
            try:
                workflows.append(parser.parse_file(wf_file))
            except Exception as e:
                err_console.print(f"[red]Error parsing {wf_file}: {e}[/red]")
                raise typer.Exit(code=2)

    findings = engine.evaluate_all(workflows)

    if format == OutputFormat.TABLE:
        Formatter.format(findings, format, console)
    else:
        rendered = Formatter.format(findings, format)
        if output:
            output.write_text(rendered + "\n", encoding="utf-8")
            console.print(f"[green]Wrote {format.value} report to {output}[/green]")
        else:
            if rendered:
                console.print(rendered)

    if show_score:
        score_result = calculate_score(findings)
        console.print()
        console.print(format_score(score_result))

    summary = ScanSummary.from_findings(findings)
    if summary.should_fail(fail_on):
        raise typer.Exit(code=1)


@app.command("init-policy")
def init_policy(
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write to file instead of stdout.",
    ),
) -> None:
    """Generate a default policy.yaml template."""
    content = DEFAULT_POLICY_YAML
    if output:
        if output.exists():
            err_console.print(f"[red]Refusing to overwrite existing file: {output}[/red]")
            raise typer.Exit(code=2)
        output.write_text(content, encoding="utf-8")
        console.print(f"[green]Wrote default policy to {output}[/green]")
    else:
        sys.stdout.write(content)


@app.command()
def explain(
    rule_id: str = typer.Argument(..., help="Rule ID to explain (e.g. actions_must_pin_sha)."),
) -> None:
    """Show detailed documentation for a specific rule."""
    text = explain_rule(rule_id)
    if text is None:
        err_console.print(
            f"[red]Unknown rule: {rule_id}[/red]\n\n"
            "[yellow]Available rules:[/yellow]\n"
            + "\n".join(
                f"  - [cyan]{cls.info.rule_id}[/cyan]: {cls.info.description}"
                for cls in RuleEngine._rules_classes if False  # type: ignore
            )
        )
        from .rules import ALL_RULES
        err_console.print(
            "\n[yellow]Available rules:[/yellow]\n"
            + "\n".join(
                f"  - [cyan]{cls.info.rule_id}[/cyan]: {cls.info.description}"
                for cls in ALL_RULES
            )
        )
        raise typer.Exit(code=2)
    console.print(text)


@app.command("list-rules")
def list_rules() -> None:
    """List all available built-in rules."""
    from .rules import ALL_RULES

    table = Table(title="Available Rules")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Category", style="magenta")
    table.add_column("Default Severity", style="yellow")
    table.add_column("Description", overflow="fold")

    for cls in sorted(ALL_RULES, key=lambda c: c.info.rule_id):
        info = cls.info
        table.add_row(
            info.rule_id,
            info.category,
            info.default_severity.value,
            info.description,
        )
    console.print(table)


@app.command()
def graph(
    path: Path = typer.Option(
        Path("."),
        "--path",
        "-p",
        help="Repository root, workflows directory, or a single workflow file.",
        exists=True,
        readable=True,
    ),
    format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table, json, or mermaid.",
    ),
) -> None:
    """Show reusable workflow dependency graph."""
    from .dependency import build_dependency_graph

    parser = WorkflowParser(path)
    workflows = list(parser.parse_all())

    graph_ = build_dependency_graph(workflows)

    if format == "json":
        import json

        console.print(json.dumps(graph_.to_dict(), indent=2))
    elif format == "mermaid":
        console.print(graph_.to_mermaid())
    else:
        table = Table(title="Reusable Workflow Dependency Graph")
        table.add_column("Caller", style="cyan")
        table.add_column("Job", style="magenta")
        table.add_column("→ Callee", style="yellow")
        table.add_column("Line", justify="right")

        if not graph_.edges:
            console.print("[yellow]No reusable workflow calls detected.[/yellow]")
        else:
            for e in sorted(graph_.edges, key=lambda x: (x.caller_file, x.caller_job)):
                table.add_row(e.caller_file, e.caller_job, e.callee_ref, str(e.line))
            console.print(table)

        cycles = graph_.detect_cycles()
        if cycles:
            console.print()
            console.print(f"[red]Detected {len(cycles)} circular dependency(ies):[/red]")
            for cyc in cycles:
                console.print(f"  - {' → '.join(cyc)}")

        console.print()
        console.print(
            f"[bold]Summary:[/bold] {len(graph_.workflows)} workflow(s), "
            f"{len(graph_.edges)} call edge(s), "
            f"{len(cycles)} cycle(s)"
        )


if __name__ == "__main__":
    app()
