"""
ITGE CLI - command-line interface for the Identity & Trust Graph Engine.
"""

from __future__ import annotations

import asyncio
import csv
import json
from pathlib import Path
from typing import Optional

import typer
from rich.progress import Progress, TextColumn
from rich.table import Table

from .config import (
    ITGEConfig,
    console,
    error,
    handle_error,
    info,
    load_config,
    save_config,
    setup_logging,
    success,
    warning,
)

app = typer.Typer(
    name="itge",
    help="ITGE - Identity & Trust Graph Engine: strategic attack path modeling for red teams",
    add_completion=False,
)


@app.callback()
def main(
    ctx: typer.Context,
    config_file: Optional[Path] = typer.Option(None, "--config", "-c", help="Configuration file path"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress non-error output"),
) -> None:
    config = load_config(config_file)
    log_level = "DEBUG" if verbose else "ERROR" if quiet else config.log_level
    setup_logging(log_level, config.log_file)
    ctx.obj = config


@app.command()
def ingest(
    ctx: typer.Context,
    burp: Optional[Path] = typer.Option(None, "--burp", help="Burp Suite XML export"),
    zap: Optional[Path] = typer.Option(None, "--zap", help="OWASP ZAP XML export"),
    amass: Optional[Path] = typer.Option(None, "--amass", help="Amass JSON export"),
    nmap: Optional[Path] = typer.Option(None, "--nmap", help="Nmap XML export"),
    build_graph: bool = typer.Option(True, "--build-graph/--no-build-graph", help="Build Neo4j graph after ingestion"),
) -> None:
    config: ITGEConfig = ctx.obj
    if not any([burp, zap, amass, nmap]):
        error("No input file specified. Use --burp, --zap, --amass, or --nmap.")
        raise typer.Exit(1)

    try:
        asyncio.run(_ingest_async(config, burp, zap, amass, nmap, build_graph))
    except Exception as exc:
        handle_error(exc)


async def _ingest_async(
    config: ITGEConfig,
    burp: Path | None,
    zap: Path | None,
    amass: Path | None,
    nmap: Path | None,
    build_graph: bool,
) -> None:
    from ..application.services.graph_construction_service import GraphConstructionService
    from ..application.services.ingestion_service import IngestionService
    from ..application.services.trust_detection_service import TrustDetectionService
    from ..infrastructure.graph import GraphRepository

    info("Starting ingestion pipeline...")
    ingestion_service = IngestionService()
    trust_service = TrustDetectionService()
    repo = None
    graph_service = None

    if build_graph:
        repo = GraphRepository(config.neo4j_uri, config.neo4j_user, config.neo4j_password)
        await repo.initialize_schema()
        graph_service = GraphConstructionService(repo)

    sources = [
        ("Burp", burp, "burp_xml"),
        ("ZAP", zap, "zap_xml"),
        ("Amass", amass, "amass_json"),
        ("Nmap", nmap, "nmap_xml"),
    ]

    totals = {
        "observations": 0,
        "findings": 0,
        "nodes": 0,
        "edges": 0,
        "services": 0,
        "datastores": 0,
    }

    try:
        with Progress(TextColumn("[progress.description]{task.description}"), console=console) as progress:
            for label, path, file_type in sources:
                if not path:
                    continue

                task = progress.add_task(f"Ingesting {label} file: {path.name}", total=None)
                async for result in ingestion_service.ingest_file(path, file_type=file_type):
                    totals["observations"] += (
                        len(result.endpoints)
                        + len(result.services)
                        + len(result.data_stores)
                    )
                    totals["services"] += len(result.services)
                    totals["datastores"] += len(result.data_stores)

                    findings = trust_service.analyze_normalization_result(result)
                    totals["findings"] += len(findings)

                    if graph_service:
                        stats = await graph_service.build_from_normalization_result(result)
                        totals["nodes"] += stats["nodes_created"]
                        totals["edges"] += stats["relationships_created"]

                progress.update(task, completed=True)
                success(f"Ingested {label} file: {path.name}")

        console.print("\n[bold]Ingestion Summary[/bold]")
        table = Table(show_header=False)
        table.add_row("Observed Entities", str(totals["observations"]))
        table.add_row("Services Inferred", str(totals["services"]))
        table.add_row("Data Stores Inferred", str(totals["datastores"]))
        table.add_row("Trust Findings", str(totals["findings"]))
        if build_graph:
            table.add_row("Graph Nodes", str(totals["nodes"]))
            table.add_row("Graph Edges", str(totals["edges"]))
        console.print(table)
    finally:
        if repo:
            await repo.close()


@app.command()
def analyze(
    ctx: typer.Context,
    persona: str = typer.Option("Unauthenticated Attacker", "--persona", "-p", help="Starting persona"),
    privilege: int = typer.Option(0, "--privilege", help="Starting privilege level (0-100)"),
    trust_zone: str = typer.Option("external", "--trust-zone", "-z", help="Starting trust zone"),
    target_type: str = typer.Option("DataStore", "--target-type", "-t", help="Target node label"),
    target_sensitivity: Optional[str] = typer.Option("confidential", "--target-sensitivity", "-s", help="Target sensitivity level"),
    target_trust_zone: Optional[str] = typer.Option(None, "--target-trust-zone", help="Filter target trust zone"),
    min_target_privilege: Optional[int] = typer.Option(None, "--min-target-privilege", help="Filter by minimum target privilege"),
    max_hops: Optional[int] = typer.Option(None, "--max-hops", help="Maximum path length"),
    max_paths: Optional[int] = typer.Option(None, "--max-paths", help="Maximum paths to find"),
    explain: bool = typer.Option(True, "--explain/--no-explain", help="Generate explanations for top paths"),
) -> None:
    config: ITGEConfig = ctx.obj
    try:
        asyncio.run(
            _analyze_async(
                config=config,
                persona=persona,
                privilege=privilege,
                trust_zone=trust_zone,
                target_type=target_type,
                target_sensitivity=target_sensitivity,
                target_trust_zone=target_trust_zone,
                min_target_privilege=min_target_privilege,
                max_hops=max_hops or config.default_max_hops,
                max_paths=max_paths or config.default_max_paths,
                explain=explain,
            )
        )
    except Exception as exc:
        handle_error(exc)


async def _analyze_async(
    config: ITGEConfig,
    persona: str,
    privilege: int,
    trust_zone: str,
    target_type: str,
    target_sensitivity: str | None,
    target_trust_zone: str | None,
    min_target_privilege: int | None,
    max_hops: int,
    max_paths: int,
    explain: bool,
) -> None:
    from ..application.services.attack_path_service import AttackPathSimulationService
    from ..application.services.explainability_service import ExplainabilityService
    from ..infrastructure.graph import GraphRepository

    info(f"Analyzing attack paths: {persona} -> {target_type}")
    repo = GraphRepository(config.neo4j_uri, config.neo4j_user, config.neo4j_password)

    try:
        with Progress(TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("Computing attack paths...", total=None)
            simulation_service = AttackPathSimulationService(repo)

            target_criteria: dict[str, object] = {"label": target_type}
            if target_sensitivity:
                target_criteria["sensitivity"] = target_sensitivity
            if target_trust_zone:
                target_criteria["trust_zone"] = target_trust_zone
            if min_target_privilege is not None:
                target_criteria["privilege"] = min_target_privilege

            result = await simulation_service.simulate_attack_paths(
                start_persona=persona,
                start_privilege=privilege,
                start_trust_zone=trust_zone,
                target_criteria=target_criteria,
                max_hops=max_hops,
                max_paths=max_paths,
            )
            progress.update(task, completed=True)

        success(f"Found {result.total_paths_found} attack paths")
        console.print("\n[bold]Analysis Summary[/bold]")
        table = Table(show_header=False)
        table.add_row("Total Paths", str(result.total_paths_found))
        table.add_row("Avg Path Length", f"{result.avg_path_length:.1f} steps")
        table.add_row("Avg Risk Score", f"{result.avg_risk_score:.2f}")
        table.add_row("Max Risk Score", f"{result.max_risk_score:.2f}")
        table.add_row("Boundary Crossings", str(result.paths_with_boundary_crossing))
        table.add_row("Privilege Escalations", str(result.paths_with_privilege_escalation))
        table.add_row("Computation Time", f"{result.computation_time_ms:.0f}ms")
        console.print(table)

        config.output_dir.mkdir(parents=True, exist_ok=True)
        output_file = config.output_dir / "analysis_result.json"
        output_file.write_text(json.dumps(result.model_dump(mode="json"), indent=2, default=str), encoding="utf-8")
        info(f"Results saved to: {output_file}")

        if explain and result.highest_risk_paths:
            explainability_service = ExplainabilityService()
            info("Generating explanations for top paths...")
            for index, path in enumerate(result.highest_risk_paths[:5], start=1):
                explanation = explainability_service.explain_path(path, result.paths)
                json_path = config.output_dir / f"explanation_path_{index}.json"
                md_path = config.output_dir / f"explanation_path_{index}.md"
                json_path.write_text(json.dumps(explanation.to_json_dict(), indent=2, default=str), encoding="utf-8")
                md_path.write_text(explanation.to_markdown(), encoding="utf-8")
            success(f"Explanations saved to: {config.output_dir}")
    finally:
        await repo.close()


@app.command("show-paths")
def show_paths(
    ctx: typer.Context,
    top: int = typer.Option(10, "--top", "-n", help="Number of top paths to show"),
    sort_by: str = typer.Option("risk", "--sort-by", help="Sort by: risk, length, crossings, escalations"),
) -> None:
    config: ITGEConfig = ctx.obj
    result_file = config.output_dir / "analysis_result.json"
    if not result_file.exists():
        error("No analysis results found. Run `itge analyze` first.")
        raise typer.Exit(1)

    try:
        data = json.loads(result_file.read_text(encoding="utf-8"))
        paths = data.get("paths", [])
        if not paths:
            warning("No paths found in results.")
            return

        sorters = {
            "risk": lambda item: item["risk_score"],
            "length": lambda item: item["path_length"],
            "crossings": lambda item: item["boundary_crossings"],
            "escalations": lambda item: item["privilege_escalations"],
        }
        if sort_by not in sorters:
            error(f"Unsupported sort field: {sort_by}")
            raise typer.Exit(1)
        paths.sort(key=sorters[sort_by], reverse=(sort_by != "length"))

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("#", style="dim", width=3)
        table.add_column("Target", style="cyan")
        table.add_column("Steps", justify="right")
        table.add_column("Risk", justify="right")
        table.add_column("Boundaries", justify="right")
        table.add_column("Escalations", justify="right")
        table.add_column("Value", style="bold")

        for index, path in enumerate(paths[:top], start=1):
            risk_color = "red" if path["risk_score"] >= 0.8 else "yellow" if path["risk_score"] >= 0.6 else "green"
            table.add_row(
                str(index),
                str(path["target_node_name"])[:48],
                str(path["path_length"]),
                f"[{risk_color}]{path['risk_score']:.2f}[/{risk_color}]",
                str(path["boundary_crossings"]),
                str(path["privilege_escalations"]),
                str(path["strategic_value"]),
            )

        console.print(f"\n[bold]Top {top} Attack Paths[/bold] (sorted by {sort_by})\n")
        console.print(table)
    except Exception as exc:
        handle_error(exc)


@app.command()
def export(
    ctx: typer.Context,
    format: str = typer.Option("json", "--format", "-f", help="Export format: json, markdown, csv"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    config: ITGEConfig = ctx.obj
    result_file = config.output_dir / "analysis_result.json"
    if not result_file.exists():
        error("No analysis results found. Run `itge analyze` first.")
        raise typer.Exit(1)

    try:
        data = json.loads(result_file.read_text(encoding="utf-8"))
        output = output or (config.output_dir / f"export.{format}")
        if format == "json":
            output.write_text(json.dumps(data, indent=2), encoding="utf-8")
        elif format == "markdown":
            _export_markdown(data, output)
        elif format == "csv":
            _export_csv(data, output)
        else:
            error(f"Unsupported format: {format}")
            raise typer.Exit(1)
        success(f"Exported analysis to: {output}")
    except Exception as exc:
        handle_error(exc)


def _export_markdown(data: dict, output: Path) -> None:
    lines = [
        "# ITGE Attack Path Analysis Report",
        "",
        f"**Persona**: {data['start_persona']}",
        f"**Total Paths**: {data['total_paths_found']}",
        f"**Avg Risk Score**: {data['avg_risk_score']:.2f}",
        "",
        "## Top Attack Paths",
        "",
    ]
    for index, path in enumerate(data.get("highest_risk_paths", [])[:10], start=1):
        lines.extend(
            [
                f"### Path {index}: {path['target_node_name']}",
                "",
                f"- Risk Score: {path['risk_score']:.2f}",
                f"- Path Length: {path['path_length']} steps",
                f"- Boundary Crossings: {path['boundary_crossings']}",
                f"- Privilege Escalations: {path['privilege_escalations']}",
                f"- Strategic Value: {path['strategic_value']}",
                "",
                path["summary"],
                "",
            ]
        )
    output.write_text("\n".join(lines), encoding="utf-8")


def _export_csv(data: dict, output: Path) -> None:
    with output.open("w", newline="", encoding="utf-8") as file_handle:
        writer = csv.writer(file_handle)
        writer.writerow(
            [
                "Rank",
                "Target",
                "Path Length",
                "Risk Score",
                "Boundary Crossings",
                "Privilege Escalations",
                "Strategic Value",
            ]
        )
        for index, path in enumerate(data.get("paths", []), start=1):
            writer.writerow(
                [
                    index,
                    path["target_node_name"],
                    path["path_length"],
                    f"{path['risk_score']:.2f}",
                    path["boundary_crossings"],
                    path["privilege_escalations"],
                    path["strategic_value"],
                ]
            )


@app.command("serve-api")
def serve_api(
    ctx: typer.Context,
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host"),
    port: int = typer.Option(8000, "--port", help="Bind port"),
) -> None:
    """Serve the optional FastAPI surface for automation/integration."""
    config: ITGEConfig = ctx.obj
    try:
        import uvicorn
        from ..api.main import create_app

        uvicorn.run(create_app(config), host=host, port=port, log_level=config.log_level.lower())
    except Exception as exc:
        handle_error(exc)


@app.command()
def doctor(ctx: typer.Context) -> None:
    """Run local preflight checks for a production launch."""
    config: ITGEConfig = ctx.obj
    try:
        asyncio.run(_doctor_async(config))
    except Exception as exc:
        handle_error(exc)


async def _doctor_async(config: ITGEConfig) -> None:
    from ..api.main import create_app
    from ..infrastructure.graph import GraphRepository

    checks: list[tuple[str, str]] = []

    config.output_dir.mkdir(parents=True, exist_ok=True)
    checks.append(("Output directory", f"OK: {config.output_dir.resolve()}"))

    app = create_app(config)
    checks.append(("API wiring", f"OK: {app.title}"))

    result_file = config.output_dir / "analysis_result.json"
    checks.append(
        (
            "Latest analysis artifact",
            "OK" if result_file.exists() else "WARN: no analysis_result.json yet",
        )
    )

    repo = GraphRepository(config.neo4j_uri, config.neo4j_user, config.neo4j_password)
    try:
        try:
            await repo.verify_connection()
            checks.append(("Neo4j connectivity", f"OK: {config.neo4j_uri}"))
        except Exception as exc:
            checks.append(("Neo4j connectivity", f"WARN: {exc}"))
    finally:
        await repo.close()

    table = Table(show_header=False)
    for name, status in checks:
        table.add_row(name, status)
    console.print("\n[bold]ITGE Doctor[/bold]\n")
    console.print(table)


@app.command("config")
def config_cmd(
    ctx: typer.Context,
    show: bool = typer.Option(False, "--show", help="Show current configuration"),
    set_neo4j_uri: Optional[str] = typer.Option(None, "--neo4j-uri", help="Set Neo4j URI"),
    set_neo4j_user: Optional[str] = typer.Option(None, "--neo4j-user", help="Set Neo4j username"),
    set_neo4j_password: Optional[str] = typer.Option(None, "--neo4j-password", help="Set Neo4j password"),
    save_to: Optional[Path] = typer.Option(None, "--save", help="Save configuration to file"),
) -> None:
    config: ITGEConfig = ctx.obj
    if set_neo4j_uri:
        config.neo4j_uri = set_neo4j_uri
        success(f"Neo4j URI set to: {set_neo4j_uri}")
    if set_neo4j_user:
        config.neo4j_user = set_neo4j_user
        success(f"Neo4j user set to: {set_neo4j_user}")
    if set_neo4j_password:
        config.neo4j_password = set_neo4j_password
        success("Neo4j password updated")
    if save_to:
        save_config(config, save_to)
        success(f"Configuration saved to: {save_to}")

    if show or not any([set_neo4j_uri, set_neo4j_user, set_neo4j_password, save_to]):
        table = Table(show_header=False)
        table.add_row("Neo4j URI", config.neo4j_uri)
        table.add_row("Neo4j User", config.neo4j_user)
        table.add_row("Neo4j Password", "***" if config.neo4j_password else "Not set")
        table.add_row("Log Level", config.log_level)
        table.add_row("Output Directory", str(config.output_dir))
        table.add_row("Default Max Hops", str(config.default_max_hops))
        table.add_row("Default Max Paths", str(config.default_max_paths))
        console.print("\n[bold]Current Configuration[/bold]\n")
        console.print(table)


if __name__ == "__main__":
    app()
