"""Configuration and bounded document-lab experiment commands."""

import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer

from temporal_auth.config import ConfigLoadError, TargetConfig, load_config
from temporal_auth.runner import run_experiment
from temporal_auth.oracles import analyze_run
from temporal_auth.replay import check_lab
from temporal_auth.replay.confirm import write_json
from temporal_auth.config.lifecycle import LifecycleConfig
from temporal_auth.generator import Scenario, generate_scenario
from temporal_auth.replay.minimize import minimize_check


def selected_scenario(config, path, seed, warmups):
    if not isinstance(config, LifecycleConfig):
        if path is not None or seed != 0 or not warmups:
            raise typer.BadParameter("Generated scenarios require schema_version 2.")
        return None
    try:
        if path is None:
            return generate_scenario(config, seed, warmups=warmups)
        if path.stat().st_size > 2_000_000:
            raise ValueError
        scenario = Scenario.model_validate_json(path.read_text(encoding="utf-8"))
        scenario.validate_for(config)
        return scenario
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise typer.BadParameter("Scenario file is unreadable or violates the configured action graph.") from None

app = typer.Typer(
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
    help="Test temporal authorization in the document lab and disposable native application pilots.",
)


@app.command()
def serve(
    port: Annotated[int, typer.Option("--port", min=1024, max=65535)] = 8080,
    data: Annotated[Path, typer.Option("--data", help="Private SQLite queue and web-job evidence directory.")] = Path("artifacts/workspace"),
    tools: Annotated[Path, typer.Option("--tools", help="Pinned native application binaries.")] = Path("artifacts/tools"),
    metrics_port: Annotated[int | None, typer.Option("--metrics-port", min=1024, max=65535,
        help="Opt in to the worker's loopback Prometheus exporter (normally 9464).")] = None,
) -> None:
    """Open the local experiment workspace with one separate worker."""
    try:
        import uvicorn
        from temporal_auth.web.app import create_app
    except ImportError:
        typer.echo("Install the web dependencies: python -m pip install -e '.[web]'", err=True)
        raise typer.Exit(2) from None
    if metrics_port is not None:
        if metrics_port == port:
            raise typer.BadParameter("Metrics and workspace need different ports.")
        try:
            import prometheus_client  # noqa: F401
        except ImportError:
            typer.echo("Install monitoring: python -m pip install -e '.[web,monitoring]'", err=True)
            raise typer.Exit(2) from None
        typer.echo(f"Worker metrics: http://127.0.0.1:{metrics_port}/metrics")
    typer.echo(f"Temporal Auth workspace: http://127.0.0.1:{port}")
    uvicorn.run(create_app(data, tools, metrics_port=metrics_port), host="127.0.0.1", port=port, workers=1,
                log_level="warning", access_log=False)


@app.command("external-check")
def external_check(
    target: Annotated[str, typer.Argument(help="gitea or pocketbase; starts a disposable local instance.")],
    tools: Annotated[Path, typer.Option("--tools", help="Directory containing pinned application binaries.")] = Path("artifacts/tools"),
    output: Annotated[Path, typer.Option("--output")] = Path("artifacts/external"),
    profile: Annotated[str, typer.Option("--profile", help="temporal, p4-single-event or generic-valid-order.")] = "temporal",
    seed: Annotated[int, typer.Option("--seed")] = 0,
    max_requests: Annotated[int, typer.Option("--max-requests", min=1)] = 500,
    max_runtime: Annotated[float, typer.Option("--max-runtime", min=1)] = 180,
) -> None:
    """Pilot a native read workflow in an empty, temporary application database."""
    from temporal_auth.integrations.pilot import run_pilot

    try:
        result = run_pilot(target, tools, output, profile=profile, seed=seed,
                           max_requests=max_requests, max_runtime_seconds=max_runtime)
    except ValueError:
        typer.echo("Unsupported target/profile or invalid budget.", err=True)
        raise typer.Exit(2) from None
    except OSError:
        typer.echo("Cannot read tools or write pilot evidence.", err=True)
        raise typer.Exit(2) from None
    except KeyboardInterrupt:
        typer.echo("Interrupted; partial evidence is retained.", err=True)
        raise typer.Exit(130) from None
    report = result.report
    typer.echo(f"Status: {report['status']}; verdict: {report['verdict']}.")
    typer.echo(f"Requests: {report['total_requests']} (readiness: {report['fixture_requests']}); clean reproductions: {report['reproductions']}/2.")
    typer.echo(f"Evidence: {result.directory}")
    if report["error"]:
        typer.echo(f"Reason: {report['error']}", err=True)
    if report["verdict"] == "confirmed_violation":
        raise typer.Exit(3)
    if report["verdict"] == "candidate":
        raise typer.Exit(4)
    if report["verdict"] != "no_violation_observed" or report["status"] != "completed":
        raise typer.Exit(1)


@app.command("native-evomaster")
def native_evomaster(
    target: Annotated[str, typer.Argument(help="gitea or pocketbase; disposable native API slice.")],
    tools: Annotated[Path, typer.Option("--tools")] = Path("artifacts/tools"),
    output: Annotated[Path, typer.Option("--output")] = Path("artifacts/native"),
    seed: Annotated[int, typer.Option("--seed")] = 0,
    seconds: Annotated[int, typer.Option("--seconds", min=1, max=60)] = 10,
) -> None:
    """Run EvoMaster's native security-enabled compatibility smoke test."""
    from temporal_auth.integrations.evomaster import run_evomaster

    try:
        report, directory = run_evomaster(target, tools, output, seed=seed, seconds=seconds)
    except (ValueError, OSError):
        typer.echo("Unsupported target, missing tools or unwritable evidence directory.", err=True)
        raise typer.Exit(2) from None
    except KeyboardInterrupt:
        typer.echo("Interrupted; partial native evidence is retained.", err=True)
        raise typer.Exit(130) from None
    typer.echo(f"Native tool status: {report['status']}; authorization verdict: not_evaluated.")
    typer.echo(f"Total requests including setup/readiness: {report['total_requests']}.")
    typer.echo(f"Evidence: {directory}")
    if report["status"] != "completed":
        raise typer.Exit(1)


@app.command("native-restler")
def native_restler(
    target: Annotated[str, typer.Argument(help="gitea or pocketbase; disposable native API slice.")],
    tools: Annotated[Path, typer.Option("--tools")] = Path("artifacts/tools"),
    output: Annotated[Path, typer.Option("--output")] = Path("artifacts/native"),
    seed: Annotated[int, typer.Option("--seed")] = 0,
) -> None:
    """Run RESTler's actual compiler, namespace checker and deletion checker."""
    from temporal_auth.integrations.restler import run_restler

    try:
        report, directory = run_restler(target, tools, output, seed=seed)
    except (ValueError, OSError):
        typer.echo("Unsupported target or unwritable evidence directory.", err=True)
        raise typer.Exit(2) from None
    except KeyboardInterrupt:
        typer.echo("Interrupted; partial native evidence is retained.", err=True)
        raise typer.Exit(130) from None
    typer.echo(f"Native tool status: {report['status']}; authorization verdict: not_evaluated.")
    typer.echo(f"Total requests including setup/readiness: {report['total_requests']}.")
    typer.echo(f"Evidence: {directory}")
    if report["status"] != "completed":
        raise typer.Exit(1)


@app.command()
def validate(path: Annotated[Path, typer.Argument(help="Path to a YAML target configuration.")]) -> None:
    """Validate policy, references and budgets without making network requests."""
    try:
        config = load_config(path)
    except ConfigLoadError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None
    typer.echo(f"Valid configuration: {config.name}")
    if config.policy.timing.mode == "unknown":
        typer.echo("Timing policy is unknown: temporal checks must be inconclusive.")
    else:
        timing = config.policy.timing
        typer.echo(
            f"Revocation bound: {timing.max_delay_seconds:g}s after acknowledgement; "
            f"probe tolerance: {timing.tolerance_seconds:g}s."
        )
    typer.echo("Configuration validation only; no application was contacted or tested.")


@app.command()
def schema(version: Annotated[int, typer.Option("--version", min=1, max=2)] = 1) -> None:
    """Print the selected configuration JSON Schema (default version 1)."""
    model = LifecycleConfig if version == 2 else TargetConfig
    typer.echo(json.dumps(model.model_json_schema(), indent=2))


@app.command()
def run(
    path: Annotated[Path, typer.Argument(help="YAML configuration using the document-lab API contract.")],
    output: Annotated[Path, typer.Option("--output", help="Parent directory for a new evidence directory per run.")] = Path("artifacts"),
    scenario: Annotated[Path | None, typer.Option("--scenario")] = None,
    seed: Annotated[int, typer.Option("--seed")] = 0,
    warmups: Annotated[bool, typer.Option("--warmups/--no-warmups")] = True,
) -> None:
    """Execute one sharing-revocation workflow and save observations; no verdict."""
    try:
        config = load_config(path)
    except ConfigLoadError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None
    plan = selected_scenario(config, scenario, seed, warmups)
    typer.echo("Collecting the document-lab workflow; security verdict is not evaluated.")
    try:
        result = asyncio.run(run_experiment(config, output, scenario=plan))
    except KeyboardInterrupt:
        typer.echo(f"Interrupted. Partial evidence, if created, is under {output}.", err=True)
        raise typer.Exit(code=130) from None
    except OSError:
        typer.echo(f"Cannot create or write evidence under {output}.", err=True)
        raise typer.Exit(code=2) from None
    typer.echo(f"Workflow status: {result.report.status}; requests attempted: {result.report.request_count}.")
    typer.echo(f"Evidence: {result.directory}")
    typer.echo("Security verdict: not_evaluated (use analyze or check to evaluate evidence).")
    if result.report.error_code:
        typer.echo(f"Reason: {result.report.error_code}", err=True)
        if result.report.error_code == "missing_credentials":
            typer.echo("Set the password environment variables named in the configuration.", err=True)
    if result.report.status != "completed":
        raise typer.Exit(code=1)


@app.command()
def analyze(
    path: Annotated[Path, typer.Argument(help="Original YAML configuration.")],
    evidence: Annotated[Path, typer.Argument(exists=True, file_okay=False, help="One run directory containing run.json and events.jsonl.")],
) -> None:
    """Evaluate stored observations without network requests; cannot confirm."""
    try:
        config = load_config(path)
    except ConfigLoadError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None
    analysis = analyze_run(config, evidence)
    try:
        write_json(evidence / "analysis.json", analysis)
    except OSError:
        typer.echo("Cannot write derived analysis.", err=True)
        raise typer.Exit(code=2) from None
    typer.echo(f"Verdict: {analysis.verdict}; reason: {analysis.reason}.")
    if analysis.kind:
        typer.echo(f"Finding kind: {analysis.kind} (requires two clean replays).")
    if analysis.verdict != "no_violation_observed":
        raise typer.Exit(code=4 if analysis.verdict == "candidate" else 1)


@app.command()
def check(
    path: Annotated[Path, typer.Argument(help="YAML configuration of the dedicated document lab.")],
    output: Annotated[Path, typer.Option("--output")] = Path("artifacts"),
    reset_key_env: Annotated[str, typer.Option("--reset-key-env", help="Environment variable holding the lab fixture reset key.")] = "LAB_RESET_KEY",
    scenario: Annotated[Path | None, typer.Option("--scenario")] = None,
    seed: Annotated[int, typer.Option("--seed")] = 0,
    warmups: Annotated[bool, typer.Option("--warmups/--no-warmups")] = True,
) -> None:
    """Reset the dedicated lab, evaluate discovery, and clean-replay candidates twice."""
    try:
        config = load_config(path)
    except ConfigLoadError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None
    plan = selected_scenario(config, scenario, seed, warmups)
    typer.echo("Checking the dedicated lab: its fixture is reset before each attempt; all attempts share one budget.")
    try:
        result = asyncio.run(check_lab(config, output, reset_key_env=reset_key_env, scenario=plan))
    except KeyboardInterrupt:
        typer.echo(f"Interrupted; partial check evidence, if created, is under {output}.", err=True)
        raise typer.Exit(code=130) from None
    except OSError:
        typer.echo(f"Cannot create or write evidence under {output}.", err=True)
        raise typer.Exit(code=2) from None
    report = result.report
    typer.echo(f"Verdict: {report.verdict}; confirmation: {report.confirmation}.")
    typer.echo(f"Clean reproductions: {report.reproductions}/2; total requests including resets: {report.total_requests}.")
    typer.echo(f"Evidence: {result.directory}")
    if report.error_code:
        typer.echo(f"Reason: {report.error_code}", err=True)
    if report.verdict == "confirmed_violation":
        raise typer.Exit(code=3)
    if report.verdict == "candidate":
        raise typer.Exit(code=4)
    if report.verdict != "no_violation_observed":
        raise typer.Exit(code=1)


@app.command()
def plan(
    path: Annotated[Path, typer.Argument(help="Version-two lifecycle configuration.")],
    seed: Annotated[int, typer.Option("--seed")] = 0,
    warmups: Annotated[bool, typer.Option("--warmups/--no-warmups")] = True,
) -> None:
    """Print a dependency-valid seeded scenario; no network activity."""
    try:
        config = load_config(path)
    except ConfigLoadError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None
    if not isinstance(config, LifecycleConfig):
        raise typer.BadParameter("Plan generation requires schema_version 2.")
    typer.echo(generate_scenario(config, seed, warmups=warmups).model_dump_json(indent=2))


@app.command()
def minimize(
    path: Annotated[Path, typer.Argument(help="Original version-two configuration.")],
    source: Annotated[Path, typer.Argument(exists=True, file_okay=False, help="A confirmed check directory.")],
    output: Annotated[Path, typer.Option("--output")] = Path("artifacts"),
    reset_key_env: Annotated[str, typer.Option("--reset-key-env")] = "LAB_RESET_KEY",
) -> None:
    """Try dependency-preserving deletions; each accepted reduction is clean-confirmed."""
    try:
        config = load_config(path)
    except ConfigLoadError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None
    typer.echo("Minimizing on the dedicated lab: each trial resets the fixture; trials share one search budget.")
    try:
        report, directory = asyncio.run(minimize_check(config, source, output, reset_key_env=reset_key_env))
    except KeyboardInterrupt:
        typer.echo(f"Interrupted; partial reduction evidence is under {output}.", err=True)
        raise typer.Exit(code=130) from None
    except (OSError, ValueError):
        typer.echo("Invalid source confirmation/scenario, or evidence could not be read/written.", err=True)
        raise typer.Exit(code=2) from None
    typer.echo(f"Actions: {report.original_actions} -> {report.smallest_verified_actions}; status: {report.status}.")
    typer.echo(f"Search requests: {report.total_requests}; evidence: {directory}")
    if report.status != "completed":
        raise typer.Exit(code=1)
