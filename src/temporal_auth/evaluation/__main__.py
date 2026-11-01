"""python -m temporal_auth.evaluation: freeze, run, analyze a source artifact."""

import asyncio
from pathlib import Path
from typing import Annotated

import typer

from temporal_auth.evaluation.analysis import analyze, markdown
from temporal_auth.evaluation.campaign import run_campaign
from temporal_auth.evaluation.protocol import freeze, load_protocol

app = typer.Typer(no_args_is_help=True, pretty_exceptions_show_locals=False)
DEFAULT_ROOT = Path(__file__).resolve().parents[3]


@app.command("freeze")
def freeze_command(
    destination: Annotated[Path, typer.Argument(help="New protocol file; existing freezes are never overwritten.")],
    root: Annotated[Path, typer.Option("--root", help="Source checkout containing examples, tests and target code.")] = DEFAULT_ROOT,
):
    try: protocol = freeze(root, destination)
    except (OSError, ValueError) as error:
        typer.echo(f"Cannot freeze protocol: {error}", err=True); raise typer.Exit(2) from None
    typer.echo(f"Frozen protocol: {protocol['protocol_sha256']}")


@app.command("run")
def run_command(
    protocol_path: Annotated[Path, typer.Argument()],
    output: Annotated[Path, typer.Option("--output")],
    track: Annotated[str, typer.Option("--track")] = "all",
    root: Annotated[Path, typer.Option("--root")] = DEFAULT_ROOT,
    tools: Annotated[Path | None, typer.Option("--tools")] = None,
):
    try:
        protocol = load_protocol(protocol_path, root)
        asyncio.run(run_campaign(root, protocol, output, track=track, tools=tools))
    except (OSError, ValueError) as error:
        typer.echo(f"Campaign stopped: {error}", err=True); raise typer.Exit(2) from None
    except KeyboardInterrupt: raise typer.Exit(130) from None


@app.command("analyze")
def analyze_command(
    protocol_path: Annotated[Path, typer.Argument()],
    output: Annotated[Path, typer.Option("--output")],
    root: Annotated[Path, typer.Option("--root")] = DEFAULT_ROOT,
):
    try:
        protocol = load_protocol(protocol_path, root)
        report = analyze(protocol, output)
        (output / "report.md").write_text(markdown(report))
    except (OSError, ValueError) as error:
        typer.echo(f"Analysis rejected: {error}", err=True); raise typer.Exit(2) from None
    typer.echo(f"Analysis saved; all frozen rows recorded: {report['all_frozen_rows_recorded']}")
    if not report["all_frozen_rows_recorded"]: raise typer.Exit(1)


if __name__ == "__main__": app()
