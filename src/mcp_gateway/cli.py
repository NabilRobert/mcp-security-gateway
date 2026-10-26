"""`mcp-gateway serve | hash-key | verify-log`, on Typer.

Exit codes: 0 ok, 1 the log doesn't verify, 2 the gateway can't start (bad
config, unreachable upstream). Options can also come from `MCP_GATEWAY_*`
environment variables.
"""

import asyncio
import json
from dataclasses import asdict
from pathlib import Path
from typing import Annotated

import typer

from mcp_gateway.app import build_detector
from mcp_gateway.app import serve as serve_gateway
from mcp_gateway.audit import AuditError
from mcp_gateway.audit import verify_log as check_log
from mcp_gateway.auth import new_key
from mcp_gateway.config import ConfigError, DetectorSettings, ModelSettings, load_config
from mcp_gateway.eval.score import load_samples, record_test_score, score

app = typer.Typer(add_completion=False, no_args_is_help=True, help="A small, measured security gateway for MCP.")


@app.command()
def serve(
    config: Annotated[Path, typer.Option(envvar="MCP_GATEWAY_CONFIG", help="the gateway's YAML config")],
    host: Annotated[str, typer.Option(envvar="MCP_GATEWAY_HOST")] = "127.0.0.1",
    port: Annotated[int, typer.Option(envvar="MCP_GATEWAY_PORT")] = 8080,
) -> None:
    """Run the gateway."""
    try:
        asyncio.run(serve_gateway(load_config(config), host=host, port=port))
    except (ConfigError, AuditError) as exc:
        typer.echo(f"mcp-gateway: {exc}", err=True)
        raise typer.Exit(2) from exc


@app.command("hash-key")
def hash_key() -> None:
    """Make a new caller key and print it with its hash."""
    key, digest = new_key()
    typer.echo(f"key (give it to the caller; it is not stored anywhere): {key}")
    typer.echo(f"key_sha256 (put this in the config): {digest}")


@app.command("verify-log")
def verify_log(path: Path) -> None:
    """Check an audit log's hash chain. Exit 1 if it was altered."""
    report = check_log(path)
    for line in report.problems + report.recoveries + report.unfinished_calls:
        typer.echo(line)
    if report.problems:
        typer.echo(f"{len(report.problems)} problem(s) in {report.lines} lines: the log was altered")
        raise typer.Exit(1)
    typer.echo(f"ok: {report.lines} lines, chain intact")


@app.command("eval-detector")
def eval_detector(
    split: Annotated[str, typer.Option(help="dev to tune; test is scored once per detector version")] = "dev",
    rules: Annotated[bool, typer.Option(help="use the rules layer")] = True,
    model_dir: Annotated[Path | None, typer.Option(help="the model's directory; omit for rules only")] = None,
    threshold: Annotated[float, typer.Option()] = 0.999,
    max_windows: Annotated[int, typer.Option()] = 16,
    timeout: Annotated[float, typer.Option(help="seconds per output before failing closed")] = 2.0,
    root: Annotated[Path, typer.Option(help="the repo root (eval/ lives there)")] = Path(),
) -> None:
    """Score the detector on the labelled set, offline (no model calls)."""
    if split not in ("dev", "test"):
        raise typer.BadParameter("split must be dev or test")
    settings = DetectorSettings(
        rules=rules,
        model=ModelSettings(dir=model_dir, threshold=threshold, max_windows=max_windows, timeout_s=timeout)
        if model_dir
        else None,
    )
    detector = build_detector(settings)
    samples = load_samples(root, "dev" if split == "dev" else "test")
    result = asyncio.run(score(detector, samples, split))
    typer.echo(json.dumps(asdict(result), indent=2, ensure_ascii=False))
    if split == "test":
        typer.echo(f"recorded: {record_test_score(root, result)}")


def main() -> None:
    app()
