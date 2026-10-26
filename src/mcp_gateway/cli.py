"""`mcp-gateway serve | hash-key | verify-log`, on Typer.

Exit codes: 0 ok, 1 the log doesn't verify, 2 the gateway can't start (bad
config, unreachable upstream). Options can also come from `MCP_GATEWAY_*`
environment variables.
"""

import asyncio
from pathlib import Path
from typing import Annotated

import typer

from mcp_gateway.app import serve as serve_gateway
from mcp_gateway.audit import AuditError, verify_chain
from mcp_gateway.auth import new_key
from mcp_gateway.config import ConfigError, load_config

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
    """Check an audit log's hash chain."""
    problems = verify_chain(path)
    for problem in problems:
        typer.echo(problem)
    typer.echo("ok" if not problems else f"{len(problems)} problem(s)")
    if problems:
        raise typer.Exit(1)


def main() -> None:
    app()
