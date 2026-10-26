"""`mcp-gateway serve | hash-key | verify-log`. Exit codes: 0 ok, 1 the log
doesn't verify, 2 the gateway can't start (bad config, unreachable upstream)."""

import argparse
import asyncio
import sys
from pathlib import Path

from mcp_gateway.app import serve
from mcp_gateway.audit import AuditError, verify_chain
from mcp_gateway.auth import new_key
from mcp_gateway.config import ConfigError, load_config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-gateway")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("serve", help="run the gateway")
    run.add_argument("--config", type=Path, required=True)
    run.add_argument("--host", default="127.0.0.1")
    run.add_argument("--port", type=int, default=8080)
    commands.add_parser("hash-key", help="make a new caller key and print it with its hash")
    verify = commands.add_parser("verify-log", help="check an audit log's hash chain")
    verify.add_argument("path", type=Path)
    args = parser.parse_args(argv)

    if args.command == "hash-key":
        key, digest = new_key()
        print(f"key (give it to the caller; it is not stored anywhere): {key}")
        print(f"key_sha256 (put this in the config): {digest}")
        return 0
    if args.command == "verify-log":
        problems = verify_chain(args.path)
        for problem in problems:
            print(problem)
        print("ok" if not problems else f"{len(problems)} problem(s)")
        return 1 if problems else 0
    try:
        asyncio.run(serve(load_config(args.config), host=args.host, port=args.port))
    except (ConfigError, AuditError) as exc:
        print(f"mcp-gateway: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
