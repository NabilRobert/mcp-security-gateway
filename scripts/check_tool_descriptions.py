"""Does tool-description scanning hide any real tool? $0: the classifier runs
locally.

Lists the tools of both real upstreams (the harness's local MCP-backbone
and the pinned filesystem server) through the gateway with rules + model
on, and reads the audit log for `tool_flagged` lines. A benign tool that
gets hidden is a false positive the agent can't work around, so this
should be zero.

    .venv/bin/python -I scripts/check_tool_descriptions.py
"""

import asyncio
import json
import os
import secrets
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import measure_overhead as mo  # noqa: E402  (gateway config and runner)
import recorded_calls as s1  # noqa: E402

OUT = ROOT / "eval" / "results" / "tool-descriptions"


async def main() -> int:
    work = Path(os.path.realpath(tempfile.mkdtemp(prefix="tool-descriptions-")))
    fixture = work / s1.FIXTURE.name
    shutil.copytree(s1.FIXTURE, fixture)
    key = secrets.token_urlsafe(32)
    config_path = work / "gateway.yaml"
    config_path.write_text(
        yaml.safe_dump(mo.gateway_config(key, fixture, mo.DETECTORS["rules + model"], work / "audit.jsonl"))
    )
    base = f"http://127.0.0.1:{mo.PORT}/mcp"
    summary: dict[str, Any] = {"detector": "rules + model (fp32, threshold 0.999, 2 s timeout)"}
    try:
        with mo.running_gateway(config_path, s1.local_backbone_key()):
            async with (
                s1.http_client(f"{base}/pagila/", key) as via_pagila,
                s1.http_client(f"{base}/files/", key) as via_fs,
            ):
                for route, client, allowed in (
                    ("pagila", via_pagila, mo.BACKBONE_TOOLS),
                    ("files", via_fs, mo.FS_TOOLS),
                ):
                    shown = {t.name for t in (await client.session.list_tools()).tools}
                    summary[route] = {
                        "allowed": len(allowed),
                        "shown": len(shown),
                        "hidden": sorted(set(allowed) - shown),
                    }
        lines = [json.loads(line) for line in (work / "audit.jsonl").read_text().splitlines()]
    finally:
        shutil.rmtree(work, ignore_errors=True)
    summary["tool_flagged"] = [
        {k: line[k] for k in ("route", "tool") if k in line} for line in lines if line.get("kind") == "tool_flagged"
    ]
    print(json.dumps(summary, indent=2))
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
