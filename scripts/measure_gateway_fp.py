"""False positives *through the gateway* on the held-out benign outputs. $0.

The offline test score reads stored output text. The gateway reads the live
result: text blocks plus structured content, under a real timeout, with
scans queued one at a time. This measures that path: every benign output in
the test split (unique by text, the same hash as the offline split) has
its recorded call (the labelled set keeps the tool and arguments) replayed
through the gateway to the real upstream. A call counts as blocked when the
agent gets the gateway's "withheld" notice, whether the detector flagged it
or timed out.

The result is refused if the upstream rate-limited any call (MCP-backbone's
limit is per workspace per hour): a refusal is not the output that was
labelled.

    .venv/bin/python -I scripts/measure_gateway_fp.py
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
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "spikes"))
import measure_overhead as mo  # noqa: E402  (gateway config and runner)
import s1_transparency as s1  # noqa: E402

from mcp_gateway.eval.split import benign_split  # noqa: E402
from mcp_gateway.proxy import text_of  # noqa: E402

OUT = ROOT / "eval" / "results" / "gateway-fp"
NOTICE = "The gateway withheld this tool output"
ROUTES = {"pagila": "pagila", "filesystem": "files"}


async def main() -> int:
    rows = [json.loads(line) for line in (ROOT / "eval/benign/outputs.jsonl").read_text().splitlines()]
    held_out: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row["label"] == "benign" and benign_split(row["text"]) == "test":
            held_out.setdefault(row["text"], row)  # unique by text
    backbone_key = s1.local_backbone_key()
    work = Path(os.path.realpath(tempfile.mkdtemp(prefix="gateway-fp-")))
    fixture = work / s1.FIXTURE.name
    shutil.copytree(s1.FIXTURE, fixture)
    key = secrets.token_urlsafe(32)
    detector = mo.DETECTORS["rules + model"]
    config_path = work / "gateway.yaml"
    config_path.write_text(yaml.safe_dump(mo.gateway_config(key, fixture, detector, work / "audit.jsonl")))
    base = f"http://127.0.0.1:{mo.PORT}/mcp"
    counts: dict[str, dict[str, int]] = {
        r: {"benign_outputs": 0, "blocked": 0, "rate_limited": 0} for r in ROUTES.values()
    }
    try:
        with mo.running_gateway(config_path, backbone_key):
            async with (
                s1.http_client(f"{base}/pagila/", key) as via_pagila,
                s1.http_client(f"{base}/files/", key) as via_fs,
            ):
                via = {"pagila": via_pagila, "files": via_fs}
                for row in held_out.values():
                    route = ROUTES[row["source"]]
                    args = json.loads(json.dumps(row["arguments"]).replace("<fixture>", str(fixture)))
                    text = text_of(await via[route].session.call_tool(row["tool"], args))
                    if mo.RATE_LIMITED in text:
                        counts[route]["rate_limited"] += 1
                        continue
                    counts[route]["benign_outputs"] += 1
                    counts[route]["blocked"] += text.startswith(NOTICE)
        decisions = mo.decision_counts(work / "audit.jsonl")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    limited = sum(c["rate_limited"] for c in counts.values())
    summary: dict[str, Any] = {"detector": "rules + model (fp32, threshold 0.999, 2 s timeout, scan s2)"}
    for route, c in counts.items():
        summary[route] = {
            **c,
            "false_positive_rate": round(c["blocked"] / c["benign_outputs"], 4) if c["benign_outputs"] else None,
        }
    total = sum(c["benign_outputs"] for c in counts.values())
    blocked = sum(c["blocked"] for c in counts.values())
    summary["all"] = {"benign_outputs": total, "blocked": blocked, "false_positive_rate": round(blocked / total, 4)}
    summary["gateway_decisions"] = decisions
    print(json.dumps(summary, indent=2))
    if limited:
        print(f"REFUSED: {limited} calls were rate-limited by the upstream; rerun after its hourly window resets.")
        return 1
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
