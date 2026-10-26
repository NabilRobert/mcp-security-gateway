"""The $0 end-to-end measurement (ADR-008): the harness's scripted gullible
agent runs the attack suite through this gateway, once per configuration,
and the results are checked against the prediction committed beforehand.

Configurations (same suite, same agent, only the gateway's settings differ):
- gateway-off: detection off, every filesystem tool allowed;
- gateway-on: rules + model (threshold 0.999), every tool allowed;
- policy-only: detection off, a read-only allow-list (least privilege).

Each run gets a fresh one-time key (never printed), its own audit log, and
a per-session filesystem upstream (ADR-010), so one trial's writes can't
reach the next.

    .venv/bin/python -I scripts/measure_gullible.py
"""

import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT.parent / "agent-eval-harness-gateway"
FIXTURE = HARNESS / "suites" / "fixtures" / "acme-shop-attacks"
MODEL = ROOT / "models/protectai-deberta-v3-base-prompt-injection-v2/90c9989b1a342275dd0d1a95aad283c04e075671"
OUT = ROOT / "eval" / "results" / "gullible"
PORT = 8080  # the harness's gateway targets point here
READ_TOOLS = ["read_file", "read_text_file", "read_media_file", "read_multiple_files", "list_directory",
              "list_directory_with_sizes", "directory_tree", "search_files", "get_file_info", "list_allowed_directories"]
WRITE_TOOLS = ["write_file", "edit_file", "create_directory", "move_file"]

CONFIGURATIONS: dict[str, dict[str, Any]] = {
    "gateway-off": {"detector": {"rules": False}, "tools": READ_TOOLS + WRITE_TOOLS},
    "gateway-on": {
        "detector": {"rules": True, "model": {"dir": str(MODEL), "threshold": 0.999, "timeout_s": 2.0}},
        "tools": READ_TOOLS + WRITE_TOOLS,
    },
    "policy-only": {"detector": {"rules": False}, "tools": READ_TOOLS},
}


def config_for(name: str, key: str) -> dict[str, Any]:
    spec = CONFIGURATIONS[name]
    return {
        "upstreams": {
            "attack-files": {
                "transport": "stdio",
                # The harness's own launcher copies the fixture per process.
                "command": sys.executable,
                "args": ["-m", "agent_eval.fs_server", str(FIXTURE)],
                "cwd": str(HARNESS),
                "per_session": True,
            }
        },
        "callers": {"harness": {"key_sha256": hashlib.sha256(key.encode()).hexdigest(), "policy": "measure"}},
        "policies": {"measure": {"routes": {"attack-files": {"tools": {t: {} for t in spec["tools"]}}}}},
        "detector": spec["detector"],
        "audit": {"path": str(OUT / name / "audit.jsonl"), "fsync": True},
    }


def wait_healthy(timeout_s: float = 60) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/healthz", timeout=2) as response:  # noqa: S310
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.2)
    raise SystemExit("the gateway didn't become healthy")


def run(name: str) -> list[dict[str, Any]]:
    key = secrets.token_urlsafe(32)
    run_dir = OUT / name
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "audit.jsonl").unlink(missing_ok=True)
    config_path = run_dir / "gateway.yaml"
    config_path.write_text(yaml.safe_dump(config_for(name, key), sort_keys=False))
    gateway = subprocess.Popen(
        [str(ROOT / ".venv/bin/mcp-gateway"), "serve", "--config", str(config_path), "--port", str(PORT)],
        stderr=(run_dir / "gateway.stderr").open("w"),
    )
    try:
        wait_healthy()
        result = subprocess.run(
            ["uv", "run", "--directory", str(HARNESS), "python", "scripts/gullible_agent.py",
             "--target", "filesystem-attacks-gateway", "--json", str(run_dir / "results.json")],
            env={**os.environ, "MCP_GATEWAY_KEY": key}, capture_output=True, text=True, timeout=600, check=False,
        )
        print(result.stdout.strip().splitlines()[-1] if result.stdout.strip() else result.stderr[-2000:])
    finally:
        gateway.terminate()
        gateway.wait(timeout=30)
    verify = subprocess.run([str(ROOT / ".venv/bin/mcp-gateway"), "verify-log", str(run_dir / "audit.jsonl")],
                            capture_output=True, text=True, check=False)
    print(f"  audit log: {verify.stdout.strip().splitlines()[-1]}")
    return json.loads((run_dir / "results.json").read_text())


def main() -> int:
    prediction = {t["task"]: t for t in json.loads((OUT / "prediction.json").read_text())["tasks"]}
    summary: dict[str, Any] = {}
    for name in CONFIGURATIONS:
        print(f"== {name}")
        rows = run(name)
        summary[name] = {
            "attacks_succeeded": sum(r["attack_succeeded"] for r in rows),
            "attacks_with_effect": sum(r["attack_effect"] for r in rows),
            "answered": sum(r["answered"] for r in rows),
            "tasks": len(rows),
            "per_task": {
                r["task"]: {"attack_succeeded": r["attack_succeeded"], "attack_effect": r["attack_effect"],
                            "answered": r["answered"]}
                for r in rows
            },
        }
    on = summary["gateway-on"]["per_task"]
    mismatches = [t for t, p in prediction.items() if on[t]["attack_succeeded"] != p["predicted_attack_succeeds"]]
    summary["gateway-on matches the prediction"] = not mismatches
    summary["mismatches"] = mismatches
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    for name in CONFIGURATIONS:
        s = summary[name]
        print(f"{name:12} attacks obeyed {s['attacks_succeeded']}/{s['tasks']}, with effect "
              f"{s['attacks_with_effect']}/{s['tasks']}, questions answered {s['answered']}/{s['tasks']}")
    print("gateway-on matches the prediction" if not mismatches else f"MISMATCH with the prediction: {mismatches}")
    return 0 if not mismatches else 1


if __name__ == "__main__":
    sys.exit(main())
