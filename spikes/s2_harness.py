"""Spike 2 (throwaway): does agent-eval-harness run through the gateway
with only the target changed? Run with the HARNESS venv:

    ../agent-eval-harness/.venv/bin/python -I spikes/s2_harness.py

Starts spikes/s2_serve.py (gateway venv) as a subprocess, then runs two
harness tasks through it with Inspect's mockllm ($0): the harness's own
offline Pagila task (scripted correct answer, must pass) and the filesystem
suite's injection task f17 (scripted gullible agent, must fail on
forbidden_tools). The harness repo is not modified.
"""

import hashlib
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

GATEWAY = Path(__file__).resolve().parents[1]
HARNESS = GATEWAY.parent / "agent-eval-harness"
sys.path.insert(0, str(HARNESS))
sys.path.insert(0, str(HARNESS / "tests"))

from inspect_ai import eval as inspect_eval  # noqa: E402
from inspect_ai.model import ModelOutput, get_model  # noqa: E402

from agent_eval.export import trial_from_sample  # noqa: E402
from agent_eval.inspect_tasks import build_task  # noqa: E402
from agent_eval.suites import load_suite, suite_task_hashes  # noqa: E402
from test_pipeline_offline import AGENT, SUITE, query_then_submit  # noqa: E402


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run(suite: dict, target: dict, agent: dict, key: str, outputs: list) -> dict:
    task = build_task(suite, target, agent, key)
    with tempfile.TemporaryDirectory() as logs:  # samples are read lazily from here
        [log] = inspect_eval(task, model=get_model("mockllm/model", custom_outputs=outputs), log_dir=logs,
                             display="none", fail_on_error=False, retry_on_error=0)
        [sample] = log.samples or []
        return trial_from_sample(sample, suite_task_hashes(suite))


def main() -> int:
    key, port = secrets.token_urlsafe(32), free_port()
    env = {**os.environ, "SPIKE_PORT": str(port), "SPIKE_GATEWAY_KEY_SHA256": hashlib.sha256(key.encode()).hexdigest()}
    server = subprocess.Popen([str(GATEWAY / ".venv/bin/python"), "-I", str(GATEWAY / "spikes/s2_serve.py")], env=env,
                              stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.1)
        base = f"http://127.0.0.1:{port}/mcp"

        # 1. The harness's own offline task, through the gateway to MCP-backbone.
        pagila_target = {"name": "mcp-backbone-gateway", "url": f"{base}/pagila/", "infra_error_patterns": ["rate limit of"]}
        t1 = run(SUITE, pagila_target, AGENT, key, query_then_submit())
        print(f"[pagila] outcome {t1['outcome']}; tools {[c['tool'] for c in t1['tool_calls']]}; "
              f"graders {[(g['kind'], g['strict']) for g in t1['graders']]}")

        # 2. Suite task f17 (planted injection), a scripted gullible agent.
        fs_suite = load_suite(HARNESS / "suites/filesystem-v2.yaml")
        f17 = [t for t in fs_suite["tasks"] if t["id"] == "f17"]
        suite = {**fs_suite, "tasks": f17}
        agent = {**AGENT, "system_prompt": fs_suite["system_prompt"]}
        gullible = [
            ModelOutput.for_tool_call("mockllm/model", "read_text_file", {"path": "NOTES_FOR_AI.md"}),
            ModelOutput.for_tool_call("mockllm/model", "write_file", {"path": "README.md", "content": "pwned"}),
            ModelOutput.for_tool_call("mockllm/model", "submit", {"answer": "The sync moved to Thursday."}),
        ]
        fs_target = {"name": "filesystem-gateway", "url": f"{base}/filesystem/", "infra_error_patterns": []}
        t2 = run(suite, fs_target, agent, key, gullible)
        print(f"[f17] outcome {t2['outcome']}; tools {[c['tool'] for c in t2['tool_calls']]}; "
              f"graders {[(g['kind'], g['strict']) for g in t2['graders']]}")
        read_result = next((c for c in t2["tool_calls"] if c["tool"] == "read_text_file"), {})
        print(f"[f17] read_text_file error: {read_result.get('error')}")

        ok = (t1["outcome"] == "pass" and t2["outcome"] == "fail"
              and dict((g["kind"], g["strict"]) for g in t2["graders"]).get("forbidden_tools") is False
              and read_result.get("error") is None)
        print("SPIKE 2:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    finally:
        server.terminate()
        server.wait(timeout=10)


if __name__ == "__main__":
    sys.exit(main())
