"""Slice B: a config mistake fails at start, loudly, instead of silently
loosening a policy."""

import hashlib
from pathlib import Path
from typing import Any

import pytest
import yaml
from conftest import FakeUpstream, in_memory, make_config, running_gateway

from mcp_gateway.cli import main
from mcp_gateway.config import ConfigError, load_config


def write(tmp_path: Path, data: dict[str, Any]) -> Path:
    path = tmp_path / "gateway.yaml"
    path.write_text(yaml.safe_dump(data))
    return path


def base(tmp_path: Path) -> dict[str, Any]:
    return make_config(tmp_path).model_dump(mode="json")


def test_a_valid_config_loads(tmp_path: Path) -> None:
    assert load_config(write(tmp_path, base(tmp_path))).callers.keys() == {"alpha", "bravo"}


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda c: c["policies"]["reader"].update(rotues={}), "Extra inputs"),
        (lambda c: c["policies"]["reader"]["routes"]["fake"]["tools"]["echo"].update(argumnets={}), "Extra inputs"),
        (lambda c: c["callers"]["alpha"].update(policy="missing"), "unknown policy"),
        (lambda c: c["policies"]["reader"]["routes"].update(ghost={"tools": {}}), "unknown route"),
        (lambda c: c["callers"]["bravo"].update(key_sha256=c["callers"]["alpha"]["key_sha256"]), "share a key"),
        (lambda c: c["callers"]["alpha"].update(key_sha256="not-a-hash"), "key_sha256"),
        (
            lambda c: c["policies"]["reader"]["routes"]["fake"]["tools"]["read"]["arguments"]["path"].update(
                pattern="x"
            ),
            "exactly one",
        ),
        (
            lambda c: c["policies"]["reader"]["routes"]["fake"]["tools"]["read"]["arguments"].update(
                path={"pattern": "("}
            ),
            "invalid pattern",
        ),
        (lambda c: c["upstreams"].update({"Bad Name": {"transport": "stdio", "command": "x"}}), "pattern"),
    ],
    ids=[
        "typo-in-policy",
        "typo-in-tool-rule",
        "unknown-policy",
        "unknown-route",
        "shared-key",
        "bad-hash",
        "both-matchers",
        "bad-regex",
        "bad-name",
    ],
)
def test_mistakes_are_rejected(tmp_path: Path, change: Any, message: str) -> None:
    config = base(tmp_path)
    change(config)
    with pytest.raises(ConfigError, match=message):
        load_config(write(tmp_path, config))


def test_a_missing_upstream_credential_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FAKE_UPSTREAM_KEY", raising=False)
    config = base(tmp_path)
    config["upstreams"]["fake"] = {
        "transport": "http",
        "url": "http://127.0.0.1:1/mcp",
        "auth_env": "FAKE_UPSTREAM_KEY",
    }
    with pytest.raises(ConfigError, match="FAKE_UPSTREAM_KEY is not set"):
        load_config(write(tmp_path, config))


@pytest.mark.anyio
async def test_a_policy_naming_a_tool_the_upstream_lacks_fails_at_start(tmp_path: Path) -> None:
    config = make_config(
        tmp_path, policies={"reader": {"routes": {"fake": {"tools": {"ehco": {}}}}}, "echo-only": {"routes": {}}}
    )
    with pytest.raises(ConfigError, match=r"doesn't have: \['ehco'\]"):
        async with running_gateway(config, in_memory(FakeUpstream())):
            pass


def test_hash_key_prints_a_key_and_its_hash(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["hash-key"]) == 0
    out = capsys.readouterr().out.splitlines()
    key = out[0].rsplit(": ", 1)[1]
    digest = out[1].rsplit(": ", 1)[1]
    assert len(key) >= 40 and hashlib.sha256(key.encode()).hexdigest() == digest


def test_serve_exits_2_on_a_bad_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("upstreams: {}\n")
    assert main(["serve", "--config", str(path)]) == 2
    assert "invalid config" in capsys.readouterr().err
