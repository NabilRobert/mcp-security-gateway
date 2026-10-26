"""Slice B: the pure policy decisions (ADR-004)."""

import pytest

from mcp_gateway.config import Policy
from mcp_gateway.policy import allowed_tools, check_call, path_within

POLICY = Policy.model_validate(
    {
        "routes": {
            "files": {
                "tools": {
                    "read_text_file": {"arguments": {"path": {"prefix": "docs/"}}},
                    "read_multiple_files": {"arguments": {"paths": {"prefix": "docs/"}}},
                    "list_directory": {},
                    "lookup": {"arguments": {"id": {"pattern": r"[0-9]{1,6}"}}},
                }
            }
        }
    }
)


@pytest.mark.parametrize(
    ("value", "prefix", "inside"),
    [
        ("docs/a.md", "docs/", True),
        ("docs", "docs/", True),
        ("docs/sub/b.md", "docs", True),
        ("./docs/a.md", "docs/", True),
        ("docs/../secrets.env", "docs/", False),
        ("docs/../../etc/passwd", "docs/", False),
        ("../docs/a.md", "docs/", False),
        ("docsevil/a.md", "docs/", False),
        ("/docs/a.md", "docs/", False),
        ("docs/a.md", "/docs/", False),
        ("/srv/data/x", "/srv/data/", True),
        ("/srv/data/../etc", "/srv/data/", False),
        ("docs\\..\\secrets", "docs/", False),
        ("docs/a\x00.md", "docs/", False),
        ("anything/at/all", ".", True),
        ("../outside", ".", False),
    ],
)
def test_path_within(value: str, prefix: str, inside: bool) -> None:
    assert path_within(value, prefix) is inside


def test_unknown_route_is_denied() -> None:
    verdict = check_call(POLICY, "other", "list_directory", {})
    assert not verdict.allowed and "route" in verdict.reason


def test_unlisted_tool_is_denied() -> None:
    verdict = check_call(POLICY, "files", "write_file", {"path": "docs/a.md", "content": "x"})
    assert not verdict.allowed and "tool 'write_file'" in verdict.reason


def test_listed_tool_without_rules_is_allowed() -> None:
    assert check_call(POLICY, "files", "list_directory", {"path": "/anywhere"}).allowed


def test_prefix_rule_allows_inside_and_denies_traversal() -> None:
    assert check_call(POLICY, "files", "read_text_file", {"path": "docs/guide.md"}).allowed
    assert not check_call(POLICY, "files", "read_text_file", {"path": "docs/../.env"}).allowed


def test_governed_argument_must_be_given() -> None:
    verdict = check_call(POLICY, "files", "read_text_file", {})
    assert not verdict.allowed and "required by policy" in verdict.reason


def test_every_item_of_a_list_argument_is_checked() -> None:
    assert check_call(POLICY, "files", "read_multiple_files", {"paths": ["docs/a", "docs/b"]}).allowed
    assert not check_call(POLICY, "files", "read_multiple_files", {"paths": ["docs/a", "config/db.toml"]}).allowed


def test_non_string_values_are_denied() -> None:
    assert not check_call(POLICY, "files", "read_text_file", {"path": {"$ne": ""}}).allowed
    assert not check_call(POLICY, "files", "read_multiple_files", {"paths": ["docs/a", 7]}).allowed


def test_pattern_must_match_the_whole_value() -> None:
    assert check_call(POLICY, "files", "lookup", {"id": "4021"}).allowed
    # A search would accept this; a full match doesn't.
    assert not check_call(POLICY, "files", "lookup", {"id": "4021; DROP TABLE"}).allowed


def test_allowed_tools() -> None:
    assert allowed_tools(POLICY, "files") == {"read_text_file", "read_multiple_files", "list_directory", "lookup"}
    assert allowed_tools(POLICY, "nope") == frozenset()
