"""Verification Gates 1 & 2: Workspace Guardrails and Baseline Flaw Reproduction."""

from pathlib import Path
from typing import Any

import hcl2
import pytest
import yaml

from benchmark_target.app.service import execute_agent_tool, verify_caller_auth

ROOT_DIR = Path(__file__).resolve().parent.parent


def test_gate1_gitignore_and_windows_guardrails() -> None:
    """Verify .gitignore blocks secrets/worktrees and .gitattributes enforces LF."""
    gitignore_path = ROOT_DIR / ".gitignore"
    gitattributes_path = ROOT_DIR / ".gitattributes"
    env_example_path = ROOT_DIR / ".env.example"

    assert gitignore_path.exists(), ".gitignore must exist before git init"
    assert gitattributes_path.exists(), (
        ".gitattributes must exist for Windows LF safety"
    )
    assert env_example_path.exists(), ".env.example must exist"

    gitignore_text = gitignore_path.read_text(encoding="utf-8")
    for required_pattern in (".env", "*.key", "*.pem", ".venv/", "wt-*/"):
        assert required_pattern in gitignore_text, (
            f"Missing {required_pattern} in .gitignore"
        )

    env_example_text = env_example_path.read_text(encoding="utf-8")
    assert "AIza" not in env_example_text, "Hardcoded Google API key detected!"


def test_gate2_authn_enforced_upfront() -> None:
    """Verify authentication boundary rejects unauthenticated or malformed callers."""
    with pytest.raises(PermissionError):
        verify_caller_auth(None)

    with pytest.raises(PermissionError):
        verify_caller_auth("Basic dXNlcjpwYXNz")

    valid_caller = verify_caller_auth("Bearer valid_session_token_123")
    assert valid_caller == "user:valid_session_token_123"


def test_gate2_reproduce_cross_layer_vulnerability_exists() -> None:
    """Deterministic reproduction proving the Code-to-Cloud flaw exists on baseline."""
    tf_path = ROOT_DIR / "benchmark_target" / "infra" / "main.tf"
    with tf_path.open("r", encoding="utf-8") as tf_file:
        tf_data: dict[str, Any] = hcl2.load(tf_file)

    iam_resources = [
        res["google_project_iam_member"]
        for res in tf_data.get("resource", [])
        if "google_project_iam_member" in res
    ]
    roles = [binding["role"] for item in iam_resources for binding in item.values()]
    assert "roles/secretmanager.secretAccessor" in roles

    payload: dict[str, Any] = {
        "resource_id": "workspace-doc-quarterly-notes",
        "use_fallback": True,
        "fallback_secret_id": "prod-master-db-credentials",
    }
    response = execute_agent_tool(
        auth_header="Bearer valid_session_token_123",
        tool_payload=payload,
    )

    assert response.allowed is True
    assert "secrets/prod-master-db-credentials/" in response.resolved_secret_uri

    rules_path = ROOT_DIR / "benchmark_target" / "secops" / "rules.yaml"
    rules_data = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    assert len(rules_data["rules"]) == 2


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Baseline unpatched architecture intentionally fails least-privilege invariant."
    ),
)
def test_gate2_architectural_security_invariant() -> None:
    """Security Invariant: Agent must NEVER resolve non-workspace secrets."""
    payload: dict[str, Any] = {
        "resource_id": "workspace-doc-quarterly-notes",
        "use_fallback": True,
        "fallback_secret_id": "prod-master-db-credentials",
    }
    response = execute_agent_tool(
        auth_header="Bearer valid_session_token_123",
        tool_payload=payload,
    )
    assert not response.resolved_secret_uri.startswith(
        "projects/gcp-sg-parallax-sandbox/secrets/prod-"
    )
