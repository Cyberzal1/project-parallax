"""Complete Verification Gate 3 fixes and Phase 4 CLI setup cleanly."""

from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent


def write_clean(rel_path: str, content: str) -> None:
    """Write UTF-8 without BOM and with LF line endings."""
    path = ROOT / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.lstrip("\ufeff"), encoding="utf-8", newline="\n")


# 1. Rewrite tests/test_phase1_and_2.py with the 3 E501 lines wrapped <= 88 chars
TEST_PHASE1_AND_2_PY = '''"""Verification Gates 1 & 2: Workspace Guardrails and Baseline Flaw Reproduction."""

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

    # Ensure no actual .env file is committed or contains real keys in .env.example
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
        "Baseline unpatched architecture intentionally fails "
        "least-privilege invariant."
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
'''

# 2. Create Phase 4 Interactive CLI Runner (parallax/cli.py)
CLI_PY = '''"""Project PARALLAX Interactive CLI Demo Runner."""

from pathlib import Path

from parallax.orchestrator import run_parallax_orchestrator


def main() -> None:
    """Execute the 4-stage adversarial audit and Git worktree simulation."""
    root = Path(__file__).resolve().parent.parent
    sep = "=" * 64
    print(sep)
    print("Project PARALLAX: Adversarial Cloud Architecture & Patch Engine")
    print(sep)
    print(f"Target Workspace: {root}")
    print("Executing 4-Stage Audit & Git Worktree Patch Simulation...\\n")

    report = run_parallax_orchestrator(root, run_worktree_simulations=True)

    print(f"Overall Posture: {report.overall_posture}")
    print(f"Total Subagent Reports: {len(report.subagent_reports)}")
    for sub in report.subagent_reports:
        print(
            f"  - [{sub.subagent_name}] "
            f"Risk: {sub.risk_score:.2f} | Findings: {len(sub.findings)}"
        )

    print("\\n--- Split-Brain Remediation Evaluation (Git Worktrees) ---")
    for delta in report.split_brain_evaluations:
        print(f"  * Patch Worktree: {delta.patch_name}")
        print(f"    Effective Security Delta : {delta.effective_security_delta:.2f}")
        print(f"    Split-Brain Detected     : {delta.split_brain_detected}")
        print(f"    Summary                  : {delta.summary}\\n")


if __name__ == "__main__":
    main()
'''

# 3. Update tasks/lessons.md per GEMINI.md §3
LESSONS_MD = """# tasks/lessons.md — Self-Improvement Log

- **2026-10-23 (Third-Party Stubs & Runtime Subscripting):** `python-hcl2` and `networkx` require `[[tool.mypy.overrides]]` (`module = ["hcl2", "hcl2.*", "networkx", "networkx.*"]`, `ignore_missing_imports = true`, `implicit_reexport = true`). Never subscript `nx.DiGraph[str]` at runtime in Python 3.13 because `networkx.DiGraph` does not implement `__class_getitem__`.
- **2026-10-23 (Windows PowerShell UTF-8 BOM & ExecutionPolicy):** Windows PowerShell `Set-Content -Encoding utf8` prepends a UTF-8 BOM (`\\ufeff`), and default ExecutionPolicy blocks `.ps1` scripts. Rule: Use Python `.py` helper scripts (`Path.write_text(..., encoding="utf-8", newline="\\n")`) for multi-file generation.
- **2026-10-23 (Never Use Complex Multi-Quote `python -c` One-Liners in PowerShell):** Pasting `python -c "..."` with nested `\\"` and `{...}` braces into interactive Windows PowerShell crashes `PSReadLine` with `OperationStopped: Object reference not set to an instance of an object`. Rule: Always use a clean `.py` script file instead of escaped `python -c` strings.
"""


def main() -> None:
    write_clean("tests/test_phase1_and_2.py", TEST_PHASE1_AND_2_PY)
    write_clean("parallax/cli.py", CLI_PY)
    write_clean("tasks/lessons.md", LESSONS_MD)

    # Remove old temporary fix_phase3.py if still present
    old_fixer = ROOT / "fix_phase3.py"
    if old_fixer.exists():
        old_fixer.unlink()

    # Format and verify all checks (Ruff, Mypy, Pytest)
    for cmd in (
        [sys.executable, "-m", "ruff", "format", "parallax", "benchmark_target", "tests"],
        [sys.executable, "-m", "ruff", "check", "parallax", "benchmark_target", "tests"],
        [sys.executable, "-m", "mypy", "parallax", "benchmark_target", "tests"],
        [sys.executable, "-m", "pytest"],
    ):
        print(f"\n>>> Running: {' '.join(cmd[2:])}")
        subprocess.run(cmd, cwd=str(ROOT), check=True)


if __name__ == "__main__":
    main()