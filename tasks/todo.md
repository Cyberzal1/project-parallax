# tasks/todo.md — Project PARALLAX Implementation Plan

## Phase 1: Workspace, Security Defaults & Windows Guardrails
- [x] 1.1 Initialize project directory structure (`parallax/`, `benchmark_target/`, `tests/`, `tasks/`).
- [x] 1.2 Create `.gitignore` and `.gitattributes` BEFORE the first `git init` commit.
- [x] 1.3 Initialize `tasks/lessons.md`, `requirements.txt`, `pyproject.toml`, and `.env.example`.
- [x] 1.4 **Verification Gate 1:** Passed `test_gate1_gitignore_and_windows_guardrails`.

## Phase 2: Benchmark GCP "Code-to-Cloud" Target (`benchmark_target/`)
- [x] 2.1 Create `benchmark_target/infra/main.tf` modeling Cloud Run AI Agent + project-wide IAM bindings.
- [x] 2.2 Create `benchmark_target/app/service.py` with upfront authn and cross-layer fallback flaw.
- [x] 2.3 Create `benchmark_target/secops/rules.yaml` and `tests/test_phase1_and_2.py`.
- [x] 2.4 **Verification Gate 2:** Reproduced baseline flaw via `test_gate2_reproduce_cross_layer_vulnerability_exists` and `xfail(strict=True)` invariant.

## Phase 3: Orchestrator & The 4 Subagents (`parallax/`)
- [x] 3.1 Define strict Pydantic schemas (`parallax/schemas.py`).
- [x] 3.2 Build Subagent 01 (`parallax/graph_analyzer.py` — Countering 01 Prepare).
- [x] 3.3 Build Subagent 02 (`parallax/cross_layer_auditor.py` — Countering 02 Scan).
- [x] 3.4 Build Subagent 03 (`parallax/patch_verifier.py` — Countering 03 Remediate in Git Worktrees).
- [x] 3.5 Build Subagent 04 (`parallax/telemetry_validator.py` — Countering 04 Monitor).
- [x] 3.6 Build Main Orchestrator (`parallax/orchestrator.py`).
- [x] 3.7 **Verification Gate 3:** `ruff`, `mypy --strict` (13 source files), and `pytest` (8 passed, 1 xfailed) all 100% green.

## Phase 4: End-to-End Git Worktree Loop Proof & Demo CLI
- [x] 4.1 Execute full simulation: Baseline (`0.77`) -> Symptom-Only Patch in Worktree (`0.61`, Split-Brain=True) -> Holistic Architectural Patch in Worktree (`0.07`, Split-Brain=False).
- [x] 4.2 Diff behavior against pre-change baseline and verify `parallax.cli` output.

## Review & Proof Section (GEMINI.md Task Management §5)
- **Pre-Change Baseline (`baseline-unpatched`):** Residual Risk Index = `0.77` (`IaC Risk=0.95`, `Code Risk=0.95`, `Telemetry Risk=0.05`, `Split-Brain=False`).
- **Symptom-Only Fast IDE Patch (`wt-symptom-patch`):** Residual Risk Index = `0.61` (`IaC Risk=0.95`, `Code Risk=0.05`, `Telemetry Drift Risk=0.85`, `Split-Brain=True`). Proves that patching Python AST in isolation while leaving GCP Terraform IAM wide open and drifting `tool_name` breaks SecOps monitoring.
- **Holistic Cloud Architect Patch (`wt-architectural-patch`):** Residual Risk Index = `0.07` (`IaC Risk=0.10`, `Code Risk=0.05`, `Telemetry Risk=0.05`, `Split-Brain=False`). Proves full remediation across Code, GCP IAM, and SecOps rules.
