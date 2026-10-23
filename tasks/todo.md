# tasks/todo.md — Project PARALLAX Implementation Plan

## Phase 1: Workspace, Security Defaults & Windows Guardrails
- [x] 1.1 Initialize project directory structure (`parallax/`, `benchmark_target/`, `tests/`, `tasks/`).
- [x] 1.2 Create `.gitignore` and `.gitattributes` BEFORE the first `git init` commit.
- [x] 1.3 Initialize `tasks/lessons.md`, `requirements.txt`, `pyproject.toml`, and `.env.example`.
- [x] 1.4 **Verification Gate 1:** Implemented `test_gate1_gitignore_and_windows_guardrails` in `tests/test_phase1_and_2.py`.

## Phase 2: Benchmark GCP "Code-to-Cloud" Target (`benchmark_target/`)
- [x] 2.1 Create `benchmark_target/infra/main.tf` modeling Cloud Run AI Agent + project-wide IAM bindings.
- [x] 2.2 Create `benchmark_target/app/service.py` with upfront authn and cross-layer fallback flaw.
- [x] 2.3 Create `benchmark_target/secops/rules.yaml` and `tests/test_phase1_and_2.py`.
- [x] 2.4 **Verification Gate 2:** Reproduce baseline flaw via `test_gate2_reproduce_cross_layer_vulnerability_exists` and `xfail(strict=True)` invariant.

## Phase 3: Orchestrator & The 4 Subagents (`parallax/`)
- [ ] 3.1 Define strict Pydantic schemas (`parallax/schemas.py`).
- [ ] 3.2 Build Subagent 01 (`parallax/graph_analyzer.py` — Countering 01 Prepare).
- [ ] 3.3 Build Subagent 02 (`parallax/cross_layer_auditor.py` — Countering 02 Scan).
- [ ] 3.4 Build Subagent 03 (`parallax/patch_verifier.py` — Countering 03 Remediate in Git Worktrees).
- [ ] 3.5 Build Subagent 04 (`parallax/telemetry_validator.py` — Countering 04 Monitor).
- [ ] 3.6 Build Main Orchestrator (`parallax/orchestrator.py`).
- [ ] 3.7 **Verification Gate 3:** Run unit tests, `mypy`, and `ruff` across all modules with 0 errors.

## Phase 4: End-to-End Git Worktree Loop Proof
- [ ] 4.1 Execute full simulation: Baseline Audit -> Symptom-Only Patch in Worktree -> Root-Cause Patch in Worktree.
- [ ] 4.2 Diff behavior against pre-change baseline and append final review to `tasks/todo.md`.
