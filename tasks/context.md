# tasks/context.md — Project PARALLAX

## Environment (Verified)
- **OS:** Windows (using `pathlib.Path` and `.gitattributes` LF enforcement)
- **Runtime:** Python 3.13.14 | **Package Manager:** pip 26.1.2
- **Architecture:** Innovation 1 Engine (Split-Brain Patch Differential) auditing Innovation 2 Target (GCP Cloud Run AI Agent + NHI IAM + SecOps rules).

## Files Created in Phase 1 & Phase 2
- `.gitignore`, `.gitattributes`, `.env.example`, `requirements.txt`, `pyproject.toml`
- `benchmark_target/infra/main.tf`
- `benchmark_target/app/service.py`
- `benchmark_target/secops/rules.yaml`
- `tests/test_phase1_and_2.py`

## Next Steps
- Run local verification commands (`pytest`, `mypy`, `ruff`) on Windows host.
- Execute Phase 3: Build `parallax/` Orchestrator and 4 Subagents.
