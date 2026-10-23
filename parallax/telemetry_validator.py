"""Subagent 04: SecOps Telemetry & Detection Validator (Countering 04 Monitor)."""

import ast
from pathlib import Path
from typing import Any

import yaml

from parallax.cross_layer_auditor import AgentToolASTVisitor
from parallax.schemas import Finding, Layer, Severity, SubagentReport


def run_telemetry_validator(target_root: Path) -> SubagentReport:
    """Verify SecOps YAML rules match AuditEvent emission in service.py."""
    service_path = target_root / "benchmark_target" / "app" / "service.py"
    rules_path = target_root / "benchmark_target" / "secops" / "rules.yaml"

    rel_service = str(service_path.relative_to(target_root).as_posix())
    rel_rules = str(rules_path.relative_to(target_root).as_posix())

    tree = ast.parse(service_path.read_text(encoding="utf-8"), filename=rel_service)
    visitor = AgentToolASTVisitor()
    visitor.visit(tree)
    emitted_tool_names = set(visitor.audited_tool_names)

    rules_data: dict[str, Any] = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    rules_list: list[dict[str, Any]] = rules_data.get("rules", [])

    findings: list[Finding] = []
    risk_score = 0.05

    for rule in rules_list:
        rule_id = str(rule.get("rule_id", "UNKNOWN"))
        match_block: dict[str, Any] = rule.get("match", {})
        expected_tool = str(match_block.get("tool_name", ""))

        if expected_tool and expected_tool not in emitted_tool_names:
            emitted_sorted = sorted(emitted_tool_names)
            findings.append(
                Finding(
                    finding_id=f"PARALLAX-SECOPS-{rule_id}",
                    layer=Layer.SECOPS_TELEMETRY,
                    severity=Severity.HIGH,
                    title=f"Silent SecOps Detection Drift on Rule {rule_id}",
                    description=(
                        f"SecOps rule {rule_id} monitors tool_name='{expected_tool}', "
                        f"but service.py emits tool_name in {emitted_sorted}. "
                        "Runtime alerts will never fire."
                    ),
                    remediation_hint=(
                        f"Synchronize tool_name between service.py and {rel_rules}."
                    ),
                )
            )
            risk_score = max(risk_score, 0.85)

    return SubagentReport(
        subagent_name="Subagent 04: Telemetry & SecOps Validator",
        countered_defense_step="04 Monitor (Machine-Speed Runtime Detection)",
        findings=findings,
        files_touched=[rel_service, rel_rules],
        open_questions=[],
        risk_score=risk_score,
    )
