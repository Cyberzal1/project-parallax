"""Subagent 04: SecOps Telemetry & Detection Validator (Countering 04 Monitor)."""

import ast
from pathlib import Path
from typing import Any

import yaml

from parallax.ast_utils import AgentToolASTVisitor
from parallax.schemas import Finding, Layer, Severity, SubagentReport

SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.7,
    Severity.MEDIUM: 0.4,
    Severity.LOW: 0.2,
    Severity.INFO: 0.1,
}

RULE_MATCH_TO_SCHEMA_FIELD: dict[str, str] = {
    "event_type": "event_type",
    "tool_name": "tool_name",
    "target_secret_prefix": "target_secret",
    "caller_identity": "caller_identity",
    "service_account": "service_account",
    "allowed": "allowed",
}


def _parse_severity(raw_sev: str) -> Severity:
    """Safely map rule severity string to Severity enum."""
    normalized = raw_sev.strip().upper()
    if normalized in Severity.__members__:
        return Severity[normalized]
    return Severity.HIGH


def _replay_synthetic_attack_against_rule(
    match_block: dict[str, Any],
    emitted_tools: set[str],
    emitted_event_types: set[str],
    schema_fields: set[str],
) -> bool:
    """Replay a synthetic prod-secret access event against a rule match block."""
    valid_events = emitted_event_types or {"SECRET_MANAGER_ACCESS"}
    for match_key, expected_val in match_block.items():
        schema_field = RULE_MATCH_TO_SCHEMA_FIELD.get(match_key, match_key)
        if schema_fields and schema_field not in schema_fields:
            return False
        if match_key == "tool_name":
            if str(expected_val) not in emitted_tools:
                return False
        elif match_key == "event_type":
            if str(expected_val) not in valid_events:
                return False
        elif match_key == "target_secret_prefix" and not (
            "prod-master-db".startswith(str(expected_val))
        ):
            return False
    return True


def run_telemetry_validator(
    target_root: Path,
    service_rel_path: str = "benchmark_target/app/service.py",
    rules_rel_path: str = "benchmark_target/secops/rules.yaml",
) -> SubagentReport:
    """Verify bidirectional SecOps coverage, schema fields, and event replay."""
    service_path = target_root / service_rel_path
    rules_path = target_root / rules_rel_path

    rel_service = (
        service_path.relative_to(target_root).as_posix()
        if service_path.is_relative_to(target_root)
        else service_rel_path
    )
    rel_rules = (
        rules_path.relative_to(target_root).as_posix()
        if rules_path.is_relative_to(target_root)
        else rules_rel_path
    )

    if not service_path.exists() or not rules_path.exists():
        missing = rel_rules if not rules_path.exists() else rel_service
        return SubagentReport(
            subagent_name="Subagent 04: Telemetry & SecOps Validator",
            countered_defense_step="04 Monitor (Machine-Speed Runtime Detection)",
            findings=[
                Finding(
                    finding_id="TELEM_FAIL_CLOSED_MISSING_FILE",
                    layer=Layer.SECOPS_TELEMETRY,
                    severity=Severity.CRITICAL,
                    title="Telemetry Contract File Missing (Fail-Closed)",
                    description=(
                        f"Required telemetry file '{missing}' was deleted or not "
                        "found. Scoring maximum telemetry blindspot risk (1.0)."
                    ),
                    remediation_hint="Restore deleted application or SecOps file.",
                    file_path=missing,
                )
            ],
            files_touched=[rel_service, rel_rules],
            open_questions=[],
            risk_score=1.0,
        )

    try:
        tree = ast.parse(service_path.read_text(encoding="utf-8"), filename=rel_service)
        raw_yaml: Any = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return SubagentReport(
            subagent_name="Subagent 04: Telemetry & SecOps Validator",
            countered_defense_step="04 Monitor (Machine-Speed Runtime Detection)",
            findings=[
                Finding(
                    finding_id="TELEM_FAIL_CLOSED_CORRUPT_INPUT",
                    layer=Layer.SECOPS_TELEMETRY,
                    severity=Severity.CRITICAL,
                    title="Malformed Telemetry Code or YAML Rules (Fail-Closed)",
                    description=f"Failed to parse telemetry inputs: {exc}",
                    remediation_hint="Ensure valid Python AST and YAML syntax.",
                    file_path=rel_rules,
                )
            ],
            files_touched=[rel_service, rel_rules],
            open_questions=[],
            risk_score=1.0,
        )

    if not isinstance(raw_yaml, dict) or not isinstance(raw_yaml.get("rules"), list):
        return SubagentReport(
            subagent_name="Subagent 04: Telemetry & SecOps Validator",
            countered_defense_step="04 Monitor (Machine-Speed Runtime Detection)",
            findings=[
                Finding(
                    finding_id="TELEM_FAIL_CLOSED_EMPTY_RULES",
                    layer=Layer.SECOPS_TELEMETRY,
                    severity=Severity.CRITICAL,
                    title="SecOps Detection Rules Empty or Invalid (Fail-Closed)",
                    description="rules.yaml does not contain a valid 'rules' list.",
                    remediation_hint="Define active detection rules under 'rules:'.",
                    file_path=rel_rules,
                )
            ],
            files_touched=[rel_service, rel_rules],
            open_questions=[],
            risk_score=1.0,
        )

    rules_list: list[Any] = raw_yaml["rules"]
    if len(rules_list) == 0:
        return SubagentReport(
            subagent_name="Subagent 04: Telemetry & SecOps Validator",
            countered_defense_step="04 Monitor (Machine-Speed Runtime Detection)",
            findings=[
                Finding(
                    finding_id="TELEM_FAIL_CLOSED_ZERO_RULES",
                    layer=Layer.SECOPS_TELEMETRY,
                    severity=Severity.CRITICAL,
                    title="Zero SecOps Detection Rules Configured (Fail-Closed)",
                    description="rules.yaml contains an empty rules list.",
                    remediation_hint="Add at least one runtime detection rule.",
                    file_path=rel_rules,
                )
            ],
            files_touched=[rel_service, rel_rules],
            open_questions=[],
            risk_score=1.0,
        )

    visitor = AgentToolASTVisitor()
    visitor.visit(tree)
    emitted_tool_names = set(visitor.audited_tool_names)
    emitted_event_types = visitor.emitted_event_types
    schema_fields = visitor.audit_event_fields

    findings: list[Finding] = []
    open_questions: list[str] = []

    if visitor.unresolved_dynamic_tool_sites:
        sites_str = ", ".join(visitor.unresolved_dynamic_tool_sites)
        open_questions.append(
            f"Found {len(visitor.unresolved_dynamic_tool_sites)} dynamic "
            f"AuditEvent.tool_name emission site(s) that cannot be resolved "
            f"statically ({sites_str})."
        )

    monitored_tool_names: set[str] = set()
    total_weight = 0.0
    broken_weight = 0.0

    for idx, rule_obj in enumerate(rules_list, start=1):
        if not isinstance(rule_obj, dict):
            broken_weight += 1.0
            total_weight += 1.0
            continue

        raw_id = str(rule_obj.get("rule_id", "")).strip()
        rule_id = raw_id if raw_id else f"UNNAMED_RULE_{idx}"
        rule_sev = _parse_severity(str(rule_obj.get("severity", "HIGH")))
        weight = SEVERITY_WEIGHTS[rule_sev]
        total_weight += weight

        match_block = rule_obj.get("match")
        if not isinstance(match_block, dict) or not match_block:
            broken_weight += weight
            findings.append(
                Finding(
                    finding_id=f"TELEM_INVALID_MATCH_{rule_id}",
                    layer=Layer.SECOPS_TELEMETRY,
                    severity=rule_sev,
                    title=f"SecOps Rule {rule_id} Has Empty or Null Match Block",
                    description=f"Rule {rule_id} has an invalid 'match' block.",
                    remediation_hint=(
                        "Specify valid field match criteria in rules.yaml."
                    ),
                    file_path=rel_rules,
                )
            )
            continue

        rule_broken = False

        for match_key in match_block:
            mapped_field = RULE_MATCH_TO_SCHEMA_FIELD.get(match_key, match_key)
            if schema_fields and mapped_field not in schema_fields:
                rule_broken = True
                findings.append(
                    Finding(
                        finding_id=f"TELEM_SCHEMA_DRIFT_{rule_id}_{mapped_field}",
                        layer=Layer.SECOPS_TELEMETRY,
                        severity=rule_sev,
                        title=f"AuditEvent Schema Field Drift on '{mapped_field}'",
                        description=(
                            f"Rule {rule_id} matches on '{match_key}' (mapped to "
                            f"AuditEvent.{mapped_field}), but AuditEvent only "
                            f"defines {sorted(schema_fields)}."
                        ),
                        remediation_hint=(
                            f"Restore field '{mapped_field}' on AuditEvent or "
                            f"update {rule_id} in rules.yaml."
                        ),
                        file_path=rel_service,
                    )
                )

        expected_tool = str(match_block.get("tool_name", "")).strip()
        if expected_tool:
            monitored_tool_names.add(expected_tool)
            if expected_tool not in emitted_tool_names:
                rule_broken = True
                findings.append(
                    Finding(
                        finding_id=f"PARALLAX-SECOPS-{rule_id}",
                        layer=Layer.SECOPS_TELEMETRY,
                        severity=Severity.HIGH,
                        title=f"Silent SecOps Detection Drift on Rule {rule_id}",
                        description=(
                            f"SecOps rule {rule_id} monitors "
                            f"tool_name='{expected_tool}', but service.py emits "
                            f"tool_name in {sorted(emitted_tool_names)}. "
                            "Runtime alerts will likely not fire."
                        ),
                        remediation_hint=(
                            f"Synchronize tool_name between service.py and {rel_rules}."
                        ),
                        file_path=rel_rules,
                    )
                )
        else:
            open_questions.append(
                f"Rule {rule_id} does not constrain 'tool_name'; verify broad "
                "event_type matching is intentional."
            )

        if not rule_broken and not _replay_synthetic_attack_against_rule(
            match_block,
            emitted_tool_names,
            emitted_event_types,
            schema_fields,
        ):
            rule_broken = True
            findings.append(
                Finding(
                    finding_id=f"TELEM_REPLAY_FAIL_{rule_id}",
                    layer=Layer.SECOPS_TELEMETRY,
                    severity=rule_sev,
                    title=f"SecOps Rule {rule_id} Failed Synthetic Attack Replay",
                    description=(
                        f"Rule {rule_id} did not fire when replaying a synthetic "
                        "secret access event against emitted AuditEvent schemas."
                    ),
                    remediation_hint="Verify rule match predicates against replay.",
                    file_path=rel_rules,
                )
            )

        if rule_broken:
            broken_weight += weight

    unmonitored_tools = sorted(emitted_tool_names - monitored_tool_names)
    for tool_name in unmonitored_tools:
        if monitored_tool_names & emitted_tool_names:
            findings.append(
                Finding(
                    finding_id=f"TELEM_UNMONITORED_TOOL_{tool_name.upper()}",
                    layer=Layer.SECOPS_TELEMETRY,
                    severity=Severity.HIGH,
                    title=f"Unmonitored Agent Tool Emission: '{tool_name}'",
                    description=(
                        f"service.py emits AuditEvent with tool_name='{tool_name}', "
                        "which is not covered by any rule in rules.yaml."
                    ),
                    remediation_hint=(
                        f"Add a detection rule covering tool_name='{tool_name}' "
                        "in secops/rules.yaml."
                    ),
                    file_path=rel_service,
                )
            )

    broken_ratio = broken_weight / total_weight if total_weight > 0 else 1.0
    unmonitored_penalty = (
        0.25
        if (unmonitored_tools and (monitored_tool_names & emitted_tool_names))
        else 0.0
    )
    dynamic_penalty = 0.15 if visitor.unresolved_dynamic_tool_sites else 0.0

    if broken_ratio == 0.0 and unmonitored_penalty == 0.0 and dynamic_penalty == 0.0:
        risk_score = 0.05
    else:
        raw_score = 0.05 + (0.80 * broken_ratio) + unmonitored_penalty + dynamic_penalty
        risk_score = round(min(0.95, raw_score), 2)

    return SubagentReport(
        subagent_name="Subagent 04: Telemetry & SecOps Validator",
        countered_defense_step="04 Monitor (Machine-Speed Runtime Detection)",
        findings=findings,
        files_touched=[rel_service, rel_rules],
        open_questions=open_questions,
        risk_score=risk_score,
    )
