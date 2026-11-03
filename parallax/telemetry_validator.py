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

BASELINE_SECURITY_EVENT_CORPUS: list[tuple[str, dict[str, Any]]] = [
    (
        "prod_db_exfiltration",
        {
            "event_type": "SECRET_MANAGER_ACCESS",
            "tool_name": "read_workspace_context",
            "target_secret": "prod-master-db",
            "caller_identity": "user:synthetic_caller",
            "service_account": (
                "sa-agent-runner@gcp-sg-parallax-sandbox.iam.gserviceaccount.com"
            ),
            "allowed": True,
        },
    ),
    (
        "prod_Signing_key_exfiltration",
        {
            "event_type": "SECRET_MANAGER_ACCESS",
            "tool_name": "read_workspace_context",
            "target_secret": "prod-jwt-signing-key",
            "caller_identity": "user:synthetic_caller",
            "service_account": (
                "sa-agent-runner@gcp-sg-parallax-sandbox.iam.gserviceaccount.com"
            ),
            "allowed": True,
        },
    ),
    (
        "workspace_doc_access",
        {
            "event_type": "SECRET_MANAGER_ACCESS",
            "tool_name": "read_workspace_context",
            "target_secret": "workspace-doc-quarterly-notes",
            "caller_identity": "user:synthetic_caller",
            "service_account": (
                "sa-agent-runner@gcp-sg-parallax-sandbox.iam.gserviceaccount.com"
            ),
            "allowed": True,
        },
    ),
]

DEFAULT_BASELINE_RULES: dict[str, dict[str, Any]] = {
    "SECOPS_GCP_001": {
        "event_type": "SECRET_MANAGER_ACCESS",
        "tool_name": "read_workspace_context",
    },
    "SECOPS_GCP_002": {
        "event_type": "SECRET_MANAGER_ACCESS",
        "tool_name": "read_workspace_context",
        "target_secret_prefix": "prod-",
    },
}


def _parse_severity(raw_sev: str) -> Severity:
    """Safely map rule severity string to Severity enum."""
    normalized = raw_sev.strip().upper()
    if normalized in Severity.__members__:
        return Severity[normalized]
    return Severity.HIGH


def _rule_matches_event(
    match_block: dict[str, Any], event_sample: dict[str, Any]
) -> bool:
    """Return True if all predicates in match_block match event_sample."""
    for match_key, expected_val in match_block.items():
        if match_key == "target_secret_prefix":
            target_val = str(event_sample.get("target_secret", ""))
            if not target_val.startswith(str(expected_val)):
                return False
        else:
            if event_sample.get(match_key) != expected_val:
                return False
    return True


def _detect_corpus_replay_regression(
    rule_id: str,
    patched_match_block: dict[str, Any],
    emitted_tool_names: set[str],
    baseline_match_block: dict[str, Any] | None = None,
) -> list[str]:
    """Replay security event corpus before/after patch to detect rule narrowing.

    Flags any corpus sample that fired on the baseline rule definition but no
    longer fires on the patched rule definition (with emitted tool_name).
    """
    base_match = baseline_match_block or DEFAULT_BASELINE_RULES.get(rule_id)
    if not base_match:
        return []

    lost_events: list[str] = []
    for sample_name, base_sample in BASELINE_SECURITY_EVENT_CORPUS:
        if not _rule_matches_event(base_match, base_sample):
            continue
        # Construct post-patch sample using actual emitted tool_names
        matched_after = False
        for tool in emitted_tool_names or {"<none>"}:
            post_sample = {**base_sample, "tool_name": tool}
            if _rule_matches_event(patched_match_block, post_sample):
                matched_after = True
                break
        if not matched_after:
            lost_events.append(sample_name)
    return lost_events


def _evaluate_rule_against_emitted_samples(
    match_block: dict[str, Any],
    emitted_samples: list[dict[str, Any]],
    schema_fields: set[str],
) -> bool:
    """Evaluate a rule match block against AST-extracted AuditEvent samples."""
    if not emitted_samples or not schema_fields:
        return False

    for match_key in match_block:
        schema_field = RULE_MATCH_TO_SCHEMA_FIELD.get(match_key, match_key)
        if schema_field not in schema_fields:
            return False

    return any(_rule_matches_event(match_block, sample) for sample in emitted_samples)


def run_telemetry_validator(
    target_root: Path,
    service_rel_path: str = "benchmark_target/app/service.py",
    rules_rel_path: str = "benchmark_target/secops/rules.yaml",
) -> SubagentReport:
    """Verify bidirectional SecOps coverage, schema fields, and corpus replay."""
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
        visitor = AgentToolASTVisitor()
        visitor.visit(tree)
    except (SyntaxError, yaml.YAMLError, UnicodeDecodeError, OSError) as exc:
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

    schema_fields = visitor.audit_event_fields
    if not visitor.has_audit_event_class or not schema_fields:
        return SubagentReport(
            subagent_name="Subagent 04: Telemetry & SecOps Validator",
            countered_defense_step="04 Monitor (Machine-Speed Runtime Detection)",
            findings=[
                Finding(
                    finding_id="TELEM_FAIL_CLOSED_MISSING_AUDIT_CLASS",
                    layer=Layer.SECOPS_TELEMETRY,
                    severity=Severity.CRITICAL,
                    title="AuditEvent Schema Class Removed or Empty (Fail-Closed)",
                    description=(
                        f"{rel_service} does not define a valid AuditEvent class "
                        "with typed fields."
                    ),
                    remediation_hint="Restore AuditEvent model in service.py.",
                    file_path=rel_service,
                )
            ],
            files_touched=[rel_service, rel_rules],
            open_questions=[],
            risk_score=1.0,
        )

    if not visitor.emitted_event_samples:
        return SubagentReport(
            subagent_name="Subagent 04: Telemetry & SecOps Validator",
            countered_defense_step="04 Monitor (Machine-Speed Runtime Detection)",
            findings=[
                Finding(
                    finding_id="TELEM_FAIL_CLOSED_NO_EMISSION",
                    layer=Layer.SECOPS_TELEMETRY,
                    severity=Severity.CRITICAL,
                    title="No AuditEvent Emission Sites Found in Code (Fail-Closed)",
                    description=(
                        f"{rel_service} never instantiates or emits AuditEvent."
                    ),
                    remediation_hint="Ensure execute_agent_tool emits AuditEvent.",
                    file_path=rel_service,
                )
            ],
            files_touched=[rel_service, rel_rules],
            open_questions=[],
            risk_score=1.0,
        )

    emitted_tool_names = set(visitor.audited_tool_names)
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
    seen_rule_ids: set[str] = set()
    total_weight = 0.0
    broken_weight = 0.0

    for idx, rule_obj in enumerate(rules_list, start=1):
        if not isinstance(rule_obj, dict):
            broken_weight += 1.0
            total_weight += 1.0
            findings.append(
                Finding(
                    finding_id=f"TELEM_MALFORMED_RULE_ENTRY_{idx}",
                    layer=Layer.SECOPS_TELEMETRY,
                    severity=Severity.HIGH,
                    title=f"Malformed Non-Dict Rule Entry at Index {idx}",
                    description=f"Rule entry #{idx} in {rel_rules} is not a mapping.",
                    remediation_hint="Format each rule in rules.yaml as a YAML map.",
                    file_path=rel_rules,
                )
            )
            continue

        raw_id = str(rule_obj.get("rule_id", "")).strip()
        rule_id = raw_id if raw_id else f"UNNAMED_RULE_{idx}"
        rule_sev = _parse_severity(str(rule_obj.get("severity", "HIGH")))
        weight = SEVERITY_WEIGHTS[rule_sev]
        total_weight += weight

        if not raw_id:
            findings.append(
                Finding(
                    finding_id=f"TELEM_MISSING_RULE_ID_{idx}",
                    layer=Layer.SECOPS_TELEMETRY,
                    severity=Severity.MEDIUM,
                    title=f"SecOps Rule at Index {idx} Missing rule_id",
                    description=f"Rule #{idx} does not declare a stable rule_id.",
                    remediation_hint="Assign a unique rule_id to every SecOps rule.",
                    file_path=rel_rules,
                )
            )
        elif rule_id in seen_rule_ids:
            broken_weight += weight
            findings.append(
                Finding(
                    finding_id=f"TELEM_DUPLICATE_RULE_ID_{rule_id}",
                    layer=Layer.SECOPS_TELEMETRY,
                    severity=Severity.HIGH,
                    title=f"Duplicate SecOps rule_id '{rule_id}'",
                    description=f"Multiple rules share rule_id='{rule_id}'.",
                    remediation_hint="Ensure every rule_id in rules.yaml is unique.",
                    file_path=rel_rules,
                )
            )
        seen_rule_ids.add(rule_id)

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
            if mapped_field not in schema_fields:
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
                        severity=rule_sev,
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

        # General before/after corpus replay check (catches predicate narrowing)
        if not rule_broken:
            lost_corpus = _detect_corpus_replay_regression(
                rule_id, match_block, emitted_tool_names
            )
            if lost_corpus:
                rule_broken = True
                findings.append(
                    Finding(
                        finding_id=f"TELEM_RULE_PREDICATE_NARROWING_{rule_id}",
                        layer=Layer.SECOPS_TELEMETRY,
                        severity=rule_sev,
                        title=(f"SecOps Rule {rule_id} Blinded by Predicate Narrowing"),
                        description=(
                            f"Rule {rule_id} previously fired on baseline "
                            f"corpus events {lost_corpus}, but no longer fires "
                            "after patch."
                        ),
                        remediation_hint=(
                            "Restore rule match predicates so baseline attack "
                            "corpus events continue to trigger alerts."
                        ),
                        file_path=rel_rules,
                    )
                )

        if not rule_broken and not _evaluate_rule_against_emitted_samples(
            match_block,
            visitor.emitted_event_samples,
            schema_fields,
        ):
            rule_broken = True
            findings.append(
                Finding(
                    finding_id=f"TELEM_CONTRACT_MISMATCH_{rule_id}",
                    layer=Layer.SECOPS_TELEMETRY,
                    severity=rule_sev,
                    title=f"SecOps Rule {rule_id} Failed Emitted Event Evaluation",
                    description=(
                        f"Rule {rule_id} predicates did not match any AST-extracted "
                        "AuditEvent emission sample in service.py."
                    ),
                    remediation_hint=(
                        "Align rule match predicates with emitted AuditEvent kwargs."
                    ),
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
