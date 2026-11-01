"""Subagent 02: Cross-Layer Code-to-Cloud Auditor (Countering 02 Scan)."""

import ast
import os
from pathlib import Path

from dotenv import load_dotenv
from google import genai

from parallax.ast_utils import AgentToolASTVisitor
from parallax.schemas import Finding, Layer, Severity, SubagentReport

__all__ = [
    "AgentToolASTVisitor",
    "evaluate_auditor_precision_recall",
    "run_cross_layer_auditor",
]


def _optional_gemini_enrichment(prompt_context: str) -> str | None:
    """Optionally enrich architectural note via Gemini if GEMINI_API_KEY is set."""
    load_dotenv()
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key or api_key == "your_gemini_api_key_here":
        return None
    try:
        client = genai.Client(api_key=api_key)
        model_name = os.environ.get("PARALLAX_MODEL", "gemini-2.5-flash")
        response = client.models.generate_content(
            model=model_name,
            contents=(
                "Provide a one-sentence Cloud Architect root-cause summary for "
                f"this Code-to-Cloud flaw: {prompt_context}"
            ),
        )
        return response.text.strip() if response.text else None
    except Exception:
        return None


def run_cross_layer_auditor(
    target_root: Path,
    iam_risk_score: float = 0.0,
    service_rel_path: str = "benchmark_target/app/service.py",
) -> SubagentReport:
    """Execute Subagent 02 with layer-independent AST risk scoring."""
    service_path = target_root / service_rel_path
    rel_service = (
        service_path.relative_to(target_root).as_posix()
        if service_path.is_relative_to(target_root)
        else service_rel_path
    )

    if not service_path.exists():
        return SubagentReport(
            subagent_name="Subagent 02: Cross-Layer Code-to-Cloud Auditor",
            countered_defense_step="02 Scan (Multi-AI Code & Runtime Context Analysis)",
            findings=[
                Finding(
                    finding_id="PARALLAX-AST-MISSING",
                    layer=Layer.CODE_AST,
                    severity=Severity.CRITICAL,
                    title="Application Service Code Missing (Fail-Closed)",
                    description=f"Expected source file {rel_service} was not found.",
                    remediation_hint="Restore application handler source file.",
                    file_path=rel_service,
                )
            ],
            files_touched=[rel_service],
            open_questions=[],
            risk_score=1.0,
        )

    try:
        source_code = service_path.read_text(encoding="utf-8")
        tree = ast.parse(source_code, filename=rel_service)
    except SyntaxError as exc:
        return SubagentReport(
            subagent_name="Subagent 02: Cross-Layer Code-to-Cloud Auditor",
            countered_defense_step="02 Scan (Multi-AI Code & Runtime Context Analysis)",
            findings=[
                Finding(
                    finding_id="PARALLAX-AST-SYNTAX",
                    layer=Layer.CODE_AST,
                    severity=Severity.CRITICAL,
                    title="Application Code Syntax Error (Fail-Closed)",
                    description=f"Failed to parse {rel_service}: {exc.msg}",
                    remediation_hint="Fix Python syntax in candidate patch.",
                    file_path=rel_service,
                )
            ],
            files_touched=[rel_service],
            open_questions=[],
            risk_score=1.0,
        )

    visitor = AgentToolASTVisitor()
    visitor.visit(tree)

    findings: list[Finding] = []
    has_unvalidated_fallback = (
        visitor.reads_fallback_param
        and visitor.overrides_effective_secret
        and not visitor.revalidates_fallback_prefix
    )

    if has_unvalidated_fallback:
        severity = Severity.CRITICAL if iam_risk_score >= 0.8 else Severity.HIGH
        base_desc = (
            "execute_agent_tool validates ALLOWED_WORKSPACE_PREFIX on primary_id, "
            "but overwrites effective_secret_id with fallback_secret_id without "
            "re-enforcing ALLOWED_WORKSPACE_PREFIX."
        )
        ai_note = _optional_gemini_enrichment(base_desc)
        full_desc = f"{base_desc} [Gemini Note: {ai_note}]" if ai_note else base_desc

        findings.append(
            Finding(
                finding_id="PARALLAX-AST-001",
                layer=Layer.CODE_AST,
                severity=severity,
                title="Cross-Layer Confused Deputy via Unvalidated fallback_secret_id",
                description=full_desc,
                remediation_hint=(
                    "Enforce ALLOWED_WORKSPACE_PREFIX validation on "
                    "fallback_secret_id or remove the override."
                ),
                file_path=rel_service,
            )
        )
        risk_score = 0.95
    else:
        risk_score = 0.05

    open_q = list(visitor.unresolved_dynamic_tool_sites)
    if findings and not open_q:
        open_q.append(
            "If an IDE patch fixes or renames this tool handler without updating "
            "Terraform or SecOps YAML, does it create a Split-Brain blind spot?"
        )

    return SubagentReport(
        subagent_name="Subagent 02: Cross-Layer Code-to-Cloud Auditor",
        countered_defense_step="02 Scan (Multi-AI Code & Runtime Context Analysis)",
        findings=findings,
        files_touched=[rel_service],
        open_questions=open_q,
        risk_score=risk_score,
    )


def evaluate_auditor_precision_recall() -> dict[str, float]:
    """Run seeded true-positive and decoy AST cases to measure precision/recall."""
    cases: list[tuple[str, bool]] = [
        (
            "\n".join(
                [
                    "def execute_agent_tool(payload):",
                    "    primary_id = payload.get('resource_id', '')",
                    "    if not primary_id.startswith(ALLOWED_WORKSPACE_PREFIX):",
                    "        raise PermissionError()",
                    "    fallback_id = payload.get('fallback_secret_id', '')",
                    "    effective_secret_id = fallback_id",
                ]
            ),
            True,
        ),
        (
            "\n".join(
                [
                    "def execute_agent_tool(payload):",
                    "    primary_id = payload['resource_id']",
                    "    if primary_id.startswith(ALLOWED_WORKSPACE_PREFIX):",
                    "        fallback_id = payload.get('fallback_secret_id', '')",
                    "        if SAFE_ID_PATTERN.match(fallback_id):",
                    "            effective_secret_id = fallback_id",
                ]
            ),
            True,
        ),
        (
            "\n".join(
                [
                    "def execute_agent_tool(payload):",
                    "    primary_id = payload.get('resource_id', '')",
                    "    if not primary_id.startswith(ALLOWED_WORKSPACE_PREFIX):",
                    "        raise PermissionError()",
                    "    fallback_id = payload.get('fallback_secret_id', '')",
                    "    if not fallback_id.startswith(ALLOWED_WORKSPACE_PREFIX):",
                    "        raise PermissionError()",
                    "    effective_secret_id = fallback_id",
                ]
            ),
            False,
        ),
        (
            "\n".join(
                [
                    "def execute_agent_tool(payload):",
                    "    primary_id = payload.get('resource_id', '')",
                    "    if not primary_id.startswith(ALLOWED_WORKSPACE_PREFIX):",
                    "        raise PermissionError()",
                    "    effective_secret_id = primary_id",
                ]
            ),
            False,
        ),
    ]
    tp = fp = tn = fn = 0
    for code_snippet, expected_vulnerable in cases:
        visitor = AgentToolASTVisitor()
        visitor.visit(ast.parse(code_snippet))
        predicted = (
            visitor.reads_fallback_param
            and visitor.overrides_effective_secret
            and not visitor.revalidates_fallback_prefix
        )
        if predicted and expected_vulnerable:
            tp += 1
        elif predicted and not expected_vulnerable:
            fp += 1
        elif not predicted and not expected_vulnerable:
            tn += 1
        else:
            fn += 1
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    return {
        "true_positives": float(tp),
        "false_positives": float(fp),
        "true_negatives": float(tn),
        "false_negatives": float(fn),
        "precision": round(precision, 2),
        "recall": round(recall, 2),
    }
