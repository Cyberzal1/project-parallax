"""Subagent 02: Cross-Layer Code-to-Cloud Auditor (Countering 02 Scan)."""

import ast
import os
from pathlib import Path

from dotenv import load_dotenv
from google import genai

from parallax.schemas import Finding, Layer, Severity, SubagentReport


class AgentToolASTVisitor(ast.NodeVisitor):
    """AST visitor inspecting execute_agent_tool for fallback bypasses."""

    def __init__(self) -> None:
        self.reads_fallback_param: bool = False
        self.revalidates_fallback_prefix: bool = False
        self.overrides_effective_secret: bool = False
        self.audited_tool_names: list[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node.name == "execute_agent_tool":
            source_segment = ast.unparse(node)
            has_double = '"fallback_secret_id"' in source_segment
            has_single = "'fallback_secret_id'" in source_segment
            if has_double or has_single:
                self.reads_fallback_param = True
            if "effective_secret_id = fallback_id" in source_segment:
                self.overrides_effective_secret = True
            if "fallback_id.startswith(ALLOWED_WORKSPACE_PREFIX)" in source_segment:
                self.revalidates_fallback_prefix = True

            for subnode in ast.walk(node):
                if isinstance(subnode, ast.keyword) and subnode.arg == "tool_name":
                    if isinstance(subnode.value, ast.Constant) and isinstance(
                        subnode.value.value, str
                    ):
                        self.audited_tool_names.append(subnode.value.value)
        self.generic_visit(node)


def _optional_gemini_enrichment(prompt_context: str) -> str | None:
    """Enrich architectural note via Gemini if GEMINI_API_KEY is configured."""
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
                "Provide a one-sentence Cloud Architect root-cause summary for this "
                f"Code-to-Cloud flaw: {prompt_context}"
            ),
        )
        return response.text.strip() if response.text else None
    except Exception:
        return None


def run_cross_layer_auditor(
    target_root: Path,
    iam_risk_score: float,
) -> SubagentReport:
    """Execute Subagent 02 combining Python AST inspection with IAM context."""
    service_path = target_root / "benchmark_target" / "app" / "service.py"
    rel_service = str(service_path.relative_to(target_root).as_posix())
    source_code = service_path.read_text(encoding="utf-8")

    tree = ast.parse(source_code, filename=rel_service)
    visitor = AgentToolASTVisitor()
    visitor.visit(tree)

    findings: list[Finding] = []
    risk_score = 0.05

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
                    "Enforce ALLOWED_WORKSPACE_PREFIX validation on fallback_secret_id "
                    "or remove the fallback_secret_id override."
                ),
            )
        )
        risk_score = 0.95 if iam_risk_score >= 0.8 else 0.65

    return SubagentReport(
        subagent_name="Subagent 02: Cross-Layer Code-to-Cloud Auditor",
        countered_defense_step="02 Scan (Multi-AI Code & Runtime Context Analysis)",
        findings=findings,
        files_touched=[rel_service],
        open_questions=[
            "If an IDE patch fixes or renames this tool handler without updating "
            "Terraform or SecOps YAML, does it create a Split-Brain blind spot?"
        ]
        if findings
        else [],
        risk_score=risk_score,
    )
