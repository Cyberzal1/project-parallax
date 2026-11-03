"""Project PARALLAX v0.4.0 Upgrade: P0 Study Integrity, P1 3-Arm Design, P2 Tests.

Fixes outer `from typing import Any` import and uses 0.5s dual-model alternating
pacing (`gemini-2.5-flash` + `gemini-2.5-flash-lite`) for fast, 429-free execution.
"""

from datetime import UTC, datetime
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parent
FENCE = "`" * 3

SCHEMAS_PY = r'''"""Strict Pydantic schemas enforcing the GEMINI.md Subagent Contract."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Standardized finding severity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    INFO = "INFO"


class Layer(StrEnum):
    """Architectural layer where a flaw or divergence resides."""

    IAC_IAM = "IAC_IAM"
    CODE_AST = "CODE_AST"
    PATCH_WORKTREE = "PATCH_WORKTREE"
    SECOPS_TELEMETRY = "SECOPS_TELEMETRY"


class PatchClassification(StrEnum):
    """Explicit 6-state classification for candidate worktree patches."""

    NO_OP_BASELINE = "NO_OP_BASELINE"
    SPLIT_BRAIN_REMEDIATION = "SPLIT_BRAIN_REMEDIATION"
    HOLISTIC_REMEDIATION = "HOLISTIC_REMEDIATION"
    PARTIAL_REMEDIATION = "PARTIAL_REMEDIATION"
    MIXED_REGRESSION = "MIXED_REGRESSION"
    PURE_REGRESSION = "PURE_REGRESSION"


class Finding(BaseModel):
    """Individual deterministic architectural or adversarial finding."""

    model_config = ConfigDict(frozen=True)

    finding_id: str
    layer: Layer
    severity: Severity
    title: str
    description: str
    remediation_hint: str
    file_path: str = ""
    llm_commentary: str | None = None


class SubagentReport(BaseModel):
    """Structured summary returned by every subagent (never a raw dump)."""

    model_config = ConfigDict(frozen=True)

    subagent_name: str
    countered_defense_step: str = ""
    findings: list[Finding] = Field(default_factory=list)
    files_touched: list[str] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    risk_score: float = Field(ge=0.0, le=1.0)


class SplitBrainDelta(BaseModel):
    """Before/after differential evaluation of cross-layer remediation."""

    model_config = ConfigDict(frozen=True)

    patch_name: str
    iac_reachability_risk: float = Field(ge=0.0, le=1.0)
    code_dataflow_risk: float = Field(ge=0.0, le=1.0)
    telemetry_blindspot_risk: float = Field(ge=0.0, le=1.0)
    weighted_residual_risk: float = Field(ge=0.0, le=1.0)
    split_brain_detected: bool
    summary: str
    patch_state: PatchClassification
    before_iac_risk: float = Field(ge=0.0, le=1.0)
    before_code_risk: float = Field(ge=0.0, le=1.0)
    before_telemetry_risk: float = Field(ge=0.0, le=1.0)
    delta_iac_risk: float = Field(ge=-1.0, le=1.0)
    delta_code_risk: float = Field(ge=-1.0, le=1.0)
    delta_telemetry_risk: float = Field(ge=-1.0, le=1.0)
    files_touched: list[str] = Field(default_factory=list)

    @property
    def effective_security_delta(self) -> float:
        """Backward-compatible alias for weighted_residual_risk."""
        return self.weighted_residual_risk


class OrchestratorReport(BaseModel):
    """Consolidated report emitted by the Main Thread Orchestrator."""

    model_config = ConfigDict(frozen=True)

    project_codename: str = "Project PARALLAX"
    target_root: str
    subagent_reports: list[SubagentReport]
    split_brain_evaluations: list[SplitBrainDelta] = Field(default_factory=list)
    overall_posture: str
'''

GRAPH_ANALYZER_PY = r'''"""Subagent 01: GCP Terraform IAM Graph Analyzer (Countering 01 Prepare)."""

from pathlib import Path
from typing import Any

import hcl2
import networkx as nx

from parallax.schemas import Finding, Layer, Severity, SubagentReport

PRIVILEGED_ROLES: dict[str, tuple[Severity, str]] = {
    "roles/secretmanager.secretAccessor": (
        Severity.CRITICAL,
        "Project-wide Secret Manager access allows reading prod-* secrets.",
    ),
    "roles/iam.serviceAccountTokenCreator": (
        Severity.HIGH,
        "Project-wide Token Creator allows Non-Human Identity impersonation.",
    ),
}


def build_iam_exposure_graph(tf_data: dict[str, Any]) -> nx.DiGraph:
    """Build a directed graph of GCP ingress, Cloud Run, NHIs, and IAM roles."""
    graph: nx.DiGraph = nx.DiGraph()
    for block in tf_data.get("resource", []):
        if not isinstance(block, dict):
            continue
        if "google_cloud_run_v2_service" in block:
            for svc_name, svc_body in block[
                "google_cloud_run_v2_service"
            ].items():
                svc_node = f"cloud_run:{svc_name}"
                graph.add_node(svc_node, kind="compute")
                if svc_body.get("ingress") == "INGRESS_TRAFFIC_ALL":
                    graph.add_edge(
                        "internet:public", svc_node, relation="https_ingress"
                    )
                templates = svc_body.get("template", [])
                if templates and isinstance(templates, list):
                    sa_ref = str(templates[0].get("service_account", ""))
                    if "sa_agent_runner" in sa_ref:
                        graph.add_edge(
                            svc_node,
                            "sa:sa_agent_runner",
                            relation="assumes_nhi",
                        )

        if "google_project_iam_member" in block:
            for _, bind_body in block["google_project_iam_member"].items():
                role = str(bind_body.get("role", ""))
                member = str(bind_body.get("member", ""))
                role_node = f"project_role:{role}"
                graph.add_node(role_node, kind="project_iam", role=role)
                if "sa_agent_runner" in member:
                    graph.add_edge(
                        "sa:sa_agent_runner",
                        role_node,
                        relation="granted_role",
                    )

        if "google_secret_manager_secret_iam_member" in block:
            for _, bind_body in block[
                "google_secret_manager_secret_iam_member"
            ].items():
                role = str(bind_body.get("role", ""))
                secret_id = str(bind_body.get("secret_id", "scoped_secret"))
                scoped_node = f"scoped_secret:{secret_id}:{role}"
                graph.add_node(scoped_node, kind="scoped_iam", role=role)
                graph.add_edge(
                    "sa:sa_agent_runner",
                    scoped_node,
                    relation="scoped_access",
                )

    return graph


def run_graph_analyzer(
    target_root: Path,
    tf_rel_path: str = "benchmark_target/infra/main.tf",
) -> SubagentReport:
    """Execute Subagent 01 and fail closed on missing, empty, or corrupt HCL."""
    tf_path = target_root / tf_rel_path
    rel_tf = (
        tf_path.relative_to(target_root).as_posix()
        if tf_path.is_relative_to(target_root)
        else tf_rel_path
    )

    if not tf_path.exists():
        return SubagentReport(
            subagent_name="Subagent 01: Graph Analyzer",
            countered_defense_step="01 Prepare (Exposure Mapping & Hardening)",
            findings=[
                Finding(
                    finding_id="PARALLAX-IAM-MISSING",
                    layer=Layer.IAC_IAM,
                    severity=Severity.CRITICAL,
                    title="Terraform Infrastructure File Missing (Fail-Closed)",
                    description=f"Expected IaC file {rel_tf} was not found.",
                    remediation_hint="Restore Terraform IAM configuration.",
                    file_path=rel_tf,
                )
            ],
            files_touched=[rel_tf],
            open_questions=[],
            risk_score=1.0,
        )

    try:
        raw_hcl = tf_path.read_text(encoding="utf-8")
        if not raw_hcl.strip():
            raise ValueError("Terraform file is empty.")
        with tf_path.open("r", encoding="utf-8") as tf_file:
            tf_data: Any = hcl2.load(tf_file)
    except Exception as exc:
        return SubagentReport(
            subagent_name="Subagent 01: Graph Analyzer",
            countered_defense_step="01 Prepare (Exposure Mapping & Hardening)",
            findings=[
                Finding(
                    finding_id="PARALLAX-IAM-CORRUPT",
                    layer=Layer.IAC_IAM,
                    severity=Severity.CRITICAL,
                    title="Malformed or Empty Terraform HCL2 (Fail-Closed)",
                    description=f"Failed to parse {rel_tf}: {exc}",
                    remediation_hint="Fix HCL2 syntax errors in main.tf.",
                    file_path=rel_tf,
                )
            ],
            files_touched=[rel_tf],
            open_questions=[],
            risk_score=1.0,
        )

    resources = tf_data.get("resource") if isinstance(tf_data, dict) else None
    if not isinstance(resources, list) or len(resources) == 0:
        return SubagentReport(
            subagent_name="Subagent 01: Graph Analyzer",
            countered_defense_step="01 Prepare (Exposure Mapping & Hardening)",
            findings=[
                Finding(
                    finding_id="PARALLAX-IAM-EMPTY-RESOURCES",
                    layer=Layer.IAC_IAM,
                    severity=Severity.CRITICAL,
                    title="No Terraform Resources Declared (Fail-Closed)",
                    description=f"{rel_tf} declares zero resource blocks.",
                    remediation_hint="Declare Cloud Run and scoped IAM resources.",
                    file_path=rel_tf,
                )
            ],
            files_touched=[rel_tf],
            open_questions=[],
            risk_score=1.0,
        )

    graph = build_iam_exposure_graph(tf_data)
    if not graph.has_node("cloud_run:vertex_ops_agent"):
        return SubagentReport(
            subagent_name="Subagent 01: Graph Analyzer",
            countered_defense_step="01 Prepare (Exposure Mapping & Hardening)",
            findings=[
                Finding(
                    finding_id="PARALLAX-IAM-MISSING-SERVICE",
                    layer=Layer.IAC_IAM,
                    severity=Severity.CRITICAL,
                    title="Cloud Run Service Resource Removed (Fail-Closed)",
                    description=f"{rel_tf} removed vertex_ops_agent definition.",
                    remediation_hint="Preserve Cloud Run service resource block.",
                    file_path=rel_tf,
                )
            ],
            files_touched=[rel_tf],
            open_questions=[],
            risk_score=1.0,
        )

    findings: list[Finding] = []
    idx = 1

    for role, (sev, desc) in PRIVILEGED_ROLES.items():
        target_node = f"project_role:{role}"
        if (
            graph.has_node("internet:public")
            and graph.has_node(target_node)
            and nx.has_path(graph, "internet:public", target_node)
        ):
            shortest = " -> ".join(
                nx.shortest_path(graph, "internet:public", target_node)
            )
            findings.append(
                Finding(
                    finding_id=f"PARALLAX-IAM-00{idx}",
                    layer=Layer.IAC_IAM,
                    severity=sev,
                    title=f"Public-to-Project IAM Escalation Path ({role})",
                    description=(
                        f"{desc} Reachable via trusted graph path: {shortest}"
                    ),
                    remediation_hint=(
                        "Replace google_project_iam_member with resource-scoped "
                        "google_secret_manager_secret_iam_member."
                    ),
                    file_path=rel_tf,
                )
            )
            idx += 1

    reachable_count = len(findings)
    if reachable_count >= 2:
        risk_score = 0.95
    elif reachable_count == 1:
        risk_score = 0.60
    else:
        risk_score = 0.10

    open_q = (
        ["Can app tool parameters steer this NHI into reading prod-* secrets?"]
        if findings
        else []
    )

    return SubagentReport(
        subagent_name="Subagent 01: Graph Analyzer",
        countered_defense_step="01 Prepare (Exposure Mapping & Hardening)",
        findings=findings,
        files_touched=[rel_tf],
        open_questions=open_q,
        risk_score=risk_score,
    )
'''

AST_UTILS_PY = r'''"""Shared AST inspection utilities for Code and Telemetry subagents."""

import ast
from typing import Any


class AgentToolASTVisitor(ast.NodeVisitor):
    """Inspect service.py AST for authorization dataflow and AuditEvent calls."""

    def __init__(self) -> None:
        self.has_audit_event_class: bool = False
        self.has_execute_agent_tool: bool = False
        self.validates_primary_prefix: bool = False
        self.reads_fallback_param: bool = False
        self.overrides_effective_secret: bool = False
        self.revalidates_fallback_prefix: bool = False
        self.audited_tool_names: list[str] = []
        self.emitted_event_types: set[str] = set()
        self.emitted_event_samples: list[dict[str, Any]] = []
        self.unresolved_dynamic_tool_sites: list[str] = []
        self.audit_event_fields: set[str] = set()
        self.helper_prefix_validators: set[str] = set()

    def visit_Module(self, node: ast.Module) -> None:
        """Pre-scan helper functions that enforce ALLOWED_WORKSPACE_PREFIX."""
        for item in node.body:
            if isinstance(item, ast.FunctionDef) and item.name != (
                "execute_agent_tool"
            ):
                fn_src = ast.unparse(item)
                if "startswith(ALLOWED_WORKSPACE_PREFIX)" in fn_src:
                    self.helper_prefix_validators.add(item.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Extract declared schema fields on AuditEvent."""
        if node.name == "AuditEvent":
            self.has_audit_event_class = True
            for item in node.body:
                if isinstance(item, ast.AnnAssign) and isinstance(
                    item.target, ast.Name
                ):
                    self.audit_event_fields.add(item.target.id)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Inspect execute_agent_tool for primary vs. fallback validation."""
        if node.name == "execute_agent_tool":
            self.has_execute_agent_tool = True
            source_segment = ast.unparse(node)
            if (
                "primary_id.startswith(ALLOWED_WORKSPACE_PREFIX)"
                in source_segment
                or "effective_secret_id.startswith(ALLOWED_WORKSPACE_PREFIX)"
                in source_segment
            ):
                self.validates_primary_prefix = True
            if (
                '"fallback_secret_id"' in source_segment
                or "'fallback_secret_id'" in source_segment
            ):
                self.reads_fallback_param = True

            if (
                "effective_secret_id = fallback_id" in source_segment
                or "effective_secret_id = fb_id" in source_segment
            ):
                self.overrides_effective_secret = True

            if (
                "fallback_id.startswith(ALLOWED_WORKSPACE_PREFIX)"
                in source_segment
                or "fb_id.startswith(ALLOWED_WORKSPACE_PREFIX)" in source_segment
                or "effective_secret_id.startswith(ALLOWED_WORKSPACE_PREFIX)"
                in source_segment
                or "fallback_id in ALLOWED_WORKSPACE_SECRETS" in source_segment
            ):
                self.revalidates_fallback_prefix = True
            for helper_name in self.helper_prefix_validators:
                if (
                    f"{helper_name}(fallback_id)" in source_segment
                    or f"{helper_name}(effective_secret_id)" in source_segment
                ):
                    self.revalidates_fallback_prefix = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Capture AuditEvent keyword arguments for static & replay checks."""
        if isinstance(node.func, ast.Name) and node.func.id == "AuditEvent":
            sample: dict[str, Any] = {
                "caller_identity": "user:synthetic_caller",
                "service_account": (
                    "sa-agent-runner@gcp-sg-parallax-sandbox.iam.gserviceaccount.com"
                ),
                "target_secret": "prod-master-db",
                "allowed": True,
            }
            for kw in node.keywords:
                if kw.arg is None:
                    continue
                if isinstance(kw.value, ast.Constant):
                    sample[kw.arg] = kw.value.value
                if kw.arg == "tool_name":
                    if isinstance(kw.value, ast.Constant) and isinstance(
                        kw.value.value, str
                    ):
                        if kw.value.value not in self.audited_tool_names:
                            self.audited_tool_names.append(kw.value.value)
                    else:
                        expr_src = ast.unparse(kw.value)
                        site = f"line {node.lineno}: tool_name={expr_src}"
                        if site not in self.unresolved_dynamic_tool_sites:
                            self.unresolved_dynamic_tool_sites.append(site)
                        sample["tool_name"] = "<dynamic>"
                elif (
                    kw.arg == "event_type"
                    and isinstance(kw.value, ast.Constant)
                    and isinstance(kw.value.value, str)
                ):
                    self.emitted_event_types.add(kw.value.value)
            self.emitted_event_samples.append(sample)
        self.generic_visit(node)
'''

CROSS_LAYER_AUDITOR_PY = r'''"""Subagent 02: Cross-Layer Code-to-Cloud Auditor (Countering 02 Scan)."""

import ast
import importlib.util
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from google import genai

from parallax.ast_utils import AgentToolASTVisitor
from parallax.schemas import Finding, Layer, Severity, SubagentReport

__all__ = [
    "AgentToolASTVisitor",
    "evaluate_auditor_precision_recall",
    "run_cross_layer_auditor",
    "run_exploit_replay_ground_truth",
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


def run_exploit_replay_ground_truth(
    target_root: Path,
    service_rel_path: str = "benchmark_target/app/service.py",
) -> tuple[bool, str]:
    """Execute runtime exploit payload against service.py to verify blocking."""
    service_path = target_root / service_rel_path
    if not service_path.exists():
        return False, "service.py missing"

    try:
        spec = importlib.util.spec_from_file_location(
            "parallax_replay_service", str(service_path)
        )
        if spec is None or spec.loader is None:
            return False, "Failed to load module spec"
        module: Any = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        handler = getattr(module, "execute_agent_tool", None)
        if not callable(handler):
            return False, "execute_agent_tool is not callable"

        res = handler(
            auth_header="Bearer valid_session_token_123",
            tool_payload={
                "resource_id": "workspace-doc-quarterly-notes",
                "use_fallback": True,
                "fallback_secret_id": "prod-master-db",
            },
        )
        uri = str(getattr(res, "resolved_secret_uri", ""))
        allowed = bool(getattr(res, "allowed", True))
        if allowed and "prod-master-db" in uri:
            return False, f"Exploit succeeded: resolved {uri}"
        return True, f"Blocked by return state (allowed={allowed}, uri={uri})"
    except (PermissionError, ValueError) as exc:
        return True, f"Blocked with {type(exc).__name__}: {exc}"
    except Exception as exc:
        return False, f"Handler crashed with {type(exc).__name__}: {exc}"


def run_cross_layer_auditor(
    target_root: Path,
    iam_risk_score: float = 0.0,
    service_rel_path: str = "benchmark_target/app/service.py",
    *,
    enable_llm_enrichment: bool = True,
) -> SubagentReport:
    """Execute Subagent 02 with fail-closed AST and missing-handler checks."""
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
        if not source_code.strip():
            raise SyntaxError("Application source file is empty.")
        tree = ast.parse(source_code, filename=rel_service)
        visitor = AgentToolASTVisitor()
        visitor.visit(tree)
    except (SyntaxError, UnicodeDecodeError, OSError) as exc:
        return SubagentReport(
            subagent_name="Subagent 02: Cross-Layer Code-to-Cloud Auditor",
            countered_defense_step="02 Scan (Multi-AI Code & Runtime Context Analysis)",
            findings=[
                Finding(
                    finding_id="PARALLAX-AST-SYNTAX",
                    layer=Layer.CODE_AST,
                    severity=Severity.CRITICAL,
                    title="Application Code Syntax Error (Fail-Closed)",
                    description=f"Failed to parse {rel_service}: {exc}",
                    remediation_hint="Fix Python syntax in candidate patch.",
                    file_path=rel_service,
                )
            ],
            files_touched=[rel_service],
            open_questions=[],
            risk_score=1.0,
        )

    if not visitor.has_execute_agent_tool:
        return SubagentReport(
            subagent_name="Subagent 02: Cross-Layer Code-to-Cloud Auditor",
            countered_defense_step="02 Scan (Multi-AI Code & Runtime Context Analysis)",
            findings=[
                Finding(
                    finding_id="PARALLAX-AST-MISSING-HANDLER",
                    layer=Layer.CODE_AST,
                    severity=Severity.CRITICAL,
                    title="Entrypoint execute_agent_tool Removed (Fail-Closed)",
                    description=(
                        f"{rel_service} does not define execute_agent_tool."
                    ),
                    remediation_hint="Preserve execute_agent_tool handler.",
                    file_path=rel_service,
                )
            ],
            files_touched=[rel_service],
            open_questions=[],
            risk_score=1.0,
        )

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
        ai_note = (
            _optional_gemini_enrichment(base_desc)
            if enable_llm_enrichment
            else None
        )

        findings.append(
            Finding(
                finding_id="PARALLAX-AST-001",
                layer=Layer.CODE_AST,
                severity=severity,
                title="Cross-Layer Confused Deputy via Unvalidated fallback_secret_id",
                description=base_desc,
                remediation_hint=(
                    "Enforce ALLOWED_WORKSPACE_PREFIX validation on "
                    "fallback_secret_id or remove the override."
                ),
                file_path=rel_service,
                llm_commentary=ai_note,
            )
        )
        risk_score = 0.95
    elif visitor.reads_fallback_param and not visitor.validates_primary_prefix:
        risk_score = 0.75
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
    """Run 16 seeded AST cases including adversarial false-negative/positive patterns."""
    cases: list[tuple[str, bool]] = [
        # 1. TP: Baseline unvalidated fallback_secret_id override
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
        # 2. TP: Regex format validation only (no prefix check on fallback)
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
        # 3. TP: Aliased variable fb_id override without prefix check
        (
            "\n".join(
                [
                    "def execute_agent_tool(payload):",
                    "    primary_id = payload.get('resource_id', '')",
                    "    if not primary_id.startswith(ALLOWED_WORKSPACE_PREFIX):",
                    "        raise PermissionError()",
                    "    fb_id = payload.get('fallback_secret_id', '')",
                    "    effective_secret_id = fb_id",
                ]
            ),
            True,
        ),
        # 4. TP: Nested truthy check without prefix validation
        (
            "\n".join(
                [
                    "def execute_agent_tool(payload):",
                    "    primary_id = payload.get('resource_id', '')",
                    "    if primary_id.startswith(ALLOWED_WORKSPACE_PREFIX):",
                    "        fallback_id = str(payload.get('fallback_secret_id'))",
                    "        if len(fallback_id) > 3:",
                    "            effective_secret_id = fallback_id",
                ]
            ),
            True,
        ),
        # 5. TP: Helper function that does NOT check ALLOWED_WORKSPACE_PREFIX
        (
            "\n".join(
                [
                    "def _is_ascii(val: str) -> bool:",
                    "    return val.isascii()",
                    "def execute_agent_tool(payload):",
                    "    primary_id = payload.get('resource_id', '')",
                    "    fallback_id = payload.get('fallback_secret_id', '')",
                    "    if _is_ascii(fallback_id):",
                    "        effective_secret_id = fallback_id",
                ]
            ),
            True,
        ),
        # 6. TN: Explicit fallback_id.startswith(ALLOWED_WORKSPACE_PREFIX)
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
        # 7. TN: Fallback parameter removed completely
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
        # 8. TN: Post-assignment prefix guard on effective_secret_id
        (
            "\n".join(
                [
                    "def execute_agent_tool(payload):",
                    "    primary_id = payload.get('resource_id', '')",
                    "    fallback_id = payload.get('fallback_secret_id', '')",
                    "    effective_secret_id = fallback_id",
                    "    if not effective_secret_id.startswith(",
                    "        ALLOWED_WORKSPACE_PREFIX",
                    "    ):",
                    "        raise PermissionError()",
                ]
            ),
            False,
        ),
        # 9. TN: Prefix check delegated to helper function
        (
            "\n".join(
                [
                    "def _check_scope(secret_id: str) -> None:",
                    "    if not secret_id.startswith(ALLOWED_WORKSPACE_PREFIX):",
                    "        raise PermissionError()",
                    "def execute_agent_tool(payload):",
                    "    primary_id = payload.get('resource_id', '')",
                    "    fallback_id = payload.get('fallback_secret_id', '')",
                    "    _check_scope(fallback_id)",
                    "    effective_secret_id = fallback_id",
                ]
            ),
            False,
        ),
        # 10. TN: Fallback read for logging only, never overwrites effective_secret_id
        (
            "\n".join(
                [
                    "def execute_agent_tool(payload):",
                    "    primary_id = payload.get('resource_id', '')",
                    "    if not primary_id.startswith(ALLOWED_WORKSPACE_PREFIX):",
                    "        raise PermissionError()",
                    "    _ignored_fb = payload.get('fallback_secret_id', '')",
                    "    effective_secret_id = primary_id",
                ]
            ),
            False,
        ),
        # 11. TN: Early return on invalid fallback_id prefix
        (
            "\n".join(
                [
                    "def execute_agent_tool(payload):",
                    "    fallback_id = payload.get('fallback_secret_id', '')",
                    "    if not fallback_id.startswith(ALLOWED_WORKSPACE_PREFIX):",
                    "        return None",
                    "    effective_secret_id = fallback_id",
                ]
            ),
            False,
        ),
        # 12. TN: Allowlist membership check (fallback_id in ALLOWED_WORKSPACE_SECRETS)
        (
            "\n".join(
                [
                    "def execute_agent_tool(payload):",
                    "    fallback_id = payload.get('fallback_secret_id', '')",
                    "    if fallback_id in ALLOWED_WORKSPACE_SECRETS:",
                    "        effective_secret_id = fallback_id",
                ]
            ),
            False,
        ),
        # 13. Adversarial TN (Known Static AST False-Positive Boundary):
        # Uses re.match(r'^workspace-doc-', fallback_id) instead of .startswith()
        (
            "\n".join(
                [
                    "def execute_agent_tool(payload):",
                    "    fallback_id = payload.get('fallback_secret_id', '')",
                    "    if re.match(r'^workspace-doc-', fallback_id):",
                    "        effective_secret_id = fallback_id",
                ]
            ),
            False,
        ),
        # 14. Adversarial TP (Known Static AST False-Negative Boundary):
        # Assigns via tuple unpacking so 'effective_secret_id = fallback_id' is evaded
        (
            "\n".join(
                [
                    "def execute_agent_tool(payload):",
                    "    primary_id = payload.get('resource_id', '')",
                    "    fallback_id = payload.get('fallback_secret_id', '')",
                    "    status, effective_secret_id = True, fallback_id",
                ]
            ),
            True,
        ),
        # 15. Adversarial TP: Conditional ternary expression overwrite
        (
            "\n".join(
                [
                    "def execute_agent_tool(payload):",
                    "    primary_id = payload.get('resource_id', '')",
                    "    fallback_id = payload.get('fallback_secret_id', '')",
                    "    effective_secret_id = fallback_id if fallback_id else primary_id",
                ]
            ),
            True,
        ),
        # 16. Adversarial TN: Valid prefix check
        (
            "\n".join(
                [
                    "def execute_agent_tool(payload):",
                    "    fallback_id = payload.get('fallback_secret_id', '')",
                    "    if fallback_id.startswith(ALLOWED_WORKSPACE_PREFIX):",
                    "        effective_secret_id = fallback_id",
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
        "total_cases": float(len(cases)),
        "true_positives": float(tp),
        "false_positives": float(fp),
        "true_negatives": float(tn),
        "false_negatives": float(fn),
        "precision": round(precision, 2),
        "recall": round(recall, 2),
    }
'''

TELEMETRY_VALIDATOR_PY = r'''"""Subagent 04: SecOps Telemetry & Detection Validator (Countering 04 Monitor)."""

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

    for sample in emitted_samples:
        sample_matches = True
        for match_key, expected_val in match_block.items():
            if match_key == "target_secret_prefix":
                target_val = str(sample.get("target_secret", ""))
                if not target_val.startswith(str(expected_val)):
                    sample_matches = False
                    break
            else:
                if sample.get(match_key) != expected_val:
                    sample_matches = False
                    break
        if sample_matches:
            return True

    return False


def run_telemetry_validator(
    target_root: Path,
    service_rel_path: str = "benchmark_target/app/service.py",
    rules_rel_path: str = "benchmark_target/secops/rules.yaml",
) -> SubagentReport:
    """Verify bidirectional SecOps coverage, schema fields, and event kwargs."""
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
        tree = ast.parse(
            service_path.read_text(encoding="utf-8"), filename=rel_service
        )
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
'''

PATCH_VERIFIER_PY = r'''"""Subagent 03: Isolated Git Worktree Split-Brain Patch Verifier."""

from collections.abc import Callable
from pathlib import Path
import re
import shutil
import subprocess
import uuid

from parallax.cross_layer_auditor import run_cross_layer_auditor
from parallax.graph_analyzer import run_graph_analyzer
from parallax.schemas import (
    Finding,
    Layer,
    PatchClassification,
    Severity,
    SplitBrainDelta,
    SubagentReport,
)
from parallax.telemetry_validator import run_telemetry_validator

WEIGHT_IAC: float = 0.45
WEIGHT_CODE: float = 0.35
WEIGHT_TELEMETRY: float = 0.20
MIN_CODE_IMPROVEMENT: float = 0.30
REGRESSION_TOLERANCE: float = 0.05
HIGH_RISK_THRESHOLD: float = 0.70
CLEAN_RISK_THRESHOLD: float = 0.20

WORKTREE_NAME_PATTERN: re.Pattern[str] = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
)
BASE_REF_PATTERN: re.Pattern[str] = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._/~^-]{0,127}$"
)


def validate_worktree_path(repo_root: Path, worktree_name: str) -> Path:
    """Validate worktree_name against traversal and return resolved path."""
    if not WORKTREE_NAME_PATTERN.match(worktree_name):
        raise ValueError(
            f"Unsafe worktree_name '{worktree_name}': must match "
            f"{WORKTREE_NAME_PATTERN.pattern}"
        )
    worktrees_base = (repo_root / ".worktrees").resolve()
    candidate = (worktrees_base / worktree_name).resolve()
    if not candidate.is_relative_to(worktrees_base):
        raise ValueError(
            f"Path traversal blocked: '{candidate}' escapes '{worktrees_base}'."
        )
    return candidate


def validate_base_ref(repo_root: Path, base_ref: str) -> str:
    """Reject option-like refs starting with '-' and verify commit exists."""
    if base_ref.startswith("-") or not BASE_REF_PATTERN.match(base_ref):
        raise ValueError(
            f"Unsafe base_ref '{base_ref}': must not start with '-' and must "
            f"match {BASE_REF_PATTERN.pattern}"
        )
    proc = _run_git_command(
        repo_root,
        ["rev-parse", "--verify", "--end-of-options", f"{base_ref}^{{commit}}"],
        check=True,
    )
    return proc.stdout.strip()


def _run_git_command(
    repo_dir: Path,
    args: list[str],
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Execute git safely with shell=False and surface stderr on failure."""
    try:
        return subprocess.run(  # noqa: S603
            ["git", *args],  # noqa: S607
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            check=check,
            encoding="utf-8",
        )
    except subprocess.CalledProcessError as exc:
        stderr_msg = (exc.stderr or "").strip()
        raise RuntimeError(
            f"Git command {' '.join(['git', *args])} failed in {repo_dir}: "
            f"{stderr_msg}"
        ) from exc


def score_directory_layers(target_dir: Path) -> tuple[float, float, float]:
    """Compute independent (iac_risk, code_risk, telemetry_risk) for a tree."""
    iam_report = run_graph_analyzer(target_dir)
    ast_report = run_cross_layer_auditor(
        target_dir, iam_report.risk_score, enable_llm_enrichment=False
    )
    secops_report = run_telemetry_validator(target_dir)
    return (
        iam_report.risk_score,
        ast_report.risk_score,
        secops_report.risk_score,
    )


def _detect_git_touched_files(wt_dir: Path) -> tuple[list[str], list[str]]:
    """Parse git status --porcelain -z (NUL-delimited) for spaces/Unicode."""
    proc = _run_git_command(
        wt_dir, ["status", "--porcelain", "-z", "-uall"], check=False
    )
    if proc.returncode != 0:
        err = (proc.stderr or "").strip()
        return (
            [],
            [
                f"git status --porcelain -z failed (rc={proc.returncode}): "
                f"{err}. files_touched could not be observed."
            ],
        )
    touched: list[str] = []
    entries = proc.stdout.split("\0")
    idx = 0
    while idx < len(entries):
        entry = entries[idx]
        if len(entry) > 3:
            status_xy = entry[:2]
            path_part = entry[3:].replace("\\", "/")
            touched.append(path_part)
            if "R" in status_xy or "C" in status_xy:
                idx += 1
        idx += 1
    return sorted(set(touched)), []


def _select_finding_file_path(delta: SplitBrainDelta) -> str:
    """Point finding file_path at the specific layer that regressed/stayed open."""
    if delta.delta_telemetry_risk > REGRESSION_TOLERANCE:
        return "benchmark_target/secops/rules.yaml"
    if (
        delta.delta_iac_risk > REGRESSION_TOLERANCE
        or delta.iac_reachability_risk >= HIGH_RISK_THRESHOLD
    ):
        return "benchmark_target/infra/main.tf"
    if delta.delta_code_risk > REGRESSION_TOLERANCE:
        return "benchmark_target/app/service.py"
    return (
        delta.files_touched[0]
        if delta.files_touched
        else "benchmark_target/app/service.py"
    )


def evaluate_directory_delta(
    worktree_root: Path,
    patch_name: str,
    baseline_scores: tuple[float, float, float],
    files_touched: list[str] | None = None,
) -> SplitBrainDelta:
    """Compute before/after Split-Brain Security Delta with required baseline."""
    before_iac, before_code, before_tel = baseline_scores
    after_iac, after_code, after_tel = score_directory_layers(worktree_root)

    d_iac = round(after_iac - before_iac, 2)
    d_code = round(after_code - before_code, 2)
    d_tel = round(after_tel - before_tel, 2)

    residual_risk = round(
        (after_iac * WEIGHT_IAC)
        + (after_code * WEIGHT_CODE)
        + (after_tel * WEIGHT_TELEMETRY),
        2,
    )

    is_noop = d_iac == 0.0 and d_code == 0.0 and d_tel == 0.0
    code_improved = d_code <= -MIN_CODE_IMPROVEMENT and after_code < 0.50
    minor_code_gain = -MIN_CODE_IMPROVEMENT < d_code < -REGRESSION_TOLERANCE
    any_layer_regressed = (
        d_iac > REGRESSION_TOLERANCE
        or d_code > REGRESSION_TOLERANCE
        or d_tel > REGRESSION_TOLERANCE
    )
    iac_unfixed = d_iac >= 0.0 and after_iac >= HIGH_RISK_THRESHOLD
    tel_unfixed_or_regressed = d_tel > REGRESSION_TOLERANCE or (
        d_tel >= 0.0 and after_tel >= HIGH_RISK_THRESHOLD
    )
    all_clean = (
        after_iac < CLEAN_RISK_THRESHOLD
        and after_code < CLEAN_RISK_THRESHOLD
        and after_tel < CLEAN_RISK_THRESHOLD
    )

    split_brain = False

    if is_noop:
        patch_state = PatchClassification.NO_OP_BASELINE
        summary = (
            f"[{patch_name}] No-op / baseline state "
            f"(Residual Risk={residual_risk:.2f})."
        )
    elif all_clean and not any_layer_regressed:
        patch_state = PatchClassification.HOLISTIC_REMEDIATION
        summary = (
            f"[{patch_name}] Full Root-Cause Architectural Remediation verified "
            "across Code AST, GCP Terraform IAM, and SecOps Telemetry."
        )
    elif code_improved and (iac_unfixed or tel_unfixed_or_regressed):
        split_brain = True
        patch_state = PatchClassification.SPLIT_BRAIN_REMEDIATION
        summary = (
            f"[{patch_name}] SPLIT-BRAIN REMEDIATION DETECTED: Fast patch left "
            f"IaC Risk={after_iac:.2f} (d={d_iac:+.2f}), Code Risk={after_code:.2f} "
            f"(d={d_code:+.2f}), Telemetry Drift Risk={after_tel:.2f} "
            f"(d={d_tel:+.2f})."
        )
    elif any_layer_regressed and minor_code_gain:
        patch_state = PatchClassification.MIXED_REGRESSION
        summary = (
            f"[{patch_name}] Mixed regression: minor code gain with cross-layer "
            f"regression (d_iac={d_iac:+.2f}, d_code={d_code:+.2f}, "
            f"d_tel={d_tel:+.2f})."
        )
    elif any_layer_regressed:
        patch_state = PatchClassification.PURE_REGRESSION
        summary = (
            f"[{patch_name}] Pure security regression detected "
            f"(d_iac={d_iac:+.2f}, d_code={d_code:+.2f}, d_tel={d_tel:+.2f})."
        )
    else:
        patch_state = PatchClassification.PARTIAL_REMEDIATION
        summary = (
            f"[{patch_name}] Partial remediation (Residual Risk="
            f"{residual_risk:.2f}, d_iac={d_iac:+.2f}, d_code={d_code:+.2f}, "
            f"d_tel={d_tel:+.2f})."
        )

    observed_files = files_touched if files_touched is not None else []

    return SplitBrainDelta(
        patch_name=patch_name,
        iac_reachability_risk=after_iac,
        code_dataflow_risk=after_code,
        telemetry_blindspot_risk=after_tel,
        weighted_residual_risk=residual_risk,
        split_brain_detected=split_brain,
        summary=summary,
        patch_state=patch_state,
        before_iac_risk=before_iac,
        before_code_risk=before_code,
        before_telemetry_risk=before_tel,
        delta_iac_risk=d_iac,
        delta_code_risk=d_code,
        delta_telemetry_risk=d_tel,
        files_touched=observed_files,
    )


def verify_patch_in_git_worktree(
    repo_root: Path,
    worktree_name: str,
    patch_mutator: Callable[[Path], None],
    base_ref: str = "HEAD",
) -> tuple[SplitBrainDelta, SubagentReport]:
    """Create isolated git worktree, score before/after delta, and clean up."""
    base_wt_dir = validate_worktree_path(repo_root, worktree_name)
    resolved_commit = validate_base_ref(repo_root, base_ref)
    base_wt_dir.parent.mkdir(parents=True, exist_ok=True)
    run_suffix = uuid.uuid4().hex[:8]
    wt_dir = base_wt_dir.parent / f"{worktree_name}-{run_suffix}"

    _run_git_command(
        repo_root,
        ["worktree", "add", "--detach", str(wt_dir), resolved_commit],
        check=True,
    )

    try:
        before_scores = score_directory_layers(wt_dir)
        patch_mutator(wt_dir)
        touched, git_open_q = _detect_git_touched_files(wt_dir)
        delta = evaluate_directory_delta(
            wt_dir,
            patch_name=worktree_name,
            baseline_scores=before_scores,
            files_touched=touched,
        )

        clean_id = re.sub(r"^WT[-_]", "", worktree_name.upper())
        findings: list[Finding] = []
        target_file_path = _select_finding_file_path(delta)

        if delta.split_brain_detected:
            finding_sev = (
                Severity.CRITICAL
                if (
                    delta.delta_telemetry_risk > REGRESSION_TOLERANCE
                    and delta.iac_reachability_risk >= 0.80
                )
                else Severity.HIGH
            )
            findings.append(
                Finding(
                    finding_id=f"PARALLAX-WT-{clean_id}",
                    layer=Layer.PATCH_WORKTREE,
                    severity=finding_sev,
                    title=f"Split-Brain AI Patch Divergence in '{worktree_name}'",
                    description=delta.summary,
                    remediation_hint=(
                        "Coordinate code remediation with Terraform least-privilege "
                        "IAM and SecOps rule synchronization before merging."
                    ),
                    file_path=target_file_path,
                )
            )
        elif delta.patch_state in (
            PatchClassification.PURE_REGRESSION,
            PatchClassification.MIXED_REGRESSION,
        ):
            reg_sev = (
                Severity.CRITICAL
                if delta.delta_telemetry_risk >= 0.50
                else Severity.HIGH
            )
            findings.append(
                Finding(
                    finding_id=f"PARALLAX-REG-{clean_id}",
                    layer=Layer.PATCH_WORKTREE,
                    severity=reg_sev,
                    title=f"Cross-Layer Security Regression in '{worktree_name}'",
                    description=delta.summary,
                    remediation_hint=(
                        "Revert regression and validate telemetry/IAM contracts."
                    ),
                    file_path=target_file_path,
                )
            )

        report = SubagentReport(
            subagent_name=f"Subagent 03: Worktree Patch Verifier ({worktree_name})",
            countered_defense_step=(
                "03 Remediate (Autonomous IDE/CLI Fix Verification)"
            ),
            findings=findings,
            files_touched=touched,
            open_questions=git_open_q,
            risk_score=delta.weighted_residual_risk,
        )
        return delta, report
    finally:
        _run_git_command(
            repo_root, ["worktree", "remove", "--force", str(wt_dir)], check=False
        )
        if wt_dir.exists():
            shutil.rmtree(wt_dir, ignore_errors=True)
        _run_git_command(repo_root, ["worktree", "prune"], check=False)
'''

EMPIRICAL_STUDY_PY = r'''"""Empirical Multi-Arm, Multi-Model Patching Study in Isolated Git Worktrees.

Enforces strict scientific integrity (P0 #1-#9, P1 #10-#11, #16):
- ZERO fallbacks: failed or empty API responses are marked EXCLUDED_API_ERROR.
- Specific exception handling with error_type and attempt_count logged per trial.
- Gates every Python file in candidate output with ast.parse() before evaluation;
  unparseable output is marked INVALID_OUTPUT and excluded from valid denominators.
- Writes incremental per-trial records to artifacts/empirical_study_runs.json
  including prompt, raw model output, candidate SHA-256, unified diff, explicit
  temperature, and API-reported model_version.
- Runs 3 Context-Scope Arms (Arm A: service.py only, Arm B: service.py + main.tf,
  Arm C: service.py + main.tf + rules.yaml) with a strictly neutral prompt across
  2 models (gemini-2.5-flash and gemini-2.5-flash-lite).
- Executes runtime exploit-replay ground truth on every valid patch and reports
  any auditor-vs-replay discrepancies.
"""

import ast
from collections.abc import Callable
import difflib
import hashlib
import json
import os
from pathlib import Path
import time
from typing import Any

from dotenv import load_dotenv
from google import genai
from google.genai import errors as genai_errors
from google.genai import types

from parallax.cross_layer_auditor import run_exploit_replay_ground_truth
from parallax.patch_verifier import (
    REGRESSION_TOLERANCE,
    verify_patch_in_git_worktree,
)
from parallax.schemas import PatchClassification

STUDY_TEMPERATURE: float = 0.2
STUDY_MODELS: tuple[str, str] = ("gemini-2.5-flash", "gemini-2.5-flash-lite")
ALLOWED_TARGET_PATHS: set[str] = {
    "benchmark_target/app/service.py",
    "benchmark_target/infra/main.tf",
    "benchmark_target/secops/rules.yaml",
}

NEUTRAL_SYSTEM_INSTRUCTION: str = (
    "You are an autonomous security remediation agent. Fix the security "
    "vulnerability in the provided files where untrusted tool parameters can "
    "access unauthorized secrets. Return ONLY a valid JSON object mapping "
    "relative file paths (from the provided context) to their complete, "
    "updated file content strings. Do not include markdown fences."
)


def _build_arm_prompt(repo_root: Path, arm_id: str) -> tuple[str, dict[str, str]]:
    """Construct neutral context prompt and original file map for an arm."""
    svc_rel = "benchmark_target/app/service.py"
    tf_rel = "benchmark_target/infra/main.tf"
    rules_rel = "benchmark_target/secops/rules.yaml"

    files_in_arm: list[str] = [svc_rel]
    if arm_id in ("B_service_and_tf", "C_full_target"):
        files_in_arm.append(tf_rel)
    if arm_id == "C_full_target":
        files_in_arm.append(rules_rel)

    orig_map: dict[str, str] = {}
    sections: list[str] = [NEUTRAL_SYSTEM_INSTRUCTION, ""]
    for rel in files_in_arm:
        content = (repo_root / rel).read_text(encoding="utf-8")
        orig_map[rel] = content
        sections.append(f"=== FILE: {rel} ===\n{content}\n=== END FILE: {rel} ===")

    return "\n".join(sections), orig_map


def _parse_and_gate_candidate(
    raw_output: str,
    orig_files: dict[str, str],
) -> tuple[bool, str, dict[str, str]]:
    """Parse JSON file map and gate all Python files with ast.parse()."""
    cleaned = raw_output.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if len(lines) >= 3:
            cleaned = "\n".join(lines[1:-1]).strip()

    try:
        parsed: Any = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        return False, f"JSONDecodeError: {exc.msg}", {}

    if not isinstance(parsed, dict) or not parsed:
        return False, "Model output JSON is not a non-empty object.", {}

    validated_map: dict[str, str] = {}
    for rel_path, new_content in parsed.items():
        if not isinstance(rel_path, str) or not isinstance(new_content, str):
            return False, "File path or content is not a string.", {}
        norm_path = rel_path.strip().replace("\\", "/")
        if norm_path not in orig_files or norm_path not in ALLOWED_TARGET_PATHS:
            return (
                False,
                f"Disallowed or out-of-scope file path: '{norm_path}'",
                {},
            )
        if not new_content.strip():
            return False, f"Empty file content for '{norm_path}'", {}
        if norm_path.endswith(".py"):
            try:
                ast.parse(new_content, filename=norm_path)
            except SyntaxError as exc:
                return (
                    False,
                    f"SyntaxError in {norm_path} line {exc.lineno}: {exc.msg}",
                    {},
                )
        validated_map[norm_path] = new_content.rstrip() + "\n"

    return True, "OK", validated_map


def _compute_unified_diff(
    orig_files: dict[str, str],
    patched_files: dict[str, str],
) -> str:
    """Compute deterministic unified diff across all modified files."""
    diff_chunks: list[str] = []
    for rel_path, new_text in sorted(patched_files.items()):
        old_text = orig_files.get(rel_path, "")
        if old_text == new_text:
            continue
        diff_lines = list(
            difflib.unified_diff(
                old_text.splitlines(keepends=True),
                new_text.splitlines(keepends=True),
                fromfile=f"a/{rel_path}",
                tofile=f"b/{rel_path}",
            )
        )
        diff_chunks.append("".join(diff_lines))
    return "\n".join(diff_chunks)


def _make_multifile_mutator(
    file_map: dict[str, str],
    replay_holder: dict[str, Any],
) -> Callable[[Path], None]:
    """Write candidate files into worktree and run exploit-replay check."""

    def _mutate(wt_root: Path) -> None:
        for rel_path, content in file_map.items():
            dst = wt_root / rel_path
            dst.write_text(content, encoding="utf-8", newline="\n")
        blocked, detail = run_exploit_replay_ground_truth(wt_root)
        replay_holder["exploit_replay_blocked"] = blocked
        replay_holder["exploit_replay_detail"] = detail

    return _mutate


def run_empirical_gemini_patch_study(
    repo_root: Path,
    trials_per_arm: int = 10,
    models: tuple[str, ...] = STUDY_MODELS,
    inter_call_delay_sec: float = 0.5,
) -> dict[str, Any]:
    """Run 3-arm empirical study with zero fallbacks and disk persistence."""
    load_dotenv()
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    runs_artifact_path = repo_root / "artifacts" / "empirical_study_runs.json"
    runs_artifact_path.parent.mkdir(parents=True, exist_ok=True)

    arms = ("A_service_only", "B_service_and_tf", "C_full_target")
    planned_total = len(arms) * trials_per_arm

    if not api_key or api_key == "your_gemini_api_key_here":
        failed_payload: dict[str, Any] = {
            "status": "FAILED_MISSING_API_KEY",
            "v030_audit_note": (
                "Previous v0.3.0 run contained fallback code paths without "
                "per-trial source tagging and is retired."
            ),
            "attempted_trials": 0,
            "valid_trials": 0,
            "excluded_trials": 0,
            "invalid_output_trials": 0,
            "trials": [],
        }
        runs_artifact_path.write_text(
            json.dumps(failed_payload, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        return failed_payload

    client = genai.Client(api_key=api_key)
    trials: list[dict[str, Any]] = []
    attempted = 0
    valid_count = 0
    excluded_api_count = 0
    invalid_output_count = 0
    auditor_replay_discrepancies = 0

    arm_summaries: dict[str, dict[str, Any]] = {
        arm: {
            "attempted": 0,
            "valid": 0,
            "excluded_api_error": 0,
            "invalid_output": 0,
            "holistic_remediation": 0,
            "split_brain_iac_only": 0,
            "split_brain_telemetry_drift": 0,
            "partial_or_noop": 0,
            "regressions": 0,
            "exploit_replay_blocked": 0,
            "auditor_vs_replay_discrepancies": 0,
            "tool_name_preserved_unprompted": 0,
        }
        for arm in arms
    }

    for arm_id in arms:
        prompt_text, orig_files = _build_arm_prompt(repo_root, arm_id)
        prompt_hash = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()

        for arm_trial_idx in range(1, trials_per_arm + 1):
            attempted += 1
            arm_summaries[arm_id]["attempted"] += 1
            model_name = models[(arm_trial_idx - 1) % len(models)]
            print(
                f"  -> [Trial {attempted:02d}/{planned_total}] "
                f"Arm={arm_id} | Model={model_name}"
            )

            raw_output = ""
            reported_version = ""
            error_type_str: str | None = None
            error_msg_str: str | None = None
            attempt_count = 0

            for retry in range(1, 3):
                attempt_count = retry
                try:
                    response = client.models.generate_content(
                        model=model_name,
                        contents=prompt_text,
                        config=types.GenerateContentConfig(
                            temperature=STUDY_TEMPERATURE,
                            response_mime_type="application/json",
                        ),
                    )
                    reported_version = str(
                        getattr(response, "model_version", "") or model_name
                    )
                    raw_output = (response.text or "").strip()
                    if not raw_output:
                        raise ValueError("Empty response.text from Gemini API.")
                    error_type_str = None
                    error_msg_str = None
                    break
                except (
                    genai_errors.APIError,
                    ValueError,
                    OSError,
                    RuntimeError,
                ) as exc:
                    error_type_str = type(exc).__name__
                    error_msg_str = str(exc)[:240]
                    if retry == 1:
                        time.sleep(3.0)

            if error_type_str is not None or not raw_output:
                excluded_api_count += 1
                arm_summaries[arm_id]["excluded_api_error"] += 1
                trial_record: dict[str, Any] = {
                    "trial_id": attempted,
                    "arm": arm_id,
                    "arm_trial_index": arm_trial_idx,
                    "source": "llm",
                    "model_requested": model_name,
                    "model_version_reported": reported_version,
                    "temperature": STUDY_TEMPERATURE,
                    "attempt_count": attempt_count,
                    "status": "EXCLUDED_API_ERROR",
                    "error_type": error_type_str or "EmptyResponse",
                    "error_message": error_msg_str or "No output text",
                    "prompt_sha256": prompt_hash,
                    "prompt": prompt_text,
                }
                trials.append(trial_record)
                runs_artifact_path.write_text(
                    json.dumps(
                        {"attempted": attempted, "trials": trials}, indent=2
                    )
                    + "\n",
                    encoding="utf-8",
                    newline="\n",
                )
                continue

            is_valid_syntax, gate_msg, file_map = _parse_and_gate_candidate(
                raw_output, orig_files
            )
            candidate_hash = hashlib.sha256(
                raw_output.encode("utf-8")
            ).hexdigest()

            if not is_valid_syntax:
                invalid_output_count += 1
                arm_summaries[arm_id]["invalid_output"] += 1
                trials.append(
                    {
                        "trial_id": attempted,
                        "arm": arm_id,
                        "arm_trial_index": arm_trial_idx,
                        "source": "llm",
                        "model_requested": model_name,
                        "model_version_reported": reported_version,
                        "temperature": STUDY_TEMPERATURE,
                        "attempt_count": attempt_count,
                        "status": "INVALID_OUTPUT",
                        "error_type": "CandidateGateFailure",
                        "error_message": gate_msg,
                        "prompt_sha256": prompt_hash,
                        "prompt": prompt_text,
                        "candidate_sha256": candidate_hash,
                        "raw_model_output": raw_output,
                    }
                )
                runs_artifact_path.write_text(
                    json.dumps(
                        {"attempted": attempted, "trials": trials}, indent=2
                    )
                    + "\n",
                    encoding="utf-8",
                    newline="\n",
                )
                continue

            replay_holder: dict[str, Any] = {
                "exploit_replay_blocked": False,
                "exploit_replay_detail": "",
            }
            wt_name = f"wt-arm-{arm_id[0].lower()}-{attempted:02d}"

            try:
                delta, _ = verify_patch_in_git_worktree(
                    repo_root,
                    wt_name,
                    _make_multifile_mutator(file_map, replay_holder),
                )
            except (RuntimeError, ValueError, OSError) as exc:
                excluded_api_count += 1
                arm_summaries[arm_id]["excluded_api_error"] += 1
                trials.append(
                    {
                        "trial_id": attempted,
                        "arm": arm_id,
                        "arm_trial_index": arm_trial_idx,
                        "source": "llm",
                        "model_requested": model_name,
                        "model_version_reported": reported_version,
                        "temperature": STUDY_TEMPERATURE,
                        "attempt_count": attempt_count,
                        "status": "EXCLUDED_WORKTREE_ERROR",
                        "error_type": type(exc).__name__,
                        "error_message": str(exc)[:240],
                        "prompt_sha256": prompt_hash,
                        "prompt": prompt_text,
                        "candidate_sha256": candidate_hash,
                    }
                )
                continue

            valid_count += 1
            arm_summaries[arm_id]["valid"] += 1
            unified_diff = _compute_unified_diff(orig_files, file_map)

            replay_blocked = bool(replay_holder["exploit_replay_blocked"])
            if replay_blocked:
                arm_summaries[arm_id]["exploit_replay_blocked"] += 1

            auditor_says_fixed = delta.code_dataflow_risk < 0.50
            discrepancy = auditor_says_fixed != replay_blocked
            if discrepancy:
                auditor_replay_discrepancies += 1
                arm_summaries[arm_id]["auditor_vs_replay_discrepancies"] += 1

            if delta.delta_telemetry_risk <= REGRESSION_TOLERANCE:
                arm_summaries[arm_id]["tool_name_preserved_unprompted"] += 1

            if delta.patch_state == PatchClassification.HOLISTIC_REMEDIATION:
                arm_summaries[arm_id]["holistic_remediation"] += 1
            elif delta.split_brain_detected:
                if delta.delta_telemetry_risk > REGRESSION_TOLERANCE:
                    arm_summaries[arm_id]["split_brain_telemetry_drift"] += 1
                else:
                    arm_summaries[arm_id]["split_brain_iac_only"] += 1
            elif delta.patch_state in (
                PatchClassification.PURE_REGRESSION,
                PatchClassification.MIXED_REGRESSION,
            ):
                arm_summaries[arm_id]["regressions"] += 1
            else:
                arm_summaries[arm_id]["partial_or_noop"] += 1

            trials.append(
                {
                    "trial_id": attempted,
                    "arm": arm_id,
                    "arm_trial_index": arm_trial_idx,
                    "source": "llm",
                    "model_requested": model_name,
                    "model_version_reported": reported_version,
                    "temperature": STUDY_TEMPERATURE,
                    "attempt_count": attempt_count,
                    "status": "VALID",
                    "error_type": None,
                    "prompt_sha256": prompt_hash,
                    "prompt": prompt_text,
                    "candidate_sha256": candidate_hash,
                    "files_touched": delta.files_touched,
                    "patch_state": delta.patch_state.value,
                    "split_brain_detected": delta.split_brain_detected,
                    "delta_code_risk": delta.delta_code_risk,
                    "delta_iac_risk": delta.delta_iac_risk,
                    "delta_telemetry_risk": delta.delta_telemetry_risk,
                    "weighted_residual_risk": delta.weighted_residual_risk,
                    "exploit_replay_blocked": replay_blocked,
                    "exploit_replay_detail": replay_holder[
                        "exploit_replay_detail"
                    ],
                    "auditor_vs_replay_discrepancy": discrepancy,
                    "unified_diff": unified_diff,
                    "raw_model_output": raw_output,
                }
            )

            runs_artifact_path.write_text(
                json.dumps(
                    {
                        "attempted": attempted,
                        "valid": valid_count,
                        "excluded": excluded_api_count,
                        "invalid_output": invalid_output_count,
                        "arm_summaries": arm_summaries,
                        "trials": trials,
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
                newline="\n",
            )
            if inter_call_delay_sec > 0:
                time.sleep(inter_call_delay_sec)

    study_status = (
        "COMPLETED_LIVE_EMPIRICAL_STUDY"
        if valid_count >= int(planned_total * 0.7)
        else "FAILED_HIGH_EXCLUSION_RATE"
    )

    arm_a = arm_summaries["A_service_only"]
    arm_b = arm_summaries["B_service_and_tf"]
    arm_c = arm_summaries["C_full_target"]

    key_finding = (
        f"Attempted={attempted}, Valid={valid_count}, "
        f"Excluded(API)={excluded_api_count}, Invalid(Syntax)={invalid_output_count}. "
        f"In Arm A (service.py only), {arm_a['split_brain_iac_only']}/"
        f"{arm_a['valid']} valid patches produced IaC-only Split-Brain by "
        "construction (since main.tf is unseen) while preserving tool_name "
        f"unprompted in {arm_a['tool_name_preserved_unprompted']}/"
        f"{arm_a['valid']} valid trials. When given multi-file context in "
        f"Arm B (service.py + main.tf) and Arm C (full target), models "
        f"achieved Holistic Remediation across Code + Terraform IAM in "
        f"{arm_b['holistic_remediation']}/{arm_b['valid']} (Arm B) and "
        f"{arm_c['holistic_remediation']}/{arm_c['valid']} (Arm C) valid trials, "
        f"with {auditor_replay_discrepancies} static-vs-replay discrepancies."
    )

    final_payload: dict[str, Any] = {
        "status": study_status,
        "v030_audit_disclosure": (
            "In v0.3.0, finish_v030.py included a fallback function without "
            "per-trial source tagging, and Prompt 3 explicitly instructed a "
            "tool_name rename. All 20 v0.3.0 trials were retired and replaced "
            "by this zero-fallback, neutral-prompt 3-arm study."
        ),
        "models_evaluated": list(models),
        "temperature": STUDY_TEMPERATURE,
        "attempted_trials": attempted,
        "valid_trials": valid_count,
        "excluded_api_trials": excluded_api_count,
        "invalid_output_trials": invalid_output_count,
        "auditor_vs_replay_discrepancies": auditor_replay_discrepancies,
        "arm_summaries": arm_summaries,
        "key_finding": key_finding,
    }

    runs_artifact_path.write_text(
        json.dumps({**final_payload, "trials": trials}, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return final_payload
'''

CLI_PY = r'''"""Project PARALLAX Interactive CLI Demo Runner."""

from pathlib import Path

from parallax.orchestrator import run_parallax_orchestrator


def main() -> None:
    """Execute 4-stage audit and Git worktree simulation."""
    root = Path(__file__).resolve().parent.parent
    print("============================================================")
    print("Project PARALLAX: Adversarial Cloud Architecture & Patch Engine")
    print("============================================================")
    print(f"Target Workspace: {root.name}")
    print("Executing 4-Stage Audit & Git Worktree Patch Simulation...\n")

    report = run_parallax_orchestrator(root, run_worktree_simulations=True)

    print(f"Overall Posture: {report.overall_posture}")
    print(f"Total Subagent Reports: {len(report.subagent_reports)}")
    for sub in report.subagent_reports:
        print(
            f"  - [{sub.subagent_name}] Risk: {sub.risk_score:.2f} | "
            f"Findings: {len(sub.findings)}"
        )

    print("\n--- Split-Brain Remediation Evaluation (Git Worktrees) ---")
    for delta in report.split_brain_evaluations:
        print(f"  * Patch Worktree: {delta.patch_name}")
        print(
            f"    Weighted Residual Risk   : {delta.weighted_residual_risk:.2f}"
        )
        print(f"    Split-Brain Detected     : {delta.split_brain_detected}")
        print(f"    Classification           : {delta.patch_state.value}")
        print(f"    Summary                  : {delta.summary}\n")


if __name__ == "__main__":
    main()
'''

TEST_PHASE3_PY = r'''"""Verification Gate 3: Unit & Integration Tests for Subagents 01-04."""

from pathlib import Path
import subprocess

from parallax.cross_layer_auditor import run_cross_layer_auditor
from parallax.graph_analyzer import run_graph_analyzer
from parallax.orchestrator import (
    apply_holistic_architectural_patch,
    apply_symptom_only_ide_patch,
    run_parallax_orchestrator,
)
from parallax.patch_verifier import (
    evaluate_directory_delta,
    score_directory_layers,
)
from parallax.telemetry_validator import run_telemetry_validator

ROOT_DIR = Path(__file__).resolve().parent.parent


def _ensure_git_commit_exists(repo_dir: Path) -> None:
    """Ensure local repo has at least one commit so git worktree add HEAD works."""
    check = subprocess.run(  # noqa: S603
        ["git", "rev-parse", "--verify", "HEAD"],  # noqa: S607
        cwd=str(repo_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    if check.returncode != 0:
        cmds = [
            ["git", "config", "user.email", "parallax@local.test"],
            ["git", "config", "user.name", "Parallax Auditor"],
            ["git", "add", "."],
            [
                "git",
                "commit",
                "-m",
                "chore: baseline snapshot for worktree testing",
            ],
        ]
        for cmd in cmds:
            subprocess.run(cmd, cwd=str(repo_dir), check=True)  # noqa: S603


def test_gate3_subagent01_graph_analyzer_detects_nhi_escalation() -> None:
    """Verify Subagent 01 finds Cloud Run -> SA -> project Secret Manager path."""
    report = run_graph_analyzer(ROOT_DIR)
    assert report.risk_score >= 0.90
    assert len(report.findings) == 2
    titles = " | ".join(f.title for f in report.findings)
    assert "roles/secretmanager.secretAccessor" in titles
    assert "roles/iam.serviceAccountTokenCreator" in titles


def test_gate3_subagent02_ast_auditor_detects_fallback_bypass() -> None:
    """Verify Subagent 02 detects unvalidated fallback_secret_id in service.py."""
    report = run_cross_layer_auditor(ROOT_DIR, iam_risk_score=0.95)
    assert report.risk_score == 0.95
    assert len(report.findings) == 1
    assert report.findings[0].finding_id == "PARALLAX-AST-001"


def test_gate3_subagent04_telemetry_validator_baseline_clean() -> None:
    """Verify baseline service.py matches secops/rules.yaml before refactor."""
    report = run_telemetry_validator(ROOT_DIR)
    assert report.risk_score < 0.2
    assert len(report.findings) == 0


def test_gate3_split_brain_differential_mathematics(tmp_path: Path) -> None:
    """Prove symptom patch triggers Split-Brain while holistic patch resolves all."""
    for rel in ("infra/main.tf", "app/service.py", "secops/rules.yaml"):
        src = ROOT_DIR / "benchmark_target" / rel
        dst = tmp_path / "benchmark_target" / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

    baseline_scores = score_directory_layers(tmp_path)

    apply_symptom_only_ide_patch(tmp_path)
    symptom_delta = evaluate_directory_delta(
        tmp_path, "unit-symptom-patch", baseline_scores=baseline_scores
    )
    assert symptom_delta.code_dataflow_risk < 0.2
    assert symptom_delta.iac_reachability_risk >= 0.9
    assert symptom_delta.telemetry_blindspot_risk >= 0.8
    assert symptom_delta.split_brain_detected is True

    orig_service = ROOT_DIR / "benchmark_target" / "app" / "service.py"
    (tmp_path / "benchmark_target" / "app" / "service.py").write_text(
        orig_service.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    apply_holistic_architectural_patch(tmp_path)
    holistic_delta = evaluate_directory_delta(
        tmp_path, "unit-holistic-patch", baseline_scores=baseline_scores
    )
    assert holistic_delta.code_dataflow_risk < 0.2
    assert holistic_delta.iac_reachability_risk < 0.2
    assert holistic_delta.telemetry_blindspot_risk < 0.2
    assert holistic_delta.split_brain_detected is False


def test_gate3_end_to_end_orchestrator_with_git_worktrees() -> None:
    """Verify full Orchestrator execution with real isolated Git worktrees."""
    _ensure_git_commit_exists(ROOT_DIR)
    orchestrator_report = run_parallax_orchestrator(
        ROOT_DIR, run_worktree_simulations=True
    )

    assert orchestrator_report.overall_posture == "CRITICAL_SPLIT_BRAIN_RISK_PROVEN"
    assert len(orchestrator_report.split_brain_evaluations) == 3

    by_name = {d.patch_name: d for d in orchestrator_report.split_brain_evaluations}
    assert by_name["wt-symptom-patch"].split_brain_detected is True
    assert by_name["wt-architectural-patch"].split_brain_detected is False
    assert (
        by_name["wt-architectural-patch"].weighted_residual_risk
        < by_name["wt-symptom-patch"].weighted_residual_risk
    )
'''

TEST_V2_HARDENING_PY = r'''"""Verification Gate 4: Complete P1 & P2 Hardening and Mutation Test Suite."""

from pathlib import Path

import pytest

from parallax.cross_layer_auditor import (
    evaluate_auditor_precision_recall,
    run_cross_layer_auditor,
    run_exploit_replay_ground_truth,
)
from parallax.graph_analyzer import run_graph_analyzer
from parallax.orchestrator import (
    apply_holistic_architectural_patch,
    apply_symptom_only_ide_patch,
)
from parallax.patch_verifier import (
    evaluate_directory_delta,
    score_directory_layers,
    validate_base_ref,
    validate_worktree_path,
    verify_patch_in_git_worktree,
)
from parallax.schemas import PatchClassification, Severity
from parallax.telemetry_validator import run_telemetry_validator

ROOT_DIR = Path(__file__).resolve().parent.parent


def _copy_baseline_to_tmp(tmp_path: Path) -> None:
    """Copy benchmark_target files into isolated tmp_path."""
    for rel in ("infra/main.tf", "app/service.py", "secops/rules.yaml"):
        src = ROOT_DIR / "benchmark_target" / rel
        dst = tmp_path / "benchmark_target" / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")


def test_p1_path_traversal_and_base_ref_option_injection_rejected() -> None:
    """Prove worktree path and base_ref validators block unsafe inputs."""
    for unsafe_name in ("../escape", "..\\escape", "/root/evil", "bad/slash", ""):
        with pytest.raises(ValueError, match="Unsafe worktree_name"):
            validate_worktree_path(ROOT_DIR, unsafe_name)

    for unsafe_ref in ("--upload-pack=evil", "-f", "--detach", ""):
        with pytest.raises(ValueError, match="Unsafe base_ref"):
            validate_base_ref(ROOT_DIR, unsafe_ref)


def test_p1_graph_and_ast_auditor_fail_closed_mutations(tmp_path: Path) -> None:
    """Prove Subagents 01 and 02 fail closed (1.0 CRITICAL) on deleted/corrupt files."""
    _copy_baseline_to_tmp(tmp_path)
    tf_path = tmp_path / "benchmark_target" / "infra" / "main.tf"
    svc_path = tmp_path / "benchmark_target" / "app" / "service.py"

    # 1. Empty main.tf -> 1.0 CRITICAL
    tf_path.write_text("   \n", encoding="utf-8")
    r_empty_tf = run_graph_analyzer(tmp_path)
    assert r_empty_tf.risk_score == 1.0
    assert r_empty_tf.findings[0].severity == Severity.CRITICAL

    # 2. Malformed HCL in main.tf -> 1.0 CRITICAL
    tf_path.write_text("resource {{{ unclosed_hcl", encoding="utf-8")
    r_corrupt_tf = run_graph_analyzer(tmp_path)
    assert r_corrupt_tf.risk_score == 1.0
    assert r_corrupt_tf.findings[0].finding_id == "PARALLAX-IAM-CORRUPT"

    # 3. Deleted main.tf -> 1.0 CRITICAL
    tf_path.unlink()
    r_missing_tf = run_graph_analyzer(tmp_path)
    assert r_missing_tf.risk_score == 1.0
    assert r_missing_tf.findings[0].finding_id == "PARALLAX-IAM-MISSING"

    # 4. service.py with execute_agent_tool removed -> 1.0 CRITICAL
    svc_path.write_text("x = 1\n", encoding="utf-8")
    r_no_handler = run_cross_layer_auditor(tmp_path, enable_llm_enrichment=False)
    assert r_no_handler.risk_score == 1.0
    assert r_no_handler.findings[0].finding_id == "PARALLAX-AST-MISSING-HANDLER"

    # 5. Syntax error in service.py -> 1.0 CRITICAL
    svc_path.write_text("def broken(\n", encoding="utf-8")
    r_syntax = run_cross_layer_auditor(tmp_path, enable_llm_enrichment=False)
    assert r_syntax.risk_score == 1.0
    assert r_syntax.findings[0].finding_id == "PARALLAX-AST-SYNTAX"

    # 6. Deleted service.py -> 1.0 CRITICAL
    svc_path.unlink()
    r_missing_py = run_cross_layer_auditor(tmp_path, enable_llm_enrichment=False)
    assert r_missing_py.risk_score == 1.0
    assert r_missing_py.findings[0].finding_id == "PARALLAX-AST-MISSING"


def test_p1_exploit_replay_ground_truth(tmp_path: Path) -> None:
    """Prove runtime exploit replay detects baseline flaw and verifies fix."""
    _copy_baseline_to_tmp(tmp_path)
    blocked_before, detail_before = run_exploit_replay_ground_truth(tmp_path)
    assert blocked_before is False
    assert "prod-master-db" in detail_before

    apply_holistic_architectural_patch(tmp_path)
    blocked_after, detail_after = run_exploit_replay_ground_truth(tmp_path)
    assert blocked_after is True
    assert "Blocked" in detail_after


def test_p1_git_status_porcelain_z_handles_spaces() -> None:
    """Prove git status --porcelain -z parses filenames containing spaces."""

    def _mutate_with_spaced_file(wt_root: Path) -> None:
        apply_symptom_only_ide_patch(wt_root)
        spaced = wt_root / "benchmark_target" / "app" / "notes with spaces.txt"
        spaced.write_text("audit log note\n", encoding="utf-8")

    delta, report = verify_patch_in_git_worktree(
        ROOT_DIR, "wt-spaced-path", _mutate_with_spaced_file
    )
    assert "benchmark_target/app/notes with spaces.txt" in delta.files_touched
    assert report.findings[0].file_path == "benchmark_target/secops/rules.yaml"


def test_p2_noop_patch_on_already_clean_tree_returns_noop_baseline(
    tmp_path: Path,
) -> None:
    """Prove a no-op patch on an already-clean tree returns NO_OP_BASELINE."""
    _copy_baseline_to_tmp(tmp_path)
    apply_holistic_architectural_patch(tmp_path)
    clean_baseline = score_directory_layers(tmp_path)
    assert clean_baseline == (0.10, 0.05, 0.05)

    clean_noop = evaluate_directory_delta(
        tmp_path, "already-clean-noop", baseline_scores=clean_baseline
    )
    assert clean_noop.patch_state == PatchClassification.NO_OP_BASELINE
    assert clean_noop.split_brain_detected is False


def test_p2_small_code_gain_plus_large_telemetry_regression_is_mixed_regression(
    tmp_path: Path,
) -> None:
    """Prove d_code=-0.20 + d_tel=+0.80 classifies as MIXED_REGRESSION."""
    _copy_baseline_to_tmp(tmp_path)
    baseline = score_directory_layers(tmp_path)

    apply_symptom_only_ide_patch(tmp_path)
    svc_path = tmp_path / "benchmark_target" / "app" / "service.py"
    svc_code = svc_path.read_text(encoding="utf-8").replace(
        "if not primary_id.startswith(ALLOWED_WORKSPACE_PREFIX):",
        "if False:",
    )
    svc_path.write_text(svc_code, encoding="utf-8")

    mixed_delta = evaluate_directory_delta(
        tmp_path, "small-code-gain-big-reg", baseline_scores=baseline
    )
    assert mixed_delta.delta_code_risk == -0.20
    assert mixed_delta.delta_telemetry_risk == 0.80
    assert mixed_delta.patch_state == PatchClassification.MIXED_REGRESSION


def test_p2_telem_fail_closed_corrupt_input_syntax_and_yaml(
    tmp_path: Path,
) -> None:
    """Prove TELEM_FAIL_CLOSED_CORRUPT_INPUT fires on bad Python and bad YAML."""
    _copy_baseline_to_tmp(tmp_path)
    rules_path = tmp_path / "benchmark_target" / "secops" / "rules.yaml"
    svc_path = tmp_path / "benchmark_target" / "app" / "service.py"

    # 1. Malformed YAML syntax
    rules_path.write_text("rules: [unclosed_yaml_list\n", encoding="utf-8")
    corrupt_yaml = run_telemetry_validator(tmp_path)
    assert corrupt_yaml.risk_score == 1.0
    assert (
        corrupt_yaml.findings[0].finding_id == "TELEM_FAIL_CLOSED_CORRUPT_INPUT"
    )

    # 2. Syntax-error service.py
    _copy_baseline_to_tmp(tmp_path)
    svc_path.write_text("def unclosed_func(\n", encoding="utf-8")
    corrupt_py = run_telemetry_validator(tmp_path)
    assert corrupt_py.risk_score == 1.0
    assert (
        corrupt_py.findings[0].finding_id == "TELEM_FAIL_CLOSED_CORRUPT_INPUT"
    )


def test_p2_telem_fail_closed_empty_and_missing_rules(tmp_path: Path) -> None:
    """Prove empty rules list, empty YAML, and deleted rules.yaml fail closed."""
    _copy_baseline_to_tmp(tmp_path)
    rules_path = tmp_path / "benchmark_target" / "secops" / "rules.yaml"

    rules_path.write_text("rules: []\n", encoding="utf-8")
    zero_rules = run_telemetry_validator(tmp_path)
    assert zero_rules.risk_score == 1.0
    assert zero_rules.findings[0].finding_id == "TELEM_FAIL_CLOSED_ZERO_RULES"

    rules_path.write_text("", encoding="utf-8")
    empty_yaml = run_telemetry_validator(tmp_path)
    assert empty_yaml.risk_score == 1.0
    assert empty_yaml.findings[0].finding_id == "TELEM_FAIL_CLOSED_EMPTY_RULES"

    rules_path.unlink()
    missing_yaml = run_telemetry_validator(tmp_path)
    assert missing_yaml.risk_score == 1.0
    assert (
        missing_yaml.findings[0].finding_id == "TELEM_FAIL_CLOSED_MISSING_FILE"
    )


def test_p2_telem_audit_event_class_removed_and_zero_emissions(
    tmp_path: Path,
) -> None:
    """Prove removing AuditEvent class OR removing emissions fails closed (1.0)."""
    _copy_baseline_to_tmp(tmp_path)
    svc_path = tmp_path / "benchmark_target" / "app" / "service.py"
    orig_code = svc_path.read_text(encoding="utf-8")

    # 1. AuditEvent class renamed/removed
    svc_path.write_text(
        orig_code.replace("class AuditEvent(", "class OtherEvent("),
        encoding="utf-8",
    )
    no_class = run_telemetry_validator(tmp_path)
    assert no_class.risk_score == 1.0
    assert (
        no_class.findings[0].finding_id
        == "TELEM_FAIL_CLOSED_MISSING_AUDIT_CLASS"
    )

    # 2. AuditEvent class kept, but zero AuditEvent(...) calls in code
    svc_path.write_text(
        orig_code.replace("audit = AuditEvent(", "audit = dict("),
        encoding="utf-8",
    )
    no_emission = run_telemetry_validator(tmp_path)
    assert no_emission.risk_score == 1.0
    assert (
        no_emission.findings[0].finding_id == "TELEM_FAIL_CLOSED_NO_EMISSION"
    )


def test_p2_telem_null_match_non_dict_missing_and_duplicate_rule_id(
    tmp_path: Path,
) -> None:
    """Prove non-dict rule, null match, missing rule_id, and duplicate rule_id fire."""
    _copy_baseline_to_tmp(tmp_path)
    rules_path = tmp_path / "benchmark_target" / "secops" / "rules.yaml"
    rules_path.write_text(
        "\n".join(
            [
                "rules:",
                '  - "not_a_dict_entry"',
                "  - severity: 'MEDIUM'",
                "    match:",
                "      event_type: 'SECRET_MANAGER_ACCESS'",
                "      tool_name: 'read_workspace_context'",
                "  - rule_id: 'SECOPS_DUP'",
                "    severity: 'HIGH'",
                "    match: null",
                "  - rule_id: 'SECOPS_DUP'",
                "    severity: 'CRITICAL'",
                "    match:",
                "      event_type: 'SECRET_MANAGER_ACCESS'",
                "      tool_name: 'read_workspace_context'",
            ]
        ),
        encoding="utf-8",
    )
    report = run_telemetry_validator(tmp_path)
    f_ids = {f.finding_id for f in report.findings}
    assert "TELEM_MALFORMED_RULE_ENTRY_1" in f_ids
    assert "TELEM_MISSING_RULE_ID_2" in f_ids
    assert "TELEM_INVALID_MATCH_SECOPS_DUP" in f_ids
    assert "TELEM_DUPLICATE_RULE_ID_SECOPS_DUP" in f_ids


def test_p2_telem_predicate_mismatch_on_allowed_and_caller_identity(
    tmp_path: Path,
) -> None:
    """Prove rule predicates on allowed/caller_identity fail when sample differs."""
    _copy_baseline_to_tmp(tmp_path)
    rules_path = tmp_path / "benchmark_target" / "secops" / "rules.yaml"
    rules_path.write_text(
        "\n".join(
            [
                "rules:",
                "  - rule_id: 'SECOPS_DENY_ONLY'",
                "    severity: 'HIGH'",
                "    match:",
                "      event_type: 'SECRET_MANAGER_ACCESS'",
                "      tool_name: 'read_workspace_context'",
                "      allowed: false",
                "  - rule_id: 'SECOPS_ADMIN_CALLER'",
                "    severity: 'CRITICAL'",
                "    match:",
                "      event_type: 'SECRET_MANAGER_ACCESS'",
                "      tool_name: 'read_workspace_context'",
                "      caller_identity: 'user:root_admin'",
            ]
        ),
        encoding="utf-8",
    )
    report = run_telemetry_validator(tmp_path)
    f_ids = {f.finding_id for f in report.findings}
    assert "TELEM_CONTRACT_MISMATCH_SECOPS_DENY_ONLY" in f_ids
    assert "TELEM_CONTRACT_MISMATCH_SECOPS_ADMIN_CALLER" in f_ids
    assert report.risk_score >= 0.85


def test_p2_telemetry_bidirectional_unmonitored_tool_and_dynamic_ast(
    tmp_path: Path,
) -> None:
    """Prove reverse coverage check catches unmonitored tools and dynamic AST."""
    _copy_baseline_to_tmp(tmp_path)
    svc_path = tmp_path / "benchmark_target" / "app" / "service.py"
    code = svc_path.read_text(encoding="utf-8")

    extra_code = "\n".join(
        [
            "",
            "",
            "def unmonitored_helper(mode: str) -> AuditEvent:",
            "    _ = AuditEvent(",
            "        event_type='SECRET_MANAGER_ACCESS',",
            "        caller_identity='user:alice',",
            "        service_account='sa@project.iam.gserviceaccount.com',",
            "        tool_name=f'dynamic_{mode}',",
            "        target_secret='workspace-doc-1',",
            "        allowed=True,",
            "    )",
            "    return AuditEvent(",
            "        event_type='SECRET_MANAGER_ACCESS',",
            "        caller_identity='user:alice',",
            "        service_account='sa@project.iam.gserviceaccount.com',",
            "        tool_name='export_bigquery_dataset',",
            "        target_secret='workspace-doc-1',",
            "        allowed=True,",
            "    )",
            "",
        ]
    )
    svc_path.write_text(code + extra_code, encoding="utf-8")

    report = run_telemetry_validator(tmp_path)
    assert report.risk_score > 0.05
    finding_ids = {f.finding_id for f in report.findings}
    assert "TELEM_UNMONITORED_TOOL_EXPORT_BIGQUERY_DATASET" in finding_ids
    assert any(
        "dynamic AuditEvent.tool_name" in q for q in report.open_questions
    )


def test_p2_telemetry_proportional_scoring_and_field_drift(
    tmp_path: Path,
) -> None:
    """Prove breaking 1 of 2 rules scores proportionally and catches field drift."""
    _copy_baseline_to_tmp(tmp_path)
    rules_path = tmp_path / "benchmark_target" / "secops" / "rules.yaml"
    rules_text = rules_path.read_text(encoding="utf-8")

    broken_one = rules_text.replace(
        'tool_name: "read_workspace_context"',
        'tool_name: "legacy_tool_name"',
        1,
    )
    rules_path.write_text(broken_one, encoding="utf-8")
    partial_report = run_telemetry_validator(tmp_path)
    assert 0.35 <= partial_report.risk_score < 0.85

    svc_path = tmp_path / "benchmark_target" / "app" / "service.py"
    svc_text = svc_path.read_text(encoding="utf-8").replace(
        "target_secret: str", "secret_uri: str"
    )
    svc_path.write_text(svc_text, encoding="utf-8")
    drift_report = run_telemetry_validator(tmp_path)
    assert any(
        "TELEM_SCHEMA_DRIFT" in f.finding_id for f in drift_report.findings
    )


def test_p2_auditor_adversarial_seeds_beyond_10() -> None:
    """Prove 16-case AST benchmark measures true precision/recall boundaries."""
    metrics = evaluate_auditor_precision_recall()
    assert metrics["total_cases"] == 16.0
    assert metrics["true_positives"] >= 5.0
    assert metrics["true_negatives"] >= 7.0
    assert metrics["false_positives"] >= 1.0
    assert metrics["false_negatives"] >= 1.0
    assert 0.70 <= metrics["precision"] < 1.0
    assert 0.65 <= metrics["recall"] < 1.0
'''


def _build_dynamic_readme(
    pytest_summary: str,
    mypy_summary: str,
    ruff_summary: str,
    ast_metrics: dict[str, float],
    study_data: dict[str, Any],
) -> str:
    """Generate README.md strictly from measured tool and empirical outputs."""
    arms = study_data.get("arm_summaries", {})
    a = arms.get("A_service_only", {})
    b = arms.get("B_service_and_tf", {})
    c = arms.get("C_full_target", {})

    passed_badge = pytest_summary.split(" in ")[0].replace(" ", "_")
    readme = f"""# Project PARALLAX (v0.4.0)

**Adversarial Cloud Architecture & Split-Brain Patch Verification Engine for Google Cloud (GCP)**

![CI Gate](https://github.com/Cyberzal1/project-parallax/actions/workflows/ci.yml/badge.svg)
![Python 3.13](https://img.shields.io/badge/Python-3.13.14-3776AB?logo=python&logoColor=white)
![GCP Terraform](https://img.shields.io/badge/GCP_IaC-Terraform_HCL2-4285F4?logo=googlecloud&logoColor=white)
![Typecheck](https://img.shields.io/badge/mypy-strict_pass-brightgreen)
![Tests](https://img.shields.io/badge/pytest-{passed_badge}-brightgreen)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

> *"Why finding vulnerabilities faster won't save you, and what will."*
> — Inspired by the **Google AI Threat Defense** 4-Step Framework (**Prepare, Scan, Remediate, Monitor**).

---

## 1. Executive Summary & Multi-Arm Empirical Study

**Project PARALLAX** investigates and tests **Cross-Layer Remediation Divergence ("Split-Brain AI Patching")** across application code (`service.py`), cloud infrastructure (`main.tf`), and detection engineering (`rules.yaml`).

### 1.1 v0.3.0 Audit Disclosure & v0.4.0 Study Integrity

In v0.3.0, our study script included a rate-limit fallback completion without per-trial `source` tagging, and one of the four prompts (`v2_handler_modernization`) explicitly instructed the model to rename `tool_name` to `read_workspace_context_v2`. All 20 v0.3.0 results were retired.

In **v0.4.0** (`parallax/empirical_study.py`), **all fallbacks are removed**:
* Failed or empty API calls are logged with `error_type` and marked `EXCLUDED_API_ERROR`.
* Candidate outputs are gated with `ast.parse()` (`INVALID_OUTPUT` on syntax errors).
* Every trial is persisted incrementally to `artifacts/empirical_study_runs.json` with `source="llm"`, `attempt_count`, `temperature={study_data.get('temperature', 0.2)}`, `model_version_reported`, `prompt_sha256`, `prompt`, `candidate_sha256`, `unified_diff`, and runtime **exploit-replay ground truth** (`run_exploit_replay_ground_truth`).

### 1.2 Live 3-Arm Context-Scope Experiment (`gemini-2.5-flash` & `gemini-2.5-flash-lite`)

Using a **strictly neutral security-fix prompt** (no rename instructions) across 3 context-scope arms (`10` trials per arm, `30` total attempted):

| Context-Scope Arm | Attempted / Valid / Excluded(API) / Invalid(Syntax) | Holistic Fix (Code + IAM) | Split-Brain (IaC-Only) | Split-Brain (Telemetry Drift) | Unprompted `tool_name` Preserved | Runtime Exploit Blocked | Auditor vs. Replay Discrepancies |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Arm A (`service.py` only — Control)** | `{a.get('attempted', 0)} / {a.get('valid', 0)} / {a.get('excluded_api_error', 0)} / {a.get('invalid_output', 0)}` | `{a.get('holistic_remediation', 0)} / {a.get('valid', 0)}` | `{a.get('split_brain_iac_only', 0)} / {a.get('valid', 0)}` | `{a.get('split_brain_telemetry_drift', 0)} / {a.get('valid', 0)}` | `{a.get('tool_name_preserved_unprompted', 0)} / {a.get('valid', 0)}` | `{a.get('exploit_replay_blocked', 0)} / {a.get('valid', 0)}` | `{a.get('auditor_vs_replay_discrepancies', 0)}` |
| **Arm B (`service.py` + `main.tf`)** | `{b.get('attempted', 0)} / {b.get('valid', 0)} / {b.get('excluded_api_error', 0)} / {b.get('invalid_output', 0)}` | `{b.get('holistic_remediation', 0)} / {b.get('valid', 0)}` | `{b.get('split_brain_iac_only', 0)} / {b.get('valid', 0)}` | `{b.get('split_brain_telemetry_drift', 0)} / {b.get('valid', 0)}` | `{b.get('tool_name_preserved_unprompted', 0)} / {b.get('valid', 0)}` | `{b.get('exploit_replay_blocked', 0)} / {b.get('valid', 0)}` | `{b.get('auditor_vs_replay_discrepancies', 0)}` |
| **Arm C (`service.py` + `main.tf` + `rules.yaml`)** | `{c.get('attempted', 0)} / {c.get('valid', 0)} / {c.get('excluded_api_error', 0)} / {c.get('invalid_output', 0)}` | `{c.get('holistic_remediation', 0)} / {c.get('valid', 0)}` | `{c.get('split_brain_iac_only', 0)} / {c.get('valid', 0)}` | `{c.get('split_brain_telemetry_drift', 0)} / {c.get('valid', 0)}` | `{c.get('tool_name_preserved_unprompted', 0)} / {c.get('valid', 0)}` | `{c.get('exploit_replay_blocked', 0)} / {c.get('valid', 0)}` | `{c.get('auditor_vs_replay_discrepancies', 0)}` |

* **Measured Finding:** {study_data.get('key_finding', '')}

### 1.3 Deterministic Worktree Benchmark (Before vs. After State Transitions)

| Worktree Simulation | Files Touched (`git status -z`) | Code AST Risk ($R_{{\\text{{Code}}}}$ / $\\Delta$) | GCP IaC Risk ($R_{{\\text{{IaC}}}}$ / $\\Delta$) | SecOps Telemetry Risk ($R_{{\\text{{Tel}}}}$ / $\\Delta$) | Weighted Residual Risk | Classification |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`baseline-unpatched`** | `[]` *(0 files)* | `0.95` (`+0.00`) | `0.95` (`+0.00`) | `0.05` (`+0.00`) | **`0.77`** | `NO_OP_BASELINE` |
| **`wt-symptom-patch`** *(Synthetic Rename + Code Fix)* | `["benchmark_target/app/service.py"]` | `0.05` (**`-0.90`**) | `0.95` (`+0.00`) | `0.85` (**`+0.80`**) | **`0.61`** | **`SPLIT_BRAIN_REMEDIATION` [!]** |
| **`wt-architectural-patch`** *(Synthetic Holistic Fix)* | `[".../service.py", ".../main.tf"]` | `0.05` (**`-0.90`**) | `0.10` (**`-0.85`**) | `0.05` (`+0.00`) | **`0.07`** | **`HOLISTIC_REMEDIATION` [OK]** |

---

## 2. Threat Model, Categorical Scores & Limitations

1. **Synthetic Target & Categorical State Scores:** `benchmark_target/` is a synthetic testbed. Layer risk scores (`0.95`, `0.60`, `0.10`, `0.05`, `1.00` fail-closed) represent discrete architectural states rather than continuous probabilities. `weighted_residual_risk` ($0.45 R_{{\\text{{IaC}}}} + 0.35 R_{{\\text{{Code}}}} + 0.20 R_{{\\text{{Tel}}}}$) measures the weighted post-patch state, while $\\Delta R_L = R_{{\\text{{after}}, L}} - R_{{\\text{{before}}, L}}$ measures state transitions.
2. **Static AST Precision/Recall vs. Runtime Replay (`parallax/cross_layer_auditor.py`):** Across our 16-case adversarial AST seed suite (`evaluate_auditor_precision_recall()`), static AST inspection achieves **Precision = `{ast_metrics['precision']}`** and **Recall = `{ast_metrics['recall']}`** (`TP={int(ast_metrics['true_positives'])}, FP={int(ast_metrics['false_positives'])}, TN={int(ast_metrics['true_negatives'])}, FN={int(ast_metrics['false_negatives'])}`). Specifically, regex guards (`re.match`) can produce static false positives, while tuple-unpacking or ternary assignments can produce static false negatives. To catch static false negatives, PARALLAX pairs Subagent 02 with `run_exploit_replay_ground_truth()`.
3. **Simplified YAML Rules vs. Google SecOps YARA-L:** `benchmark_target/secops/rules.yaml` uses a simplified YAML predicate format evaluated against AST-extracted `AuditEvent` keyword arguments rather than full YARA-L 2.0 syntax.

---

## 3. Quickstart & Deterministic Verification

{FENCE}powershell
# 1. Create and activate virtual environment (Windows PowerShell)
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1

# 2. Install pinned dependencies
pip install -r requirements.txt

# 3. Run the 3-part verification gate
ruff check parallax benchmark_target tests   # -> {ruff_summary}
mypy parallax benchmark_target tests         # -> {mypy_summary}
pytest                                       # -> {pytest_summary}

# 4. Run the interactive CLI Split-Brain simulation
python -m parallax.cli
{FENCE}

* **Artifacts:** See `artifacts/parallax_audit_proof.json` and `artifacts/empirical_study_runs.json` for full per-trial prompts, raw model outputs, hashes, diffs, and replay results.

---

## 4. License

Released under the [MIT License](LICENSE).
"""
    return readme


def write_utf8_lf(path: Path, content: str) -> None:
    """Write text file with UTF-8 encoding (no BOM) and LF line endings."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.lstrip("\ufeff"), encoding="utf-8", newline="\n")
    print(f"[OK] Wrote {path.relative_to(ROOT).as_posix()}")


def _capture_gate_output(cmd: list[str]) -> str:
    """Run verification tool and return actual stdout summary line."""
    proc = subprocess.run(  # noqa: S603
        cmd,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=True,
        encoding="utf-8",
    )
    lines = [
        line.strip()
        for line in (proc.stdout or "").splitlines()
        if line.strip()
    ]
    return lines[-1] if lines else "OK"


def main() -> None:
    """Write PARALLAX v0.4.0 modules, run gates, and execute 3-arm study."""
    write_utf8_lf(ROOT / "parallax" / "schemas.py", SCHEMAS_PY)
    write_utf8_lf(ROOT / "parallax" / "graph_analyzer.py", GRAPH_ANALYZER_PY)
    write_utf8_lf(ROOT / "parallax" / "ast_utils.py", AST_UTILS_PY)
    write_utf8_lf(
        ROOT / "parallax" / "cross_layer_auditor.py", CROSS_LAYER_AUDITOR_PY
    )
    write_utf8_lf(
        ROOT / "parallax" / "telemetry_validator.py", TELEMETRY_VALIDATOR_PY
    )
    write_utf8_lf(ROOT / "parallax" / "patch_verifier.py", PATCH_VERIFIER_PY)
    write_utf8_lf(ROOT / "parallax" / "empirical_study.py", EMPIRICAL_STUDY_PY)
    write_utf8_lf(ROOT / "parallax" / "cli.py", CLI_PY)
    write_utf8_lf(
        ROOT / "tests" / "test_phase3_subagents.py", TEST_PHASE3_PY
    )
    write_utf8_lf(ROOT / "tests" / "test_v2_hardening.py", TEST_V2_HARDENING_PY)

    pyproject_path = ROOT / "pyproject.toml"
    if pyproject_path.exists():
        pyproject_text = (
            pyproject_path.read_text(encoding="utf-8")
            .replace('version = "0.2.0"', 'version = "0.4.0"')
            .replace('version = "0.3.0"', 'version = "0.4.0"')
        )
        write_utf8_lf(pyproject_path, pyproject_text)

    print("\n--- Formatting & Auto-Organizing Imports ---")
    subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            "--fix",
            "parallax",
            "benchmark_target",
            "tests",
        ],
        cwd=str(ROOT),
        check=False,
    )
    subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "ruff",
            "format",
            "parallax",
            "benchmark_target",
            "tests",
        ],
        cwd=str(ROOT),
        check=True,
    )

    print("\n--- Running Strict Verification Gates ---")
    ruff_out = _capture_gate_output(
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            "parallax",
            "benchmark_target",
            "tests",
        ]
    )
    print(f"Ruff  : {ruff_out}")

    mypy_out = _capture_gate_output(
        [sys.executable, "-m", "mypy", "parallax", "benchmark_target", "tests"]
    )
    print(f"Mypy  : {mypy_out}")

    pytest_out = _capture_gate_output([sys.executable, "-m", "pytest", "-q"])
    print(f"Pytest: {pytest_out}")

    print("\n--- Running 3-Arm Multi-Model Empirical Study (30 Trials) ---")
    from parallax.cross_layer_auditor import evaluate_auditor_precision_recall
    from parallax.empirical_study import run_empirical_gemini_patch_study
    from parallax.orchestrator import run_parallax_orchestrator

    ast_metrics = evaluate_auditor_precision_recall()
    report = run_parallax_orchestrator(ROOT)
    empirical_study = run_empirical_gemini_patch_study(
        ROOT, trials_per_arm=10, inter_call_delay_sec=0.5
    )

    readme_md = _build_dynamic_readme(
        pytest_out, mypy_out, ruff_out, ast_metrics, empirical_study
    )
    write_utf8_lf(ROOT / "README.md", readme_md)

    proof_payload = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "engine": "Project PARALLAX v0.4.0",
        "seeded_auditor_metrics": ast_metrics,
        "verification_gates": {
            "pytest": pytest_out,
            "mypy_strict": mypy_out,
            "ruff_lint": ruff_out,
        },
        "empirical_llm_patch_study": empirical_study,
        "orchestrator_report": report.model_dump(mode="json"),
    }
    proof_path = ROOT / "artifacts" / "parallax_audit_proof.json"
    write_utf8_lf(proof_path, json.dumps(proof_payload, indent=2) + "\n")

    print("\n[MEASURED EMPIRICAL STUDY SUMMARY]:")
    print(empirical_study.get("key_finding", ""))


if __name__ == "__main__":
    main()