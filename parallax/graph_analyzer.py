"""Subagent 01: GCP Terraform IAM Graph Analyzer (Countering 01 Prepare)."""

import json
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


def _extract_sa_identifiers(tf_data: dict[str, Any]) -> set[str]:
    """Extract all declared google_service_account resource names and IDs."""
    sa_ids: set[str] = set()
    for block in tf_data.get("resource", []):
        if isinstance(block, dict) and "google_service_account" in block:
            for res_name, body in block["google_service_account"].items():
                sa_ids.add(res_name)
                if isinstance(body, dict) and body.get("account_id"):
                    sa_ids.add(str(body["account_id"]))
    return sa_ids


def _member_matches_service_account(member_str: str, declared_sas: set[str]) -> bool:
    """Check if an IAM member string references a workload service account."""
    if "serviceAccount:" in member_str or "google_service_account." in member_str:
        return True
    return any(sa in member_str for sa in declared_sas)


def _validate_scoped_secret_bindings(
    tf_data: dict[str, Any],
    rel_tf: str,
) -> list[Finding]:
    """Detect placeholder secret_ids (e.g. 'workspace-doc-') or dangling each.key."""
    declared_secrets: set[str] = set()
    for block in tf_data.get("resource", []):
        if isinstance(block, dict) and "google_secret_manager_secret" in block:
            for sec_res_name, sec_body in block["google_secret_manager_secret"].items():
                declared_secrets.add(sec_res_name)
                if isinstance(sec_body, dict) and sec_body.get("secret_id"):
                    declared_secrets.add(str(sec_body["secret_id"]))

    issues: list[Finding] = []
    for block in tf_data.get("resource", []):
        if not isinstance(block, dict):
            continue
        for res_type in (
            "google_secret_manager_secret_iam_member",
            "google_secret_manager_secret_iam_binding",
            "google_secret_manager_secret_iam_policy",
        ):
            if res_type not in block:
                continue
            for bind_name, bind_body in block[res_type].items():
                if not isinstance(bind_body, dict):
                    continue
                sec_id = str(bind_body.get("secret_id", "")).strip()
                has_for_each = "for_each" in bind_body
                is_prefix_placeholder = sec_id.endswith("-") or sec_id in (
                    "",
                    "workspace-doc",
                    "placeholder",
                    "TODO",
                )
                is_dangling_each = "each." in sec_id and not has_for_each
                is_unresolved_ref = (
                    "google_secret_manager_secret." in sec_id
                    and not any(
                        f"google_secret_manager_secret.{s}" in sec_id
                        for s in declared_secrets
                    )
                )
                if is_prefix_placeholder or is_dangling_each or is_unresolved_ref:
                    issues.append(
                        Finding(
                            finding_id=f"PARALLAX-IAM-INVALID-SCOPED-SECRET-{bind_name.upper()}",
                            layer=Layer.IAC_IAM,
                            severity=Severity.HIGH,
                            title=(
                                f"Invalid or Placeholder Scoped Secret Binding "
                                f"({bind_name})"
                            ),
                            description=(
                                f"{res_type}.{bind_name} binds secret_id='{sec_id}', "
                                "which is a prefix placeholder, dangling each.key, "
                                "or undeclared secret resource. GCP Secret Manager "
                                "IAM does not support prefix wildcards."
                            ),
                            remediation_hint=(
                                "Bind a concrete secret_id (e.g. "
                                "'workspace-doc-context') or a declared "
                                "google_secret_manager_secret resource."
                            ),
                            file_path=rel_tf,
                        )
                    )
    return issues


def build_iam_exposure_graph(tf_data: dict[str, Any]) -> nx.DiGraph:
    """Build a directed graph of GCP ingress, Cloud Run, NHIs, and IAM roles."""
    graph: nx.DiGraph = nx.DiGraph()
    declared_sas = _extract_sa_identifiers(tf_data)

    for block in tf_data.get("resource", []):
        if not isinstance(block, dict):
            continue
        if "google_cloud_run_v2_service" in block:
            for svc_name, svc_body in block["google_cloud_run_v2_service"].items():
                svc_node = f"cloud_run:{svc_name}"
                graph.add_node(svc_node, kind="compute")
                if (
                    isinstance(svc_body, dict)
                    and svc_body.get("ingress") == "INGRESS_TRAFFIC_ALL"
                ):
                    graph.add_edge(
                        "internet:public", svc_node, relation="https_ingress"
                    )
                graph.add_edge(svc_node, "sa:workload_nhi", relation="assumes_nhi")

        if "google_project_iam_member" in block:
            for _, bind_body in block["google_project_iam_member"].items():
                if not isinstance(bind_body, dict):
                    continue
                role = str(bind_body.get("role", ""))
                member = str(bind_body.get("member", ""))
                role_node = f"project_role:{role}"
                graph.add_node(role_node, kind="project_iam", role=role)
                if _member_matches_service_account(member, declared_sas):
                    graph.add_edge(
                        "sa:workload_nhi", role_node, relation="granted_role"
                    )

        if "google_project_iam_binding" in block:
            for _, bind_body in block["google_project_iam_binding"].items():
                if not isinstance(bind_body, dict):
                    continue
                role = str(bind_body.get("role", ""))
                members = bind_body.get("members", [])
                role_node = f"project_role:{role}"
                graph.add_node(role_node, kind="project_iam", role=role)
                if isinstance(members, list) and any(
                    _member_matches_service_account(str(m), declared_sas)
                    for m in members
                ):
                    graph.add_edge(
                        "sa:workload_nhi", role_node, relation="granted_role"
                    )

        if "google_project_iam_policy" in block:
            for _, pol_body in block["google_project_iam_policy"].items():
                if not isinstance(pol_body, dict):
                    continue
                pol_str = str(pol_body.get("policy_data", ""))
                for role in PRIVILEGED_ROLES:
                    if role in pol_str:
                        role_node = f"project_role:{role}"
                        graph.add_node(role_node, kind="project_iam", role=role)
                        graph.add_edge(
                            "sa:workload_nhi",
                            role_node,
                            relation="granted_role",
                        )

        if "google_secret_manager_secret_iam_member" in block:
            for _, bind_body in block[
                "google_secret_manager_secret_iam_member"
            ].items():
                if not isinstance(bind_body, dict):
                    continue
                role = str(bind_body.get("role", ""))
                secret_id = str(bind_body.get("secret_id", "scoped_secret"))
                scoped_node = f"scoped_secret:{secret_id}:{role}"
                graph.add_node(scoped_node, kind="scoped_iam", role=role)
                graph.add_edge(
                    "sa:workload_nhi",
                    scoped_node,
                    relation="scoped_access",
                )

    for data_block in tf_data.get("data", []):
        if isinstance(data_block, dict) and "google_iam_policy" in data_block:
            for _, pol_body in data_block["google_iam_policy"].items():
                pol_dump = json.dumps(pol_body)
                for role in PRIVILEGED_ROLES:
                    if role in pol_dump:
                        role_node = f"project_role:{role}"
                        graph.add_node(role_node, kind="project_iam", role=role)
                        graph.add_edge(
                            "sa:workload_nhi",
                            role_node,
                            relation="granted_role",
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
    compute_nodes = [n for n, d in graph.nodes(data=True) if d.get("kind") == "compute"]
    if not compute_nodes:
        return SubagentReport(
            subagent_name="Subagent 01: Graph Analyzer",
            countered_defense_step="01 Prepare (Exposure Mapping & Hardening)",
            findings=[
                Finding(
                    finding_id="PARALLAX-IAM-MISSING-SERVICE",
                    layer=Layer.IAC_IAM,
                    severity=Severity.CRITICAL,
                    title="Cloud Run Service Resource Removed (Fail-Closed)",
                    description=f"{rel_tf} removed google_cloud_run_v2_service.",
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
                        "Replace project-wide IAM bindings with resource-scoped "
                        "google_secret_manager_secret_iam_member."
                    ),
                    file_path=rel_tf,
                )
            )
            idx += 1

    scoped_issues = _validate_scoped_secret_bindings(tf_data, rel_tf)
    findings.extend(scoped_issues)

    project_role_count = idx - 1
    if project_role_count >= 2:
        risk_score = 0.95
    elif project_role_count == 1:
        risk_score = 0.70
    elif scoped_issues:
        # Project-level edge removed, but replacement secret binding is invalid
        risk_score = 0.65
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
