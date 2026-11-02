"""Subagent 01: GCP Terraform IAM Graph Analyzer (Countering 01 Prepare)."""

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
        if "google_cloud_run_v2_service" in block:
            for svc_name, svc_body in block["google_cloud_run_v2_service"].items():
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
    """Execute Subagent 01 to detect public-to-project IAM blast radius."""
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

    with tf_path.open("r", encoding="utf-8") as tf_file:
        tf_data: dict[str, Any] = hcl2.load(tf_file)

    graph = build_iam_exposure_graph(tf_data)
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

    # Measurable risk derivation from reachable privileged project roles
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
