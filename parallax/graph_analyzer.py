"""Subagent 01: GCP IAM & Exposure Graph Analyzer (Countering 01 Prepare)."""

from pathlib import Path
from typing import Any

import hcl2
import networkx as nx

from parallax.schemas import Finding, Layer, Severity, SubagentReport

HIGH_RISK_ROLES: dict[str, tuple[Severity, str]] = {
    "roles/secretmanager.secretAccessor": (
        Severity.CRITICAL,
        "Project-wide Secret Manager access allows reading prod-* secrets.",
    ),
    "roles/iam.serviceAccountTokenCreator": (
        Severity.HIGH,
        "Project-wide Token Creator allows Non-Human Identity impersonation.",
    ),
}


def build_gcp_exposure_graph(tf_path: Path) -> nx.DiGraph:
    """Parse Terraform HCL2 into a directed reachability graph."""
    with tf_path.open("r", encoding="utf-8") as tf_file:
        tf_data: dict[str, Any] = hcl2.load(tf_file)

    graph = nx.DiGraph()
    resources: list[dict[str, Any]] = tf_data.get("resource", [])

    for block in resources:
        if "google_service_account" in block:
            for sa_key, sa_body in block["google_service_account"].items():
                sa_node = f"sa:{sa_key}"
                graph.add_node(
                    sa_node,
                    node_type="service_account",
                    account_id=str(sa_body.get("account_id", sa_key)),
                )

        if "google_cloud_run_v2_service" in block:
            for svc_key, svc_body in block["google_cloud_run_v2_service"].items():
                svc_node = f"cloud_run:{svc_key}"
                ingress = str(svc_body.get("ingress", "INGRESS_TRAFFIC_ALL"))
                graph.add_node(svc_node, node_type="cloud_run", ingress=ingress)
                if ingress == "INGRESS_TRAFFIC_ALL":
                    graph.add_node("internet:public", node_type="external")
                    graph.add_edge("internet:public", svc_node, relation="public_https")

                templates = svc_body.get("template", [])
                if isinstance(templates, list) and templates:
                    sa_ref = str(templates[0].get("service_account", ""))
                    if "sa_agent_runner" in sa_ref:
                        graph.add_edge(
                            svc_node, "sa:sa_agent_runner", relation="assumes_nhi"
                        )

        if "google_project_iam_member" in block:
            for bind_key, bind_body in block["google_project_iam_member"].items():
                role = str(bind_body.get("role", ""))
                member = str(bind_body.get("member", ""))
                role_node = f"project_role:{role}"
                graph.add_node(
                    role_node,
                    node_type="iam_role",
                    binding_name=bind_key,
                    scope="project_wide",
                )
                if "sa_agent_runner" in member:
                    graph.add_edge(
                        "sa:sa_agent_runner", role_node, relation="granted_role"
                    )

        if "google_secret_manager_secret_iam_member" in block:
            sec_iam = block["google_secret_manager_secret_iam_member"]
            for bind_key, bind_body in sec_iam.items():
                role = str(bind_body.get("role", ""))
                secret_id = str(bind_body.get("secret_id", "scoped_secret"))
                role_node = f"scoped_role:{role}:{secret_id}"
                graph.add_node(
                    role_node,
                    node_type="iam_role",
                    binding_name=bind_key,
                    scope="resource_scoped",
                )

    return graph


def run_graph_analyzer(target_root: Path) -> SubagentReport:
    """Execute Subagent 01 and return a structured SubagentReport."""
    tf_path = target_root / "benchmark_target" / "infra" / "main.tf"
    rel_tf = str(tf_path.relative_to(target_root).as_posix())
    graph = build_gcp_exposure_graph(tf_path)

    findings: list[Finding] = []
    risk_score = 0.1

    for role_str, (severity, desc) in HIGH_RISK_ROLES.items():
        target_node = f"project_role:{role_str}"
        if graph.has_node(target_node) and graph.has_node("internet:public"):
            if nx.has_path(graph, "internet:public", target_node):
                path_nodes = nx.shortest_path(graph, "internet:public", target_node)
                chain_str = " -> ".join(path_nodes)
                findings.append(
                    Finding(
                        finding_id=f"PARALLAX-IAM-{len(findings) + 1:03d}",
                        layer=Layer.IAC_IAM,
                        severity=severity,
                        title=f"Public-to-Project IAM Escalation Path ({role_str})",
                        description=(
                            f"{desc} Reachable via trusted graph path: {chain_str}"
                        ),
                        remediation_hint=(
                            "Replace google_project_iam_member with resource-scoped "
                            "google_secret_manager_secret_iam_member."
                        ),
                    )
                )
                crit_score = 0.95 if severity == Severity.CRITICAL else 0.75
                risk_score = max(risk_score, crit_score)

    return SubagentReport(
        subagent_name="Subagent 01: Graph Analyzer",
        countered_defense_step="01 Prepare (Exposure Mapping & Hardening)",
        findings=findings,
        files_touched=[rel_tf],
        open_questions=[
            "Can app tool parameters steer this NHI into reading prod-* secrets?"
        ]
        if findings
        else [],
        risk_score=risk_score,
    )
