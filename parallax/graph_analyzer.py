"""Subagent 01: GCP Terraform IAM Graph Analyzer (Countering 01 Prepare)."""

import json
import re
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

KNOWN_GCP_TERRAFORM_RESOURCES: set[str] = {
    "google_service_account",
    "google_cloud_run_v2_service",
    "google_project_iam_member",
    "google_project_iam_binding",
    "google_project_iam_policy",
    "google_secret_manager_secret",
    "google_secret_manager_secret_version",
    "google_secret_manager_secret_iam_member",
    "google_secret_manager_secret_iam_binding",
    "google_secret_manager_secret_iam_policy",
    "google_service_account_iam_member",
    "google_service_account_iam_binding",
    "google_service_account_iam_policy",
}

PLACEHOLDER_SUBSTRINGS: tuple[str, ...] = (
    "placeholder",
    "example",
    "todo",
    "replace",
    "changeme",
    "dummy",
    "your-",
    "your_",
)


def _extract_declared_sas(tf_data: dict[str, Any]) -> dict[str, str]:
    """Map SA resource names and account_ids to canonical sa:<res_name> nodes."""
    sa_map: dict[str, str] = {}
    for block in tf_data.get("resource", []):
        if isinstance(block, dict) and "google_service_account" in block:
            for res_name, body in block["google_service_account"].items():
                canonical = f"sa:{res_name}"
                sa_map[res_name] = canonical
                if isinstance(body, dict) and body.get("account_id"):
                    sa_map[str(body["account_id"])] = canonical
    return sa_map


def _resolve_sa_node(ref_str: str, sa_map: dict[str, str]) -> str | None:
    """Resolve a Terraform SA reference string to its canonical sa:<name> node."""
    for token, canonical in sa_map.items():
        if token in ref_str:
            return canonical
    m = re.search(r"google_service_account\.([A-Za-z0-9_-]+)", ref_str)
    if m:
        return f"sa:{m.group(1)}"
    m_email = re.search(r"serviceAccount:([A-Za-z0-9_-]+)@", ref_str)
    if m_email:
        acct = m_email.group(1)
        return sa_map.get(acct, f"sa:{acct}")
    return None


def _audit_terraform_resources_and_secrets(
    tf_data: dict[str, Any],
    raw_hcl: str,
    rel_tf: str,
    sa_map: dict[str, str],
) -> tuple[list[Finding], bool, bool]:
    """Validate resource types, declared secrets, placeholders, and SA self-grants.

    Returns (findings, has_unknown_resource, has_invalid_scoped_or_self_grant).
    """
    findings: list[Finding] = []
    has_unknown_res = False
    has_scoped_issue = False

    declared_secret_res: set[str] = set()
    declared_secret_ids: set[str] = set()
    for block in tf_data.get("resource", []):
        if isinstance(block, dict) and "google_secret_manager_secret" in block:
            for sec_name, sec_body in block["google_secret_manager_secret"].items():
                declared_secret_res.add(sec_name)
                if isinstance(sec_body, dict) and sec_body.get("secret_id"):
                    declared_secret_ids.add(str(sec_body["secret_id"]).strip())

    # Check raw HCL lines around secret_id for placeholder comments
    raw_secret_comment_flagged = False
    for line in raw_hcl.splitlines():
        low = line.lower()
        if "secret_id" in low and "#" in low:
            comment_part = low.split("#", 1)[1]
            if any(p in comment_part for p in PLACEHOLDER_SUBSTRINGS):
                raw_secret_comment_flagged = True

    for block in tf_data.get("resource", []):
        if not isinstance(block, dict):
            continue
        for res_type, instances in block.items():
            if res_type not in KNOWN_GCP_TERRAFORM_RESOURCES:
                has_unknown_res = True
                findings.append(
                    Finding(
                        finding_id=(
                            f"PARALLAX-IAM-UNKNOWN-RESOURCE-{res_type.upper()}"
                        ),
                        layer=Layer.IAC_IAM,
                        severity=Severity.CRITICAL,
                        title=(
                            f"Unrecognized Terraform Resource Type '{res_type}' "
                            "(Fail-Closed)"
                        ),
                        description=(
                            f"{rel_tf} declares resource type '{res_type}', "
                            "which is not a valid Google Cloud provider IAM or "
                            "Secret Manager resource."
                        ),
                        remediation_hint=(
                            "Use google_secret_manager_secret_iam_member and "
                            "validate with terraform validate."
                        ),
                        file_path=rel_tf,
                    )
                )
                if raw_secret_comment_flagged or any(
                    p in json.dumps(instances).lower() for p in PLACEHOLDER_SUBSTRINGS
                ):
                    has_scoped_issue = True
                    findings.append(
                        Finding(
                            finding_id=(
                                f"PARALLAX-IAM-INVALID-SCOPED-SECRET-{res_type.upper()}"
                            ),
                            layer=Layer.IAC_IAM,
                            severity=Severity.HIGH,
                            title="Placeholder Secret in Unrecognized Resource",
                            description=(
                                f"{res_type} also contains a placeholder "
                                "secret_id or comment."
                            ),
                            remediation_hint="Use a declared secret resource.",
                            file_path=rel_tf,
                        )
                    )
                continue

            if not isinstance(instances, dict):
                continue

            # Check SA self-impersonation / token creator on service account
            if res_type in (
                "google_service_account_iam_member",
                "google_service_account_iam_binding",
                "google_service_account_iam_policy",
            ):
                for bind_name, bind_body in instances.items():
                    body_dump = json.dumps(bind_body)
                    if "serviceAccountTokenCreator" in body_dump:
                        has_scoped_issue = True
                        findings.append(
                            Finding(
                                finding_id=(
                                    f"PARALLAX-IAM-SA-TOKEN-CREATOR-{bind_name.upper()}"
                                ),
                                layer=Layer.IAC_IAM,
                                severity=Severity.HIGH,
                                title=(
                                    "Service Account Granted Token Creator "
                                    f"({bind_name})"
                                ),
                                description=(
                                    f"{res_type}.{bind_name} retains "
                                    "roles/iam.serviceAccountTokenCreator."
                                ),
                                remediation_hint=(
                                    "Remove serviceAccountTokenCreator binding."
                                ),
                                file_path=rel_tf,
                            )
                        )

            # Check scoped secret bindings
            if res_type in (
                "google_secret_manager_secret_iam_member",
                "google_secret_manager_secret_iam_binding",
                "google_secret_manager_secret_iam_policy",
            ):
                for bind_name, bind_body in instances.items():
                    if not isinstance(bind_body, dict):
                        continue
                    sec_id = str(bind_body.get("secret_id", "")).strip()
                    low_sec = sec_id.lower()
                    has_for_each = "for_each" in bind_body

                    has_placeholder_word = any(
                        p in low_sec for p in PLACEHOLDER_SUBSTRINGS
                    )
                    is_prefix_wildcard = (
                        sec_id.endswith("-")
                        or "*" in sec_id
                        or sec_id in ("", "workspace-doc")
                    )
                    is_dangling_each = "each." in sec_id and not has_for_each

                    # Must reference a declared google_secret_manager_secret
                    refs_declared_res = any(
                        f"google_secret_manager_secret.{r}" in sec_id
                        for r in declared_secret_res
                    )
                    matches_declared_id = (
                        sec_id in declared_secret_ids and len(declared_secret_res) > 0
                    )
                    is_undeclared_secret = not (
                        refs_declared_res or matches_declared_id
                    )

                    if (
                        has_placeholder_word
                        or raw_secret_comment_flagged
                        or is_prefix_wildcard
                        or is_dangling_each
                        or is_undeclared_secret
                    ):
                        has_scoped_issue = True
                        findings.append(
                            Finding(
                                finding_id=(
                                    "PARALLAX-IAM-INVALID-SCOPED-SECRET-"
                                    f"{bind_name.upper()}"
                                ),
                                layer=Layer.IAC_IAM,
                                severity=Severity.HIGH,
                                title=(
                                    "Invalid, Placeholder, or Undeclared Scoped "
                                    f"Secret ({bind_name})"
                                ),
                                description=(
                                    f"{res_type}.{bind_name} binds "
                                    f"secret_id='{sec_id}', which is undeclared "
                                    "in main.tf or uses a placeholder/prefix."
                                ),
                                remediation_hint=(
                                    "Declare a google_secret_manager_secret "
                                    "resource and reference its secret_id."
                                ),
                                file_path=rel_tf,
                            )
                        )

    return findings, has_unknown_res, has_scoped_issue


def build_iam_exposure_graph(tf_data: dict[str, Any]) -> nx.DiGraph:
    """Build a directed graph linking each Cloud Run service to its specific SA."""
    graph: nx.DiGraph = nx.DiGraph()
    sa_map = _extract_declared_sas(tf_data)

    for block in tf_data.get("resource", []):
        if not isinstance(block, dict):
            continue
        if "google_cloud_run_v2_service" in block:
            for svc_name, svc_body in block["google_cloud_run_v2_service"].items():
                svc_node = f"cloud_run:{svc_name}"
                graph.add_node(svc_node, kind="compute")
                if not isinstance(svc_body, dict):
                    continue
                if svc_body.get("ingress") == "INGRESS_TRAFFIC_ALL":
                    graph.add_edge(
                        "internet:public", svc_node, relation="https_ingress"
                    )
                templates = svc_body.get("template", [])
                sa_ref = ""
                if isinstance(templates, list) and templates:
                    sa_ref = str(templates[0].get("service_account", ""))
                elif isinstance(templates, dict):
                    sa_ref = str(templates.get("service_account", ""))
                unique_sas = set(sa_map.values())
                default_sa = (
                    next(iter(unique_sas))
                    if len(unique_sas) == 1
                    else "sa:default_compute"
                )
                sa_node = _resolve_sa_node(sa_ref, sa_map) if sa_ref else default_sa
                if sa_node:
                    graph.add_node(sa_node, kind="service_account")
                    graph.add_edge(svc_node, sa_node, relation="assumes_nhi")

        if "google_project_iam_member" in block:
            for _, bind_body in block["google_project_iam_member"].items():
                if not isinstance(bind_body, dict):
                    continue
                role = str(bind_body.get("role", ""))
                member = str(bind_body.get("member", ""))
                role_node = f"project_role:{role}"
                graph.add_node(role_node, kind="project_iam", role=role)
                sa_node = _resolve_sa_node(member, sa_map)
                if sa_node:
                    graph.add_edge(sa_node, role_node, relation="granted_role")

        if "google_project_iam_binding" in block:
            for _, bind_body in block["google_project_iam_binding"].items():
                if not isinstance(bind_body, dict):
                    continue
                role = str(bind_body.get("role", ""))
                members = bind_body.get("members", [])
                role_node = f"project_role:{role}"
                graph.add_node(role_node, kind="project_iam", role=role)
                if isinstance(members, list):
                    for m_str in members:
                        sa_node = _resolve_sa_node(str(m_str), sa_map)
                        if sa_node:
                            graph.add_edge(sa_node, role_node, relation="granted_role")

        if "google_project_iam_policy" in block:
            for _, pol_body in block["google_project_iam_policy"].items():
                if not isinstance(pol_body, dict):
                    continue
                pol_str = str(pol_body.get("policy_data", ""))
                for role in PRIVILEGED_ROLES:
                    if role in pol_str:
                        role_node = f"project_role:{role}"
                        graph.add_node(role_node, kind="project_iam", role=role)
                        for sa_node in set(sa_map.values()):
                            graph.add_edge(sa_node, role_node, relation="granted_role")

    for data_block in tf_data.get("data", []):
        if isinstance(data_block, dict) and "google_iam_policy" in data_block:
            for _, pol_body in data_block["google_iam_policy"].items():
                pol_dump = json.dumps(pol_body)
                for role in PRIVILEGED_ROLES:
                    if role in pol_dump:
                        role_node = f"project_role:{role}"
                        graph.add_node(role_node, kind="project_iam", role=role)
                        for sa_node in set(sa_map.values()):
                            if sa_node.split(":", 1)[1] in pol_dump:
                                graph.add_edge(
                                    sa_node, role_node, relation="granted_role"
                                )

    return graph


def run_graph_analyzer(
    target_root: Path,
    tf_rel_path: str = "benchmark_target/infra/main.tf",
) -> SubagentReport:
    """Execute Subagent 01 and fail closed on unknown or invalid Terraform."""
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

    sa_map = _extract_declared_sas(tf_data)
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

    extra_findings, has_unknown_res, has_scoped_issue = (
        _audit_terraform_resources_and_secrets(tf_data, raw_hcl, rel_tf, sa_map)
    )
    findings.extend(extra_findings)

    project_role_count = idx - 1
    if project_role_count >= 2:
        risk_score = 0.95
    elif has_unknown_res:
        risk_score = 0.90
    elif project_role_count == 1:
        risk_score = 0.75
    elif has_scoped_issue:
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
