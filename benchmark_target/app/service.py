"""Cloud Run Vertex AI Agent Tool Handler (Benchmark Target)."""

import re
from dataclasses import dataclass
from typing import Any

ALLOWED_WORKSPACE_PREFIX = "workspace-doc-"
SAFE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{3,64}$")


@dataclass(frozen=True)
class AuditEvent:
    """Structured Cloud Audit Log entry emitted for Google SecOps monitoring."""

    principal_email: str
    caller_identity: str
    tool_name: str
    target_secret_uri: str
    status: str
    reason: str


@dataclass(frozen=True)
class ToolResponse:
    """Result returned by the AI Agent tool execution."""

    allowed: bool
    resolved_secret_uri: str
    audit_event: AuditEvent


def verify_caller_auth(auth_header: str | None) -> str:
    """Enforce authentication upfront before any handler execution."""
    if not auth_header or not auth_header.startswith("Bearer "):
        raise PermissionError("Missing or invalid Bearer authentication token.")
    token = auth_header.removeprefix("Bearer ").strip()
    if len(token) < 12 or not SAFE_ID_PATTERN.match(token):
        raise PermissionError("Malformed caller token.")
    return f"user:{token}"


def execute_agent_tool(
    auth_header: str | None,
    tool_payload: dict[str, Any],
    project_id: str = "gcp-sg-parallax-sandbox",
) -> ToolResponse:
    """Execute the AI Agent workspace secret lookup tool.

    Contains an intentional Cross-Layer Confused Deputy flaw:
    While `primary_id` is checked against `ALLOWED_WORKSPACE_PREFIX`, an optional
    `fallback_secret_id` in the agent tool context bypasses the prefix check and
    leverages the over-permissive `roles/secretmanager.secretAccessor` IAM role.
    """
    caller = verify_caller_auth(auth_header)
    primary_id = str(tool_payload.get("resource_id", ""))
    fallback_id = str(tool_payload.get("fallback_secret_id", ""))

    if not SAFE_ID_PATTERN.match(primary_id):
        raise ValueError("Invalid resource_id format.")

    if not primary_id.startswith(ALLOWED_WORKSPACE_PREFIX):
        audit = AuditEvent(
            principal_email="sa-agent-runner@gcp-sg-parallax-sandbox.iam.gserviceaccount.com",
            caller_identity=caller,
            tool_name="read_workspace_context",
            target_secret_uri=f"projects/{project_id}/secrets/{primary_id}",
            status="DENIED_BY_APP_FILTER",
            reason="Resource does not match allowed workspace prefix.",
        )
        return ToolResponse(
            allowed=False,
            resolved_secret_uri=audit.target_secret_uri,
            audit_event=audit,
        )

    # CROSS-LAYER FLAW: Agent tool falls back to `fallback_id` when `use_fallback`
    # is set in tool metadata, without re-validating ALLOWED_WORKSPACE_PREFIX.
    effective_secret_id = primary_id
    if tool_payload.get("use_fallback") is True and fallback_id:
        if not SAFE_ID_PATTERN.match(fallback_id):
            raise ValueError("Invalid fallback_secret_id format.")
        effective_secret_id = fallback_id

    secret_uri = f"projects/{project_id}/secrets/{effective_secret_id}/versions/latest"
    audit = AuditEvent(
        principal_email="sa-agent-runner@gcp-sg-parallax-sandbox.iam.gserviceaccount.com",
        caller_identity=caller,
        tool_name="read_workspace_context",
        target_secret_uri=secret_uri,
        status="GRANTED",
        reason="Tool execution completed.",
    )
    return ToolResponse(
        allowed=True,
        resolved_secret_uri=secret_uri,
        audit_event=audit,
    )
