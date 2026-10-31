"""Benchmark Cloud Run AI Agent Service with upfront authn and cross-layer fallback flaw."""

import re
from typing import Any

from pydantic import BaseModel

SAFE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]+$")
ALLOWED_WORKSPACE_PREFIX = "workspace-doc-"
PROJECT_ID = "gcp-sg-parallax-sandbox"


class AuditEvent(BaseModel):
    """Structured Cloud Audit Log payload evaluated by Google SecOps."""

    event_type: str
    caller_identity: str
    service_account: str
    tool_name: str
    target_secret: str
    allowed: bool


class ToolExecutionResult(BaseModel):
    """Structured response returned by the Cloud Run AI Agent tool."""

    allowed: bool
    caller: str
    resolved_secret_uri: str
    audit_event: AuditEvent


def verify_caller_auth(auth_header: str | None) -> str:
    """Enforce upfront authentication guardrail before parsing tool payload."""
    if not auth_header or not auth_header.startswith("Bearer "):
        raise PermissionError("Missing or invalid Bearer authentication token.")
    token = auth_header.removeprefix("Bearer ").strip()
    if not token or len(token) < 10:
        raise PermissionError("Malformed session token.")
    return f"user:{token}"


def execute_agent_tool(
    auth_header: str | None,
    tool_payload: dict[str, Any],
) -> ToolExecutionResult:
    """Execute agent tool logic with a subtle cross-layer Confused Deputy bypass."""
    caller = verify_caller_auth(auth_header)

    primary_id = str(tool_payload.get("resource_id", ""))
    use_fallback = bool(tool_payload.get("use_fallback", False))
    fallback_id = str(tool_payload.get("fallback_secret_id", ""))

    if not SAFE_ID_PATTERN.match(primary_id):
        raise ValueError("Invalid resource_id format.")

    if not primary_id.startswith(ALLOWED_WORKSPACE_PREFIX):
        raise PermissionError("Access denied: resource_id outside workspace scope.")

    effective_secret_id = primary_id

    # [ARCHITECTURAL FLAW / CONFUSED DEPUTY]
    # Primary ID validates ALLOWED_WORKSPACE_PREFIX, but fallback_id overwrites
    # effective_secret_id without verifying ALLOWED_WORKSPACE_PREFIX!
    if use_fallback and fallback_id:
        if not SAFE_ID_PATTERN.match(fallback_id):
            raise ValueError("Invalid fallback_secret_id format.")
        effective_secret_id = fallback_id

    resolved_uri = (
        f"projects/{PROJECT_ID}/secrets/{effective_secret_id}/versions/latest"
    )

    audit = AuditEvent(
        event_type="SECRET_MANAGER_ACCESS",
        caller_identity=caller,
        service_account=f"sa-agent-runner@{PROJECT_ID}.iam.gserviceaccount.com",
        tool_name="read_workspace_context",
        target_secret=effective_secret_id,
        allowed=True,
    )

    return ToolExecutionResult(
        allowed=True,
        caller=caller,
        resolved_secret_uri=resolved_uri,
        audit_event=audit,
    )
