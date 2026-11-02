"""Shared AST inspection utilities for Code and Telemetry subagents."""

import ast
from typing import Any


class AgentToolASTVisitor(ast.NodeVisitor):
    """Inspect service.py AST for authorization dataflow and AuditEvent calls."""

    def __init__(self) -> None:
        self.has_audit_event_class: bool = False
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
            source_segment = ast.unparse(node)
            if "primary_id.startswith(ALLOWED_WORKSPACE_PREFIX)" in source_segment:
                self.validates_primary_prefix = True
            if (
                '"fallback_secret_id"' in source_segment
                or "'fallback_secret_id'" in source_segment
            ):
                self.reads_fallback_param = True

            # Detect assignment of fallback_id (or alias) to effective_secret_id
            if (
                "effective_secret_id = fallback_id" in source_segment
                or "effective_secret_id = fb_id" in source_segment
            ):
                self.overrides_effective_secret = True

            # Detect direct prefix check, allowlist check, or helper validator
            if (
                "fallback_id.startswith(ALLOWED_WORKSPACE_PREFIX)" in source_segment
                or "fb_id.startswith(ALLOWED_WORKSPACE_PREFIX)" in source_segment
                or "effective_secret_id.startswith(ALLOWED_WORKSPACE_PREFIX)"
                in source_segment
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
