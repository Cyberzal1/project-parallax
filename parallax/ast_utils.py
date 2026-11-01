"""Shared AST inspection utilities for Code and Telemetry subagents."""

import ast


class AgentToolASTVisitor(ast.NodeVisitor):
    """Inspect service.py AST for authorization dataflow and AuditEvent fields."""

    def __init__(self) -> None:
        self.validates_primary_prefix: bool = False
        self.reads_fallback_param: bool = False
        self.overrides_effective_secret: bool = False
        self.revalidates_fallback_prefix: bool = False
        self.audited_tool_names: list[str] = []
        self.emitted_event_types: set[str] = set()
        self.unresolved_dynamic_tool_sites: list[str] = []
        self.audit_event_fields: set[str] = set()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Extract declared schema fields on AuditEvent."""
        if node.name == "AuditEvent":
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
            if "effective_secret_id = fallback_id" in source_segment:
                self.overrides_effective_secret = True
            if "fallback_id.startswith(ALLOWED_WORKSPACE_PREFIX)" in source_segment:
                self.revalidates_fallback_prefix = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Capture static and dynamic tool_name and event_type values."""
        if isinstance(node.func, ast.Name) and node.func.id == "AuditEvent":
            for kw in node.keywords:
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
                elif (
                    kw.arg == "event_type"
                    and isinstance(kw.value, ast.Constant)
                    and isinstance(kw.value.value, str)
                ):
                    self.emitted_event_types.add(kw.value.value)
        self.generic_visit(node)
