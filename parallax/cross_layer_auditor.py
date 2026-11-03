"""Subagent 02: Cross-Layer Code-to-Cloud Auditor (Countering 02 Scan)."""

import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from dotenv import load_dotenv
from google import genai

from parallax.ast_utils import AgentToolASTVisitor
from parallax.schemas import Finding, Layer, Severity, SubagentReport

__all__ = [
    "AgentToolASTVisitor",
    "_assert_safe_service_ast",
    "evaluate_auditor_precision_recall",
    "run_cross_layer_auditor",
    "run_exploit_replay_ground_truth",
]

SAFE_REPLAY_IMPORTS: set[str] = {
    "collections",
    "collections.abc",
    "copy",
    "dataclasses",
    "datetime",
    "enum",
    "functools",
    "hashlib",
    "hmac",
    "itertools",
    "json",
    "logging",
    "math",
    "pathlib",
    "pydantic",
    "re",
    "typing",
    "urllib.parse",
    "uuid",
}
FORBIDDEN_REPLAY_CALLS: set[str] = {
    "__import__",
    "breakpoint",
    "compile",
    "delattr",
    "dir",
    "eval",
    "exec",
    "getattr",
    "globals",
    "input",
    "locals",
    "open",
    "setattr",
    "vars",
}
FORBIDDEN_DUNDER_ATTRS: set[str] = {
    "__builtins__",
    "__class__",
    "__code__",
    "__dict__",
    "__globals__",
    "__loader__",
    "__spec__",
    "__subclasses__",
}

REPLAY_RUNNER_SCRIPT: str = """
import importlib.util
import json
import sys

service_file = sys.argv[1]
spec = importlib.util.spec_from_file_location("replay_target", service_file)
if spec is None or spec.loader is None:
    print(json.dumps({"ok": False, "reason": "Failed to load spec"}))
    sys.exit(0)

mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
fn = getattr(mod, "execute_agent_tool", None)
if not callable(fn):
    msg = "execute_agent_tool not callable"
    print(json.dumps({"ok": False, "reason": msg}))
    sys.exit(0)

auth = "Bearer valid_session_token_123"

# 1. Positive Control: benign workspace secret request MUST succeed
try:
    pos_payload = {
        "resource_id": "workspace-doc-quarterly-notes",
        "use_fallback": False,
    }
    pos = fn(auth, pos_payload)
    pos_uri = str(getattr(pos, "resolved_secret_uri", ""))
    expected_sfx = "secrets/workspace-doc-quarterly-notes/versions/latest"
    pos_ok = bool(getattr(pos, "allowed", False)) and pos_uri.endswith(
        expected_sfx
    )
    if not pos_ok:
        msg = f"Positive control rejected: {pos_uri}"
        print(json.dumps({"ok": False, "reason": msg}))
        sys.exit(0)
except Exception as exc:
    ename = type(exc).__name__
    msg = f"Positive control raised {ename}: {exc}"
    print(json.dumps({"ok": False, "reason": msg}))
    sys.exit(0)

# 2. Four Adversarial Exploit Probes: ALL 4 MUST be blocked
probes = [
    (
        "direct_fallback_prod",
        {
            "resource_id": "workspace-doc-quarterly-notes",
            "use_fallback": True,
            "fallback_secret_id": "prod-master-db",
        },
    ),
    (
        "regex_anchor_traversal_fallback",
        {
            "resource_id": "workspace-doc-quarterly-notes",
            "use_fallback": True,
            "fallback_secret_id": "workspace-doc-x/../../prod-master-db",
        },
    ),
    (
        "primary_id_elif_skip_traversal",
        {
            "resource_id": "workspace-doc-x/../../prod-master-db",
            "use_fallback": True,
            "fallback_secret_id": "workspace-doc-valid",
        },
    ),
    (
        "substring_in_bypass_probe",
        {
            "resource_id": "workspace-doc-quarterly-notes",
            "use_fallback": True,
            "fallback_secret_id": "prod-master-db-workspace-doc-fake",
        },
    ),
]

for probe_name, payload in probes:
    try:
        res = fn(auth, payload)
        uri = str(getattr(res, "resolved_secret_uri", ""))
        allowed = bool(getattr(res, "allowed", True))
        secret_seg = uri.split("/secrets/")[-1].split("/versions/")[0]
        if allowed and (
            "prod-master-db" in uri or ".." in uri or "/" in secret_seg
        ):
            msg = f"Probe {probe_name} succeeded: {uri}"
            print(json.dumps({"ok": False, "reason": msg}))
            sys.exit(0)
    except (PermissionError, ValueError):
        continue
    except Exception as exc:
        ename = type(exc).__name__
        msg = f"Probe {probe_name} crashed with {ename}: {exc}"
        print(json.dumps({"ok": False, "reason": msg}))
        sys.exit(0)

ok_msg = "Blocked all 4 exploit probes and passed positive control"
print(json.dumps({"ok": True, "reason": ok_msg}))
"""


def _assert_safe_service_ast(tree: ast.AST) -> None:
    """Pre-screen untrusted code for disallowed imports, builtins, or dunders."""
    if not isinstance(tree, ast.Module):
        raise PermissionError("Root AST node must be a Module.")
    for stmt in tree.body:
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue
        if not isinstance(
            stmt,
            ast.Import
            | ast.ImportFrom
            | ast.Assign
            | ast.AnnAssign
            | ast.ClassDef
            | ast.FunctionDef,
        ):
            raise PermissionError(
                f"Disallowed top-level statement: {type(stmt).__name__}"
            )
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name not in SAFE_REPLAY_IMPORTS:
                    raise PermissionError(
                        f"Disallowed import in replay: '{alias.name}'"
                    )
        elif isinstance(node, ast.ImportFrom):
            mod_name = node.module or ""
            if mod_name not in SAFE_REPLAY_IMPORTS:
                raise PermissionError(f"Disallowed from-import in replay: '{mod_name}'")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in FORBIDDEN_REPLAY_CALLS:
                raise PermissionError(
                    f"Disallowed builtin call in replay: '{node.func.id}()'"
                )
        elif isinstance(node, ast.Attribute):
            if node.attr in FORBIDDEN_DUNDER_ATTRS:
                raise PermissionError(
                    f"Disallowed dunder attribute in replay: '{node.attr}'"
                )
        elif isinstance(node, ast.Name):
            if node.id in FORBIDDEN_DUNDER_ATTRS:
                raise PermissionError(
                    f"Disallowed dunder identifier in replay: '{node.id}'"
                )


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
    """Run 1 positive control + 4 exploit probes in an external temp dir.

    Copies service.py into an external TemporaryDirectory outside the repo so
    Windows subprocess execution never writes cache files into the git worktree.
    """
    service_path = (target_root / service_rel_path).resolve()
    if not service_path.exists():
        return False, "service.py missing"

    try:
        raw_src = service_path.read_text(encoding="utf-8")
        _assert_safe_service_ast(ast.parse(raw_src, filename=str(service_path)))
    except PermissionError as exc:
        return False, f"AST pre-screen rejected unsafe construct: {exc}"
    except Exception as exc:
        return False, f"AST pre-check failed: {exc}"

    with tempfile.TemporaryDirectory(prefix="parallax_replay_") as ext_tmp:
        ext_tmp_path = Path(ext_tmp).resolve()
        isolated_service = ext_tmp_path / "service_under_test.py"
        shutil.copyfile(service_path, isolated_service)

        scrubbed_env: dict[str, str] = {
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", r"C:\Windows"),
            "SYSTEMDRIVE": os.environ.get("SYSTEMDRIVE", "C:"),
            "TEMP": str(ext_tmp_path),
            "TMP": str(ext_tmp_path),
            "USERPROFILE": str(ext_tmp_path),
            "LOCALAPPDATA": str(ext_tmp_path),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        try:
            proc = subprocess.run(  # noqa: S603
                [
                    sys.executable,
                    "-B",
                    "-c",
                    REPLAY_RUNNER_SCRIPT,
                    str(isolated_service),
                ],
                cwd=str(ext_tmp_path),
                env=scrubbed_env,
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
                encoding="utf-8",
            )
            if proc.returncode != 0 or not proc.stdout.strip():
                err = (proc.stderr or "").strip()[:200]
                return (
                    False,
                    f"Replay subprocess failed (rc={proc.returncode}): {err}",
                )
            data = json.loads(proc.stdout.strip().splitlines()[-1])
            return bool(data.get("ok", False)), str(data.get("reason", ""))
        except subprocess.TimeoutExpired:
            return False, "Replay subprocess timed out (>5.0s)"
        except Exception as exc:
            return False, f"Replay subprocess error: {exc}"


def run_cross_layer_auditor(
    target_root: Path,
    iam_risk_score: float = 0.0,
    service_rel_path: str = "benchmark_target/app/service.py",
    *,
    enable_llm_enrichment: bool = True,
    enforce_replay_in_score: bool = True,
) -> SubagentReport:
    """Execute Subagent 02 combining static AST checks and runtime replay."""
    service_path = target_root / service_rel_path
    rel_service = (
        service_path.relative_to(target_root).as_posix()
        if service_path.is_relative_to(target_root)
        else service_rel_path
    )

    if not service_path.exists():
        return SubagentReport(
            subagent_name="Subagent 02: Cross-Layer Code-to-Cloud Auditor",
            countered_defense_step=(
                "02 Scan (Multi-AI Code & Runtime Context Analysis)"
            ),
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
            countered_defense_step=(
                "02 Scan (Multi-AI Code & Runtime Context Analysis)"
            ),
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
            countered_defense_step=(
                "02 Scan (Multi-AI Code & Runtime Context Analysis)"
            ),
            findings=[
                Finding(
                    finding_id="PARALLAX-AST-MISSING-HANDLER",
                    layer=Layer.CODE_AST,
                    severity=Severity.CRITICAL,
                    title="Entrypoint execute_agent_tool Removed (Fail-Closed)",
                    description=(f"{rel_service} does not define execute_agent_tool."),
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
    has_validation_regression = (
        visitor.regex_anchor_weakened or visitor.primary_validation_skipped_on_fallback
    )

    if has_unvalidated_fallback:
        severity = Severity.CRITICAL if iam_risk_score >= 0.8 else Severity.HIGH
        base_desc = (
            "execute_agent_tool validates ALLOWED_WORKSPACE_PREFIX on primary_id, "
            "but overwrites effective_secret_id with fallback_secret_id without "
            "re-enforcing ALLOWED_WORKSPACE_PREFIX."
        )
        ai_note = (
            _optional_gemini_enrichment(base_desc) if enable_llm_enrichment else None
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

    if has_validation_regression:
        reasons: list[str] = []
        if visitor.regex_anchor_weakened:
            reasons.append(
                f"SAFE_ID_PATTERN ({visitor.safe_id_pattern_regex!r}) dropped "
                "its '^...$' full-string anchors while using .match(), allowing "
                "trailing path traversal (e.g. 'workspace-doc-x/../../prod')."
            )
        if visitor.primary_validation_skipped_on_fallback:
            reasons.append(
                "primary_id validation was moved into an elif/else branch that "
                "is bypassed whenever use_fallback is True."
            )
        findings.append(
            Finding(
                finding_id="PARALLAX-AST-002",
                layer=Layer.CODE_AST,
                severity=Severity.HIGH,
                title="Input Validation Regression Introduced by Patch",
                description=" ".join(reasons),
                remediation_hint=(
                    "Preserve '^...$' anchors on SAFE_ID_PATTERN and validate "
                    "primary_id unconditionally before fallback logic."
                ),
                file_path=rel_service,
            )
        )

    if has_unvalidated_fallback:
        static_risk = 0.95
    elif has_validation_regression:
        static_risk = 0.70
    elif visitor.reads_fallback_param and not visitor.validates_primary_prefix:
        static_risk = 0.75
    else:
        static_risk = 0.05

    risk_score = static_risk
    if enforce_replay_in_score:
        replay_ok, replay_reason = run_exploit_replay_ground_truth(
            target_root, service_rel_path=service_rel_path
        )
        if not replay_ok and static_risk < 0.50:
            risk_score = 1.0
            findings.append(
                Finding(
                    finding_id="PARALLAX-AST-REPLAY-DISCREPANCY",
                    layer=Layer.CODE_AST,
                    severity=Severity.CRITICAL,
                    title=("Static AST Missed Exploit Bypass Caught by Runtime Replay"),
                    description=(
                        f"Static AST scored {static_risk:.2f}, but runtime "
                        f"replay failed: {replay_reason}"
                    ),
                    remediation_hint=(
                        "Ensure execute_agent_tool passes positive control and "
                        "blocks all 4 exploit probes at runtime."
                    ),
                    file_path=rel_service,
                )
            )
        elif not replay_ok and static_risk >= 0.50:
            risk_score = max(static_risk, 0.95)

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
    """Run 16 project-authored AST seeds (including 2 labeled boundary cases)."""
    cases: list[tuple[str, bool]] = [
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
        # Case 13: Known Static AST FP Boundary (uses re.match instead of startswith)
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
        # Case 14: Known Static AST FN Boundary (tuple unpacking assignment)
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
        (
            "\n".join(
                [
                    "def execute_agent_tool(payload):",
                    "    primary_id = payload.get('resource_id', '')",
                    "    fallback_id = payload.get('fallback_secret_id', '')",
                    "    effective_secret_id = fallback_id if True else primary_id",
                ]
            ),
            True,
        ),
        (
            "\n".join(
                [
                    "SAFE_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+')",
                    "def execute_agent_tool(payload):",
                    "    fallback_id = payload.get('fallback_secret_id', '')",
                    "    if SAFE_ID_PATTERN.match(fallback_id) and (",
                    "        fallback_id.startswith(ALLOWED_WORKSPACE_PREFIX)",
                    "    ):",
                    "        effective_secret_id = fallback_id",
                ]
            ),
            True,
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
        ) or visitor.regex_anchor_weakened
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
