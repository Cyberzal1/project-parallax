"""Strict Pydantic schemas enforcing the GEMINI.md Subagent Contract."""

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
