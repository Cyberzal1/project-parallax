"""Strict Pydantic schemas enforcing the GEMINI.md Subagent Contract."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Standardized finding severity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Layer(StrEnum):
    """Architectural layer where a flaw or divergence resides."""

    IAC_IAM = "IAC_IAM"
    CODE_AST = "CODE_AST"
    PATCH_WORKTREE = "PATCH_WORKTREE"
    SECOPS_TELEMETRY = "SECOPS_TELEMETRY"


class Finding(BaseModel):
    """Individual architectural or adversarial finding."""

    model_config = ConfigDict(frozen=True)

    finding_id: str
    layer: Layer
    severity: Severity
    title: str
    description: str
    remediation_hint: str


class SubagentReport(BaseModel):
    """Structured summary returned by every subagent (never a raw dump)."""

    model_config = ConfigDict(frozen=True)

    subagent_name: str
    countered_defense_step: str
    findings: list[Finding] = Field(default_factory=list)
    files_touched: list[str] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    risk_score: float = Field(ge=0.0, le=1.0)


class SplitBrainDelta(BaseModel):
    """Mathematical evaluation of cross-layer remediation completeness."""

    model_config = ConfigDict(frozen=True)

    patch_name: str
    iac_reachability_risk: float = Field(ge=0.0, le=1.0)
    code_dataflow_risk: float = Field(ge=0.0, le=1.0)
    telemetry_blindspot_risk: float = Field(ge=0.0, le=1.0)
    effective_security_delta: float
    split_brain_detected: bool
    summary: str


class OrchestratorReport(BaseModel):
    """Consolidated report emitted by the Main Thread Orchestrator."""

    model_config = ConfigDict(frozen=True)

    project_codename: str = "Project PARALLAX"
    target_root: str
    subagent_reports: list[SubagentReport]
    split_brain_evaluations: list[SplitBrainDelta] = Field(default_factory=list)
    overall_posture: str
