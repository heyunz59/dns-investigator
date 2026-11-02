from typing import Literal
from pydantic import BaseModel, Field, ConfigDict


class Hypothesis(BaseModel):
    testable_claim: Literal["dns_query_failure","tcp_connection_failure","http_error_response","certificate_verification_failure"] | None = None
    measurement_scope: dict = Field(default_factory=dict)
    evidence_review_notes: list[str] = Field(default_factory=list)
    category: Literal["dns_resolution","transport","http_response","certificate_validation","client_environment","endpoint_intent","registration","other"] = "other"
    id: str
    statement: str
    status: Literal["待验证", "获得支持", "被削弱", "无法确定"]
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)


class AgentDraft(BaseModel):
    """Model-owned decisions only. Measurement/report fields remain application-owned."""
    model_config=ConfigDict(extra="forbid")
    request_kind: Literal["query","investigation"]
    outcome: Literal["answered","insufficient_information","execution_failed"]
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    analysis_summary: str = ""
    limitations: list[str] = Field(default_factory=list)
    next_directions: list[str] = Field(default_factory=list)


class Observation(BaseModel):
    evidence_id: str
    observation: str


class ExecutionIssue(BaseModel):
    attempt_id: str
    tool_name: str
    target: str
    record_type: str | None = None
    error_code: str
    description: str = ""


class Finding(BaseModel):
    provenance: str = "observed"
    finding_status: str = "observed"
    severity: str = "information"
    validation_result_ids: list[str] = Field(default_factory=list)
    scope: dict = Field(default_factory=dict)
    observed_facts: list[dict] = Field(default_factory=list)
    localization: dict = Field(default_factory=dict)
    root_cause_confirmed: Literal[False] = False
    code: str
    stage: str
    status: str
    evidence_ids: list[str]
    explanation: str
    limitations: list[str]
    next_checks: list[str]


class InvestigationResult(BaseModel):
    authority_investigations: list[dict] = Field(default_factory=list)
    diagnostic_assessment: str = ""
    assessment_level: str = "unassessed"
    report_fallback_reason: str | None = None
    dns_comparison: dict = Field(default_factory=dict)
    execution_issues: list[ExecutionIssue] = Field(default_factory=list)
    measured_facts: list[dict] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    request_kind: Literal["query", "investigation"] = "investigation"
    outcome: Literal["answered", "insufficient_information", "execution_failed"] = "answered"
    observations: list[Observation]
    hypotheses: list[Hypothesis]
    conclusion: str = Field(min_length=1)
    conclusion_evidence_ids: list[str]
    limitations: list[str]
    recommendations: list[str]
