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


class RemediationBranch(BaseModel):
    condition: str
    interpretation: str
    next_action: str
    change_prerequisites: list[str] = Field(default_factory=list)


class RemediationStep(BaseModel):
    method: dict = Field(default_factory=dict)
    branches: list[RemediationBranch] = Field(default_factory=list)
    id: str
    priority: int = Field(ge=1)
    title: str
    action_type: Literal['CHECK', 'POSSIBLE_FIX', 'VERIFY']
    description: str
    target: str
    reason: str
    related_finding_codes: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    validation_ids: list[str] = Field(default_factory=list)
    instructions: list[str] = Field(default_factory=list)
    expected_outcomes: list[str] = Field(default_factory=list)
    verification_method: str
    prerequisites: list[str] = Field(default_factory=list)
    safety_notes: list[str] = Field(default_factory=list)
    executed: Literal[False] = False


class DiagnosticConclusion(BaseModel):
    status_code: int | None = None
    error_details: dict = Field(default_factory=dict)
    location: list[dict] = Field(default_factory=list)
    fault_component: str | None = None
    failure_stage: str | None = None
    reason_code: str | None = None
    direct_evidence_ids: list[str] = Field(default_factory=list)
    direct_validation_ids: list[str] = Field(default_factory=list)
    dependency_evidence_ids: list[str] = Field(default_factory=list)
    dependency_validation_ids: list[str] = Field(default_factory=list)
    relevance: str = 'unknown_context'
    selection_reason: str = '未取得受控问题上下文；不据此推断用户关注点。'
    intent_source: str = 'unknown'
    diagnosis_status: Literal['CONFIRMED_PROTOCOL_ISSUE', 'LIKELY_CAUSE', 'FAULT_LOCALIZED',
                              'NO_FAULT_OBSERVED', 'INSUFFICIENT_EVIDENCE']
    fault_detected: bool | None = None
    primary_issue: str
    summary: str
    fault_layer: Literal['Recursive DNS', 'Authoritative DNS', 'Delegation', 'DNSSEC',
                         'CNAME/Alias Resolution', 'TCP/Network Transport', 'TLS', 'HTTP',
                         'Client Environment', 'Unknown'] = 'Unknown'
    fault_location: str
    affected_scope: list[dict] = Field(default_factory=list)
    unaffected_or_comparison_scope: list[dict] = Field(default_factory=list)
    cause: str
    cause_status: Literal['VERIFIED_PROTOCOL', 'OBSERVED_MECHANISM', 'CANDIDATE', 'UNKNOWN'] = 'UNKNOWN'
    alternative_causes: list[str] = Field(default_factory=list)
    reason: str
    evidence_ids: list[str] = Field(default_factory=list)
    validation_ids: list[str] = Field(default_factory=list)
    finding_codes: list[str] = Field(default_factory=list)
    relevant_attempt_ids: list[str] = Field(default_factory=list)
    source_modes: list[str] = Field(default_factory=list)
    remediation_steps: list[RemediationStep] = Field(default_factory=list)
    verification_steps: list[RemediationStep] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class InvestigationResult(BaseModel):
    request_context: dict = Field(default_factory=dict)
    diagnosis_selection_mode: Literal['primary','parallel'] = 'primary'
    diagnostic_conclusion: DiagnosticConclusion | None = None
    secondary_diagnoses: list[DiagnosticConclusion] = Field(default_factory=list)
    diagnosis_ordering: str = ''
    remediation_plan: list[RemediationStep] = Field(default_factory=list)
    candidate_analysis: list[dict] = Field(default_factory=list)
    protocol_investigations: list[dict] = Field(default_factory=list)
    validation_results: list[dict] = Field(default_factory=list)
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
