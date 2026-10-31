from typing import Literal
from pydantic import BaseModel, Field


class Hypothesis(BaseModel):
    id: str
    statement: str
    status: Literal["待验证", "获得支持", "被削弱", "无法确定"]
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)


class Observation(BaseModel):
    evidence_id: str
    observation: str


class InvestigationResult(BaseModel):
    request_kind: Literal["query", "investigation"] = "investigation"
    outcome: Literal["answered", "insufficient_information", "execution_failed"] = "answered"
    observations: list[Observation]
    hypotheses: list[Hypothesis]
    conclusion: str = Field(min_length=1)
    conclusion_evidence_ids: list[str]
    limitations: list[str]
    recommendations: list[str]
