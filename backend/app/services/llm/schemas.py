"""Structured-output contracts for the Phase 7 investigation pipeline.

Every LLM call in this pipeline requests one of these schemas via Groq's
`json_schema` response format -- the model's output is validated against
it before anything downstream ever sees it. A response that doesn't
parse into one of these is a pipeline failure, not free text quietly
accepted.
"""

from enum import Enum

from pydantic import BaseModel, Field


class AnomalyType(str, Enum):
    port_scan = "port_scan"
    beaconing = "beaconing"
    dns_tunneling = "dns_tunneling"
    data_exfil = "data_exfil"
    unknown = "unknown"


class ClassificationResult(BaseModel):
    anomaly_type: AnomalyType
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str


class Citation(BaseModel):
    source: str  # a retrieved chunk id, e.g. "mitre:T1595:0"
    excerpt: str  # text that must actually appear in that chunk


class InvestigationOutput(BaseModel):
    summary: str
    detailed_narrative: str
    mitre_techniques: list[str] = []
    citations: list[Citation] = []
    confidence: float = Field(ge=0.0, le=1.0)
    recommended_action: str


class SelfCheckResult(BaseModel):
    citations_valid: bool
    invalid_citations: list[str] = []
    unsupported_claims: list[str] = []
    notes: str = ""
