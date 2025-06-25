from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class ThreatSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackTactic(BaseModel):
    id: str
    name: str
    description: str
    external_id: str


class AttackTechnique(BaseModel):
    id: str
    name: str
    description: str
    tactic_ids: List[str] = Field(default_factory=list)
    sub_techniques: List[str] = Field(default_factory=list)
    platforms: List[str] = Field(default_factory=list)
    data_sources: List[str] = Field(default_factory=list)
    mitigations: List[str] = Field(default_factory=list)


class ThreatIndicator(BaseModel):
    id: str
    type: str
    value: str
    severity: ThreatSeverity
    confidence: float = Field(..., ge=0.0, le=1.0)
    first_seen: datetime
    last_seen: datetime
    tags: List[str] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict)


class ThreatReport(BaseModel):
    id: str
    title: str
    description: str
    source: str
    timestamp: datetime
    severity: ThreatSeverity
    indicators: List[ThreatIndicator] = Field(default_factory=list)
    raw_content: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AttackMapping(BaseModel):
    id: str
    threat_id: str
    tactic_id: str
    technique_id: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence: List[str] = Field(default_factory=list)
    analyst_notes: str = Field(default="")
    created_at: datetime


class ThreatAnalysis(BaseModel):
    id: str
    report: ThreatReport
    mappings: List[AttackMapping] = Field(default_factory=list)
    risk_score: float = Field(..., ge=0.0, le=10.0)
    recommendations: List[str] = Field(default_factory=list)
    analysis_timestamp: datetime
    analyst: str = Field(default="AI Agent")


class MCPToolRequest(BaseModel):
    tool_name: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    agent_id: str
    session_id: str


class MCPToolResponse(BaseModel):
    success: bool
    result: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = Field(None)
    execution_time: float
    metadata: Dict[str, Any] = Field(default_factory=dict)
