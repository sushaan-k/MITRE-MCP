"""
Data models for the MCP Agentic AI Framework
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class ThreatSeverity(str, Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackTactic(BaseModel):
    """MITRE ATT&CK Tactic model"""
    id: str = Field(..., description="MITRE ATT&CK Tactic ID (e.g., TA0001)")
    name: str = Field(..., description="Tactic name")
    description: str = Field(..., description="Tactic description")
    external_id: str = Field(..., description="External reference ID")


class AttackTechnique(BaseModel):
    """MITRE ATT&CK Technique model"""
    id: str = Field(..., description="MITRE ATT&CK Technique ID (e.g., T1059)")
    name: str = Field(..., description="Technique name")
    description: str = Field(..., description="Technique description")
    tactic_ids: List[str] = Field(default_factory=list, description="Associated tactic IDs")
    sub_techniques: List[str] = Field(default_factory=list, description="Sub-technique IDs")
    platforms: List[str] = Field(default_factory=list, description="Supported platforms")
    data_sources: List[str] = Field(default_factory=list, description="Data sources for detection")
    mitigations: List[str] = Field(default_factory=list, description="Mitigation strategies")


class ThreatIndicator(BaseModel):
    """Threat indicator model"""
    id: str = Field(..., description="Unique indicator ID")
    type: str = Field(..., description="Indicator type (IP, domain, hash, etc.)")
    value: str = Field(..., description="Indicator value")
    severity: ThreatSeverity = Field(..., description="Threat severity")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score (0-1)")
    first_seen: datetime = Field(..., description="First observation timestamp")
    last_seen: datetime = Field(..., description="Last observation timestamp")
    tags: List[str] = Field(default_factory=list, description="Associated tags")
    context: Dict[str, Any] = Field(default_factory=dict, description="Additional context")


class ThreatReport(BaseModel):
    """Threat intelligence report model"""
    id: str = Field(..., description="Unique report ID")
    title: str = Field(..., description="Report title")
    description: str = Field(..., description="Report description")
    source: str = Field(..., description="Intelligence source")
    timestamp: datetime = Field(..., description="Report timestamp")
    severity: ThreatSeverity = Field(..., description="Overall threat severity")
    indicators: List[ThreatIndicator] = Field(default_factory=list, description="Threat indicators")
    raw_content: str = Field(..., description="Raw report content")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class AttackMapping(BaseModel):
    """Mapping between threats and MITRE ATT&CK framework"""
    id: str = Field(..., description="Unique mapping ID")
    threat_id: str = Field(..., description="Associated threat ID")
    tactic_id: str = Field(..., description="MITRE ATT&CK Tactic ID")
    technique_id: str = Field(..., description="MITRE ATT&CK Technique ID")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Mapping confidence score")
    evidence: List[str] = Field(default_factory=list, description="Supporting evidence")
    analyst_notes: str = Field(default="", description="Analyst annotations")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp")


class ThreatAnalysis(BaseModel):
    """Complete threat analysis result"""
    id: str = Field(..., description="Analysis ID")
    report: ThreatReport = Field(..., description="Original threat report")
    mappings: List[AttackMapping] = Field(default_factory=list, description="MITRE ATT&CK mappings")
    risk_score: float = Field(..., ge=0.0, le=10.0, description="Overall risk score (0-10)")
    recommendations: List[str] = Field(default_factory=list, description="Security recommendations")
    analysis_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Analysis timestamp")
    analyst: str = Field(default="AI Agent", description="Analyst identifier")


class MCPToolRequest(BaseModel):
    """MCP tool request model"""
    tool_name: str = Field(..., description="Name of the MCP tool")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Tool parameters")
    agent_id: str = Field(..., description="Requesting agent ID")
    session_id: str = Field(..., description="Session identifier")


class MCPToolResponse(BaseModel):
    """MCP tool response model"""
    success: bool = Field(..., description="Tool execution success status")
    result: Dict[str, Any] = Field(default_factory=dict, description="Tool execution result")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    execution_time: float = Field(..., description="Execution time in seconds")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
