#!/usr/bin/env python3
"""
Simple demonstration of the MCP Agentic AI Threat Intelligence Framework
"""
import json
import sqlite3
import re
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

# Simple data classes instead of Pydantic
class ThreatSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class AttackTactic:
    id: str
    name: str
    description: str
    external_id: str

@dataclass
class AttackTechnique:
    id: str
    name: str
    description: str
    tactic_ids: List[str]
    platforms: List[str]
    data_sources: List[str]
    mitigations: List[str]

@dataclass
class ThreatIndicator:
    id: str
    type: str
    value: str
    severity: ThreatSeverity
    confidence: float
    first_seen: datetime
    last_seen: datetime
    tags: List[str]

@dataclass
class ThreatReport:
    id: str
    title: str
    description: str
    source: str
    timestamp: datetime
    severity: ThreatSeverity
    indicators: List[ThreatIndicator]
    raw_content: str

@dataclass
class AttackMapping:
    id: str
    threat_id: str
    tactic_id: str
    technique_id: str
    confidence: float
    evidence: List[str]
    analyst_notes: str
    created_at: datetime

@dataclass
class ThreatAnalysis:
    id: str
    report: ThreatReport
    mappings: List[AttackMapping]
    risk_score: float
    recommendations: List[str]
    analysis_timestamp: datetime
    analyst: str


class SimpleMitreFramework:
    """Simple MITRE ATT&CK Framework implementation"""
    
    def __init__(self, db_path: str = "data/mitre_attack.db"):
        self.db_path = db_path
        self._ensure_database()
        
    def _ensure_database(self):
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
        
        if not Path(self.db_path).exists():
            self._initialize_database()
            self._populate_database()
    
    def _initialize_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tactics (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                external_id TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS techniques (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                platforms TEXT,
                data_sources TEXT,
                mitigations TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS technique_tactics (
                technique_id TEXT,
                tactic_id TEXT,
                PRIMARY KEY (technique_id, tactic_id)
            )
        """)
        
        conn.commit()
        conn.close()
    
    def _populate_database(self):
        tactics_data = [
            {"id": "TA0001", "name": "Initial Access", "description": "The adversary is trying to get into your network.", "external_id": "TA0001"},
            {"id": "TA0002", "name": "Execution", "description": "The adversary is trying to run malicious code.", "external_id": "TA0002"},
            {"id": "TA0003", "name": "Persistence", "description": "The adversary is trying to maintain their foothold.", "external_id": "TA0003"},
            {"id": "TA0004", "name": "Privilege Escalation", "description": "The adversary is trying to gain higher-level permissions.", "external_id": "TA0004"},
            {"id": "TA0005", "name": "Defense Evasion", "description": "The adversary is trying to avoid being detected.", "external_id": "TA0005"},
            {"id": "TA0006", "name": "Credential Access", "description": "The adversary is trying to steal account names and passwords.", "external_id": "TA0006"},
            {"id": "TA0007", "name": "Discovery", "description": "The adversary is trying to figure out your environment.", "external_id": "TA0007"},
            {"id": "TA0008", "name": "Lateral Movement", "description": "The adversary is trying to move through your environment.", "external_id": "TA0008"},
            {"id": "TA0009", "name": "Collection", "description": "The adversary is trying to gather data of interest.", "external_id": "TA0009"},
            {"id": "TA0010", "name": "Exfiltration", "description": "The adversary is trying to steal data.", "external_id": "TA0010"},
            {"id": "TA0011", "name": "Command and Control", "description": "The adversary is trying to communicate with compromised systems.", "external_id": "TA0011"},
            {"id": "TA0040", "name": "Impact", "description": "The adversary is trying to manipulate, interrupt, or destroy your systems and data.", "external_id": "TA0040"}
        ]
        
        techniques_data = [
            {"id": "T1059", "name": "Command and Scripting Interpreter", "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Command", "Process", "Script"], "mitigations": ["Code Signing", "Execution Prevention"], "tactics": ["TA0002"]},
            {"id": "T1566", "name": "Phishing", "description": "Adversaries may send phishing messages to gain access to victim systems.", "platforms": ["Windows", "Linux", "macOS", "Office 365", "SaaS", "Google Workspace"], "data_sources": ["Application Log", "Email Gateway", "File"], "mitigations": ["User Training", "Email Security"], "tactics": ["TA0001"]},
            {"id": "T1055", "name": "Process Injection", "description": "Adversaries may inject code into processes in order to evade process-based defenses.", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Process", "Windows Registry"], "mitigations": ["Behavior Prevention on Endpoint"], "tactics": ["TA0004", "TA0005"]},
            {"id": "T1003", "name": "OS Credential Dumping", "description": "Adversaries may attempt to dump credentials to obtain account login information.", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Command", "File", "Process"], "mitigations": ["Password Policies", "Privileged Account Management"], "tactics": ["TA0006"]},
            {"id": "T1082", "name": "System Information Discovery", "description": "An adversary may attempt to get detailed information about the operating system and hardware.", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Command", "Process"], "mitigations": [], "tactics": ["TA0007"]}
        ]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for tactic in tactics_data:
            cursor.execute("INSERT OR REPLACE INTO tactics (id, name, description, external_id) VALUES (?, ?, ?, ?)", 
                          (tactic["id"], tactic["name"], tactic["description"], tactic["external_id"]))
        
        for technique in techniques_data:
            cursor.execute("INSERT OR REPLACE INTO techniques (id, name, description, platforms, data_sources, mitigations) VALUES (?, ?, ?, ?, ?, ?)", 
                          (technique["id"], technique["name"], technique["description"], json.dumps(technique["platforms"]), json.dumps(technique["data_sources"]), json.dumps(technique["mitigations"])))
            
            for tactic_id in technique["tactics"]:
                cursor.execute("INSERT OR REPLACE INTO technique_tactics (technique_id, tactic_id) VALUES (?, ?)", 
                              (technique["id"], tactic_id))
        
        conn.commit()
        conn.close()
    
    def get_all_tactics(self) -> List[AttackTactic]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, description, external_id FROM tactics ORDER BY id")
        rows = cursor.fetchall()
        conn.close()
        
        return [AttackTactic(id=row[0], name=row[1], description=row[2] or "", external_id=row[3] or "") for row in rows]
    
    def search_techniques_by_keywords(self, keywords: List[str]) -> List[Tuple[AttackTechnique, float]]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT t.id, t.name, t.description, t.platforms, t.data_sources, t.mitigations,
                   GROUP_CONCAT(tt.tactic_id) as tactic_ids
            FROM techniques t
            LEFT JOIN technique_tactics tt ON t.id = tt.technique_id
            GROUP BY t.id, t.name, t.description, t.platforms, t.data_sources, t.mitigations
            ORDER BY t.id
        """)
        rows = cursor.fetchall()
        conn.close()
        
        techniques = []
        for row in rows:
            tactic_ids = row[6].split(",") if row[6] else []
            technique = AttackTechnique(
                id=row[0], name=row[1], description=row[2] or "", tactic_ids=tactic_ids,
                platforms=json.loads(row[3]) if row[3] else [],
                data_sources=json.loads(row[4]) if row[4] else [],
                mitigations=json.loads(row[5]) if row[5] else []
            )
            
            # Calculate match score
            score = self._calculate_keyword_match_score(technique, keywords)
            if score > 0:
                techniques.append((technique, score))
        
        return sorted(techniques, key=lambda x: x[1], reverse=True)
    
    def _calculate_keyword_match_score(self, technique: AttackTechnique, keywords: List[str]) -> float:
        text_fields = [technique.name.lower(), technique.description.lower(), " ".join(technique.platforms).lower()]
        full_text = " ".join(text_fields)
        
        keyword_matches = sum(1 for keyword in keywords if keyword.lower() in full_text)
        if len(keywords) == 0:
            return 0.0
        
        base_score = keyword_matches / len(keywords)
        if any(keyword.lower() in technique.name.lower() for keyword in keywords):
            base_score *= 1.5
        
        return min(base_score, 1.0)


class SimpleThreatAnalyzer:
    """Simple threat analyzer implementation"""
    
    def __init__(self):
        self.mitre_framework = SimpleMitreFramework()
        
        self.ioc_patterns = {
            "ip": re.compile(r'\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b'),
            "domain": re.compile(r'\\b[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\\.[a-zA-Z]{2,}\\b'),
            "md5": re.compile(r'\\b[a-fA-F0-9]{32}\\b'),
            "sha1": re.compile(r'\\b[a-fA-F0-9]{40}\\b'),
            "sha256": re.compile(r'\\b[a-fA-F0-9]{64}\\b'),
            "email": re.compile(r'\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b'),
            "url": re.compile(r'https?://[^\\s<>"{}|\\\\^`\\[\\]]+')
        }
    
    def analyze_threat_report(self, raw_content: str, source: str = "Unknown") -> ThreatAnalysis:
        analysis_id = self._generate_id(f"{source}_{raw_content[:100]}")
        
        # Create threat report
        threat_report = self._create_threat_report(raw_content, source)
        
        # Extract indicators
        indicators = self._extract_indicators(raw_content)
        threat_report.indicators = indicators
        
        # Map to MITRE ATT&CK
        mappings = self._map_to_mitre_attack(raw_content)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(threat_report, mappings)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(mappings, risk_score)
        
        return ThreatAnalysis(
            id=analysis_id, report=threat_report, mappings=mappings,
            risk_score=risk_score, recommendations=recommendations,
            analysis_timestamp=datetime.utcnow(), analyst="AI Agent"
        )
    
    def _create_threat_report(self, raw_content: str, source: str) -> ThreatReport:
        report_id = self._generate_id(f"{source}_{raw_content[:50]}")
        lines = raw_content.split('\\n')
        title = lines[0][:100] if lines else raw_content[:100]
        description = raw_content[:300]
        severity = self._assess_severity(raw_content)
        
        return ThreatReport(
            id=report_id, title=title, description=description, source=source,
            timestamp=datetime.utcnow(), severity=severity, indicators=[], raw_content=raw_content
        )
    
    def _assess_severity(self, content: str) -> ThreatSeverity:
        content_lower = content.lower()
        
        if any(keyword in content_lower for keyword in ["ransomware", "data breach", "zero-day", "apt", "nation-state"]):
            return ThreatSeverity.CRITICAL
        elif any(keyword in content_lower for keyword in ["malware", "backdoor", "exploit", "vulnerability", "attack"]):
            return ThreatSeverity.HIGH
        elif any(keyword in content_lower for keyword in ["suspicious", "anomaly", "unusual", "potential"]):
            return ThreatSeverity.MEDIUM
        else:
            return ThreatSeverity.LOW
    
    def _extract_indicators(self, content: str) -> List[ThreatIndicator]:
        indicators = []
        
        for ioc_type, pattern in self.ioc_patterns.items():
            matches = pattern.findall(content)
            for match in set(matches):
                indicator_id = self._generate_id(f"{ioc_type}_{match}")
                indicator = ThreatIndicator(
                    id=indicator_id, type=ioc_type, value=match, severity=ThreatSeverity.MEDIUM,
                    confidence=0.7, first_seen=datetime.utcnow(), last_seen=datetime.utcnow(), tags=[ioc_type]
                )
                indicators.append(indicator)
        
        return indicators
    
    def _map_to_mitre_attack(self, content: str) -> List[AttackMapping]:
        mappings = []
        keywords = self._extract_keywords(content)
        
        technique_matches = self.mitre_framework.search_techniques_by_keywords(keywords)
        
        for technique, confidence in technique_matches:
            if confidence > 0.3:
                evidence = self._find_evidence(content, technique, keywords)
                
                for tactic_id in technique.tactic_ids:
                    mapping_id = self._generate_id(f"mapping_{technique.id}_{tactic_id}")
                    mapping = AttackMapping(
                        id=mapping_id, threat_id=self._generate_id(content[:50]),
                        tactic_id=tactic_id, technique_id=technique.id, confidence=confidence,
                        evidence=evidence, analyst_notes=f"Mapped with {confidence:.2f} confidence",
                        created_at=datetime.utcnow()
                    )
                    mappings.append(mapping)
        
        return mappings
    
    def _extract_keywords(self, content: str) -> List[str]:
        content_lower = content.lower()
        security_keywords = [
            "malware", "virus", "trojan", "backdoor", "ransomware", "phishing", "spear phishing",
            "social engineering", "command", "script", "powershell", "cmd", "bash", "injection",
            "exploit", "vulnerability", "persistence", "privilege escalation", "lateral movement",
            "exfiltration", "credential", "password", "hash", "mimikatz", "reconnaissance",
            "discovery", "enumeration", "remote access", "c2", "command and control"
        ]
        
        return [keyword for keyword in security_keywords if keyword in content_lower]
    
    def _find_evidence(self, content: str, technique, keywords: List[str]) -> List[str]:
        evidence = []
        content_lower = content.lower()
        
        if technique.name.lower() in content_lower:
            evidence.append(f"Technique name mentioned: '{technique.name}'")
        
        for keyword in keywords:
            if keyword in content_lower:
                evidence.append(f"Found keyword: '{keyword}'")
        
        return evidence[:3]  # Limit evidence
    
    def _calculate_risk_score(self, report: ThreatReport, mappings: List[AttackMapping]) -> float:
        severity_scores = {ThreatSeverity.LOW: 2.0, ThreatSeverity.MEDIUM: 4.0, ThreatSeverity.HIGH: 7.0, ThreatSeverity.CRITICAL: 9.0}
        base_score = severity_scores.get(report.severity, 2.0)
        
        indicator_score = min(len(report.indicators) * 0.2, 2.0)
        mapping_score = min(len(mappings) * 0.3, 3.0)
        
        return min(base_score + indicator_score + mapping_score, 10.0)
    
    def _generate_recommendations(self, mappings: List[AttackMapping], risk_score: float) -> List[str]:
        recommendations = []
        
        if risk_score >= 8.0:
            recommendations.append("IMMEDIATE ACTION: High-risk threat detected. Implement emergency response procedures.")
        elif risk_score >= 6.0:
            recommendations.append("HIGH PRIORITY: Significant threat identified. Increase monitoring and deploy additional countermeasures.")
        elif risk_score >= 4.0:
            recommendations.append("MEDIUM PRIORITY: Potential threat detected. Review security controls and update threat intelligence.")
        else:
            recommendations.append("LOW PRIORITY: Monitor for additional indicators and maintain standard security posture.")
        
        technique_ids = set(mapping.technique_id for mapping in mappings)
        
        if "T1566" in technique_ids:
            recommendations.append("Implement email security controls and user awareness training for phishing attacks.")
        if "T1059" in technique_ids:
            recommendations.append("Monitor and restrict script execution. Implement application whitelisting.")
        if "T1055" in technique_ids:
            recommendations.append("Deploy endpoint detection and response (EDR) solutions to detect process injection.")
        if "T1003" in technique_ids:
            recommendations.append("Implement credential protection measures and monitor for credential access attempts.")
        
        recommendations.append("Update threat intelligence feeds with new indicators.")
        
        return recommendations
    
    def _generate_id(self, content: str) -> str:
        return hashlib.md5(content.encode()).hexdigest()[:16]


def run_demo():
    print("=" * 70)
    print("🛡️  MCP AGENTIC AI THREAT INTELLIGENCE FRAMEWORK  🛡️")
    print("   Mapping Cyber Threats to MITRE ATT&CK Framework")
    print("=" * 70)
    print()
    
    print("🚀 Initializing System...")
    analyzer = SimpleThreatAnalyzer()
    mitre = SimpleMitreFramework()
    
    print("✅ System initialized successfully!")
    print()
    
    # Demo 1: Show MITRE tactics
    print("📋 Available MITRE ATT&CK Tactics:")
    tactics = mitre.get_all_tactics()
    for tactic in tactics[:6]:
        print(f"  • {tactic.id}: {tactic.name}")
    print(f"  ... and {len(tactics)-6} more tactics")
    print()
    
    # Demo 2: Search techniques
    print("🔍 Searching techniques for 'phishing':")
    results = mitre.search_techniques_by_keywords(["phishing"])
    for technique, confidence in results[:3]:
        print(f"  • {technique.id}: {technique.name} (confidence: {confidence:.2f})")
    print()
    
    # Demo 3: Analyze sample threat
    sample_threat = """
    THREAT INTELLIGENCE REPORT

    Title: APT29 Phishing Campaign Targeting Government Entities

    Description: Our security team has identified a sophisticated phishing campaign 
    attributed to APT29 (Cozy Bear) targeting government entities. The campaign 
    utilizes spear-phishing emails with malicious attachments containing PowerShell scripts.

    Indicators of Compromise (IOCs):
    - Email: cozy-updates@gov-secure.com
    - Domain: gov-secure.com
    - IP Address: 185.234.72.45
    - File Hash (SHA256): 4f2d8b2c1a3e5d6f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f
    - Command: powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden

    Attack Details:
    The malicious emails contain PDF attachments that exploit a vulnerability to execute 
    PowerShell commands. The PowerShell script establishes persistence through scheduled 
    tasks and attempts to collect credentials using mimikatz-like techniques.
    """
    
    print("🔬 Analyzing sample threat intelligence report...")
    analysis = analyzer.analyze_threat_report(sample_threat, "Security Team")
    
    print(f"📊 ANALYSIS RESULTS:")
    print(f"  Analysis ID: {analysis.id}")
    print(f"  Severity: {analysis.report.severity.value.upper()}")
    print(f"  Risk Score: {analysis.risk_score:.1f}/10")
    print(f"  Indicators Found: {len(analysis.report.indicators)}")
    print(f"  MITRE Mappings: {len(analysis.mappings)}")
    print()
    
    print("🎯 THREAT INDICATORS:")
    for indicator in analysis.report.indicators[:3]:
        print(f"  • {indicator.type.upper()}: {indicator.value}")
    print()
    
    print("🗺️ MITRE ATT&CK MAPPINGS:")
    for mapping in analysis.mappings[:3]:
        print(f"  • Technique {mapping.technique_id} → Tactic {mapping.tactic_id}")
        print(f"    Confidence: {mapping.confidence:.2f}")
    print()
    
    print("💡 SECURITY RECOMMENDATIONS:")
    for i, rec in enumerate(analysis.recommendations[:3], 1):
        print(f"  {i}. {rec}")
    print()
    
    print("🤖 MCP Integration Simulation:")
    tools = ["analyze_threat_report", "search_mitre_techniques", "get_mitre_tactic_details"]
    print("📚 Available MCP Tools for AI Agents:")
    for i, tool in enumerate(tools, 1):
        print(f"  {i}. {tool}")
    print()
    
    print("✅ System Status:")
    print("  ✓ MITRE ATT&CK Framework: Operational")
    print("  ✓ Threat Analysis Engine: Operational")
    print("  ✓ MCP Server Framework: Ready")
    print("  ✓ Web Interface: Available")
    print()
    
    print("🚀 Next Steps:")
    print("  • Start web interface: python3 src/web_interface.py")
    print("  • Access at: http://localhost:8000")
    print("  • View API docs: http://localhost:8000/docs")


if __name__ == "__main__":
    run_demo()
