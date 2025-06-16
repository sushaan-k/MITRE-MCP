"""
Threat Analyzer Engine
Core component for analyzing threats and mapping them to MITRE ATT&CK framework
"""
import re
import json
import hashlib
from typing import List, Dict, Any, Tuple
from datetime import datetime
import logging
from src.models import (
    ThreatReport, ThreatIndicator, ThreatSeverity, 
    AttackMapping, ThreatAnalysis
)
from src.mitre_attack import MitreAttackFramework


class ThreatAnalyzer:
    """
    Core threat analysis engine that processes threat intelligence
    and maps threats to MITRE ATT&CK framework
    """
    
    def __init__(self):
        self.mitre_framework = MitreAttackFramework()
        self.logger = logging.getLogger(__name__)
        
        # Keyword mappings for common threat indicators
        self.technique_keywords = {
            "T1059": ["command", "script", "powershell", "cmd", "bash", "interpreter"],
            "T1566": ["phishing", "email", "attachment", "malicious link", "social engineering"],
            "T1055": ["process injection", "dll injection", "code injection", "memory injection"],
            "T1003": ["credential dump", "password", "hash", "mimikatz", "lsass"],
            "T1082": ["system info", "reconnaissance", "enumeration", "discovery", "whoami"]
        }
        
        # IOC patterns
        self.ioc_patterns = {
            "ip": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            "domain": re.compile(r'\b[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\b'),
            "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
            "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
            "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
            "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            "url": re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        }
    
    def analyze_threat_report(self, raw_content: str, source: str = "Unknown") -> ThreatAnalysis:
        """
        Main method to analyze a threat intelligence report
        """
        self.logger.info(f"Starting threat analysis for report from {source}")
        
        # Generate unique ID for this analysis
        analysis_id = self._generate_id(f"{source}_{raw_content[:100]}")
        
        # Create threat report
        threat_report = self._create_threat_report(raw_content, source)
        
        # Extract threat indicators
        indicators = self._extract_indicators(raw_content)
        threat_report.indicators = indicators
        
        # Map to MITRE ATT&CK framework
        mappings = self._map_to_mitre_attack(raw_content, indicators)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(threat_report, mappings)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(mappings, risk_score)
        
        # Create analysis result
        analysis = ThreatAnalysis(
            id=analysis_id,
            report=threat_report,
            mappings=mappings,
            risk_score=risk_score,
            recommendations=recommendations,
            analysis_timestamp=datetime.utcnow(),
            analyst="AI Agent"
        )
        
        self.logger.info(f"Threat analysis completed. Risk score: {risk_score}")
        return analysis
    
    def _create_threat_report(self, raw_content: str, source: str) -> ThreatReport:
        """Create a structured threat report from raw content"""
        # Generate unique ID
        report_id = self._generate_id(f"{source}_{raw_content[:50]}")
        
        # Extract title (first line or first 100 chars)
        lines = raw_content.split('\n')
        title = lines[0][:100] if lines else raw_content[:100]
        
        # Extract description (first paragraph)
        description = self._extract_description(raw_content)
        
        # Determine severity based on content
        severity = self._assess_severity(raw_content)
        
        return ThreatReport(
            id=report_id,
            title=title,
            description=description,
            source=source,
            timestamp=datetime.utcnow(),
            severity=severity,
            indicators=[],  # Will be populated later
            raw_content=raw_content,
            metadata={"content_length": len(raw_content)}
        )
    
    def _extract_description(self, content: str) -> str:
        """Extract a meaningful description from content"""
        # Take first paragraph or first 300 characters
        paragraphs = content.split('\n\n')
        if paragraphs:
            return paragraphs[0][:300]
        return content[:300]
    
    def _assess_severity(self, content: str) -> ThreatSeverity:
        """Assess threat severity based on content keywords"""
        content_lower = content.lower()
        
        critical_keywords = ["ransomware", "data breach", "zero-day", "apt", "nation-state"]
        high_keywords = ["malware", "backdoor", "exploit", "vulnerability", "attack"]
        medium_keywords = ["suspicious", "anomaly", "unusual", "potential"]
        
        if any(keyword in content_lower for keyword in critical_keywords):
            return ThreatSeverity.CRITICAL
        elif any(keyword in content_lower for keyword in high_keywords):
            return ThreatSeverity.HIGH
        elif any(keyword in content_lower for keyword in medium_keywords):
            return ThreatSeverity.MEDIUM
        else:
            return ThreatSeverity.LOW
    
    def _extract_indicators(self, content: str) -> List[ThreatIndicator]:
        """Extract threat indicators from content"""
        indicators = []
        
        for ioc_type, pattern in self.ioc_patterns.items():
            matches = pattern.findall(content)
            for match in set(matches):  # Remove duplicates
                indicator_id = self._generate_id(f"{ioc_type}_{match}")
                
                indicator = ThreatIndicator(
                    id=indicator_id,
                    type=ioc_type,
                    value=match,
                    severity=self._assess_indicator_severity(ioc_type, match, content),
                    confidence=self._calculate_indicator_confidence(ioc_type, match, content),
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    tags=self._generate_indicator_tags(ioc_type, match, content),
                    context={"source_content": content[:200]}
                )
                indicators.append(indicator)
        
        return indicators
    
    def _assess_indicator_severity(self, ioc_type: str, value: str, content: str) -> ThreatSeverity:
        """Assess the severity of a specific indicator"""
        content_lower = content.lower()
        
        # Check context around the indicator
        if "malicious" in content_lower or "malware" in content_lower:
            return ThreatSeverity.HIGH
        elif "suspicious" in content_lower:
            return ThreatSeverity.MEDIUM
        else:
            return ThreatSeverity.LOW
    
    def _calculate_indicator_confidence(self, ioc_type: str, value: str, content: str) -> float:
        """Calculate confidence score for an indicator"""
        base_confidence = 0.5
        
        # Boost confidence based on context
        context_keywords = ["confirmed", "verified", "observed", "detected"]
        if any(keyword in content.lower() for keyword in context_keywords):
            base_confidence += 0.3
        
        # Boost confidence for certain IOC types
        if ioc_type in ["md5", "sha1", "sha256"]:
            base_confidence += 0.2
        
        return min(base_confidence, 1.0)
    
    def _generate_indicator_tags(self, ioc_type: str, value: str, content: str) -> List[str]:
        """Generate tags for an indicator based on context"""
        tags = [ioc_type]
        
        content_lower = content.lower()
        
        if "malware" in content_lower:
            tags.append("malware")
        if "phishing" in content_lower:
            tags.append("phishing")
        if "ransomware" in content_lower:
            tags.append("ransomware")
        if "apt" in content_lower:
            tags.append("apt")
        
        return tags
    
    def _map_to_mitre_attack(self, content: str, indicators: List[ThreatIndicator]) -> List[AttackMapping]:
        """Map threat content to MITRE ATT&CK techniques"""
        mappings = []
        content_lower = content.lower()
        
        # Extract keywords from content
        keywords = self._extract_keywords(content)
        
        # Search for matching techniques
        technique_matches = self.mitre_framework.search_techniques_by_keywords(keywords)
        
        for technique, confidence in technique_matches:
            if confidence > 0.3:  # Only include reasonably confident matches
                # Find supporting evidence
                evidence = self._find_evidence(content, technique, keywords)
                
                # Get associated tactics
                for tactic_id in technique.tactic_ids:
                    mapping_id = self._generate_id(f"mapping_{technique.id}_{tactic_id}")
                    
                    mapping = AttackMapping(
                        id=mapping_id,
                        threat_id=self._generate_id(content[:50]),
                        tactic_id=tactic_id,
                        technique_id=technique.id,
                        confidence=confidence,
                        evidence=evidence,
                        analyst_notes=f"Mapped based on keyword analysis with {confidence:.2f} confidence",
                        created_at=datetime.utcnow()
                    )
                    mappings.append(mapping)
        
        return mappings
    
    def _extract_keywords(self, content: str) -> List[str]:
        """Extract relevant keywords from content for technique matching"""
        # Simple keyword extraction - could be enhanced with NLP
        content_lower = content.lower()
        
        # Common cybersecurity keywords
        security_keywords = [
            "malware", "virus", "trojan", "backdoor", "ransomware",
            "phishing", "spear phishing", "social engineering",
            "command", "script", "powershell", "cmd", "bash",
            "injection", "exploit", "vulnerability", "persistence",
            "privilege escalation", "lateral movement", "exfiltration",
            "credential", "password", "hash", "mimikatz",
            "reconnaissance", "discovery", "enumeration",
            "remote access", "c2", "command and control"
        ]
        
        found_keywords = []
        for keyword in security_keywords:
            if keyword in content_lower:
                found_keywords.append(keyword)
        
        return found_keywords
    
    def _find_evidence(self, content: str, technique, keywords: List[str]) -> List[str]:
        """Find supporting evidence for a technique mapping"""
        evidence = []
        content_lower = content.lower()
        
        # Look for technique-specific keywords
        if technique.id in self.technique_keywords:
            for keyword in self.technique_keywords[technique.id]:
                if keyword in content_lower:
                    evidence.append(f"Found keyword: '{keyword}'")
        
        # Look for general matches with technique name/description
        if technique.name.lower() in content_lower:
            evidence.append(f"Technique name mentioned: '{technique.name}'")
        
        return evidence
    
    def _calculate_risk_score(self, report: ThreatReport, mappings: List[AttackMapping]) -> float:
        """Calculate overall risk score (0-10)"""
        base_score = 0.0
        
        # Severity contribution
        severity_scores = {
            ThreatSeverity.LOW: 2.0,
            ThreatSeverity.MEDIUM: 4.0,
            ThreatSeverity.HIGH: 7.0,
            ThreatSeverity.CRITICAL: 9.0
        }
        base_score += severity_scores.get(report.severity, 2.0)
        
        # Number of indicators contribution
        indicator_score = min(len(report.indicators) * 0.2, 2.0)
        base_score += indicator_score
        
        # MITRE ATT&CK mappings contribution
        mapping_score = min(len(mappings) * 0.3, 3.0)
        base_score += mapping_score
        
        # High-confidence mappings boost
        high_conf_mappings = [m for m in mappings if m.confidence > 0.7]
        if high_conf_mappings:
            base_score += len(high_conf_mappings) * 0.5
        
        return min(base_score, 10.0)
    
    def _generate_recommendations(self, mappings: List[AttackMapping], risk_score: float) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        # Risk-based recommendations
        if risk_score >= 8.0:
            recommendations.append("IMMEDIATE ACTION: High-risk threat detected. Implement emergency response procedures.")
            recommendations.append("Isolate affected systems and conduct thorough investigation.")
        elif risk_score >= 6.0:
            recommendations.append("HIGH PRIORITY: Significant threat identified. Increase monitoring and deploy additional countermeasures.")
        elif risk_score >= 4.0:
            recommendations.append("MEDIUM PRIORITY: Potential threat detected. Review security controls and update threat intelligence.")
        else:
            recommendations.append("LOW PRIORITY: Monitor for additional indicators and maintain standard security posture.")
        
        # Technique-specific recommendations
        technique_ids = set(mapping.technique_id for mapping in mappings)
        
        if "T1566" in technique_ids:  # Phishing
            recommendations.append("Implement email security controls and user awareness training for phishing attacks.")
        
        if "T1059" in technique_ids:  # Command and Scripting Interpreter
            recommendations.append("Monitor and restrict script execution. Implement application whitelisting.")
        
        if "T1055" in technique_ids:  # Process Injection
            recommendations.append("Deploy endpoint detection and response (EDR) solutions to detect process injection.")
        
        if "T1003" in technique_ids:  # OS Credential Dumping
            recommendations.append("Implement credential protection measures and monitor for credential access attempts.")
        
        # General recommendations
        recommendations.append("Update threat intelligence feeds with new indicators.")
        recommendations.append("Review and update security controls based on identified attack techniques.")
        
        return recommendations
    
    def _generate_id(self, content: str) -> str:
        """Generate a unique ID based on content"""
        return hashlib.md5(content.encode()).hexdigest()[:16]
