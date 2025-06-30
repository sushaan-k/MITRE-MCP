import re
import json
import hashlib
from typing import List, Dict, Any, Tuple
from datetime import datetime
import logging
from models import (
    ThreatReport, ThreatIndicator, ThreatSeverity,
    AttackMapping, ThreatAnalysis
)
from mitre_attack import MitreAttackFramework


class ThreatAnalyzer:
    
    def __init__(self):
        self.mitre_framework = MitreAttackFramework()
        self.logger = logging.getLogger(__name__)

        self.technique_keywords = {
            "T1059": ["command", "script", "powershell", "cmd", "bash", "interpreter"],
            "T1566": ["phishing", "email", "attachment", "malicious link", "social engineering"],
            "T1055": ["process injection", "dll injection", "code injection", "memory injection"],
            "T1003": ["credential dump", "password", "hash", "mimikatz", "lsass"],
            "T1082": ["system info", "reconnaissance", "enumeration", "discovery", "whoami"]
        }

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
        self.logger.info(f"Starting threat analysis for report from {source}")

        analysis_id = self._generate_id(f"{source}_{raw_content[:100]}")
        threat_report = self._create_threat_report(raw_content, source)
        indicators = self._extract_indicators(raw_content)
        threat_report.indicators = indicators
        mappings = self._map_to_mitre_attack(raw_content, indicators)
        risk_score = self._calculate_risk_score(threat_report, mappings)
        recommendations = self._generate_recommendations(mappings, risk_score)

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
        report_id = self._generate_id(f"{source}_{raw_content[:50]}")
        lines = raw_content.split('\n')
        title = lines[0][:100] if lines else raw_content[:100]
        description = self._extract_description(raw_content)
        severity = self._assess_severity(raw_content)

        return ThreatReport(
            id=report_id,
            title=title,
            description=description,
            source=source,
            timestamp=datetime.utcnow(),
            severity=severity,
            indicators=[],
            raw_content=raw_content,
            metadata={"content_length": len(raw_content)}
        )
    
    def _extract_description(self, content: str) -> str:
        paragraphs = content.split('\n\n')
        if paragraphs:
            return paragraphs[0][:300]
        return content[:300]

    def _assess_severity(self, content: str) -> ThreatSeverity:
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
        indicators = []

        for ioc_type, pattern in self.ioc_patterns.items():
            matches = pattern.findall(content)
            for match in set(matches):
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
        content_lower = content.lower()

        if "malicious" in content_lower or "malware" in content_lower:
            return ThreatSeverity.HIGH
        elif "suspicious" in content_lower:
            return ThreatSeverity.MEDIUM
        else:
            return ThreatSeverity.LOW

    def _calculate_indicator_confidence(self, ioc_type: str, value: str, content: str) -> float:
        base_confidence = 0.5

        context_keywords = ["confirmed", "verified", "observed", "detected"]
        if any(keyword in content.lower() for keyword in context_keywords):
            base_confidence += 0.3

        if ioc_type in ["md5", "sha1", "sha256"]:
            base_confidence += 0.2

        return min(base_confidence, 1.0)

    def _generate_indicator_tags(self, ioc_type: str, value: str, content: str) -> List[str]:
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
        mappings = []
        keywords = self._extract_keywords(content)
        technique_matches = self.mitre_framework.search_techniques_by_keywords(keywords)

        for technique, confidence in technique_matches:
            if confidence > 0.3:
                evidence = self._find_evidence(content, technique, keywords)

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
        content_lower = content.lower()

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
        evidence = []
        content_lower = content.lower()

        if technique.id in self.technique_keywords:
            for keyword in self.technique_keywords[technique.id]:
                if keyword in content_lower:
                    evidence.append(f"Found keyword: '{keyword}'")

        if technique.name.lower() in content_lower:
            evidence.append(f"Technique name mentioned: '{technique.name}'")

        return evidence
    
    def _calculate_risk_score(self, report: ThreatReport, mappings: List[AttackMapping]) -> float:
        base_score = 0.0

        severity_scores = {
            ThreatSeverity.LOW: 2.0,
            ThreatSeverity.MEDIUM: 4.0,
            ThreatSeverity.HIGH: 7.0,
            ThreatSeverity.CRITICAL: 9.0
        }
        base_score += severity_scores.get(report.severity, 2.0)

        indicator_score = min(len(report.indicators) * 0.2, 2.0)
        base_score += indicator_score

        mapping_score = min(len(mappings) * 0.3, 3.0)
        base_score += mapping_score

        high_conf_mappings = [m for m in mappings if m.confidence > 0.7]
        if high_conf_mappings:
            base_score += len(high_conf_mappings) * 0.5

        return min(base_score, 10.0)
    
    def _generate_recommendations(self, mappings: List[AttackMapping], risk_score: float) -> List[str]:
        recommendations = []

        if risk_score >= 8.0:
            recommendations.append("IMMEDIATE ACTION: High-risk threat detected. Implement emergency response procedures.")
            recommendations.append("Isolate affected systems and conduct thorough investigation.")
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
        recommendations.append("Review and update security controls based on identified attack techniques.")

        return recommendations

    def _generate_id(self, content: str) -> str:
        return hashlib.md5(content.encode()).hexdigest()[:16]
