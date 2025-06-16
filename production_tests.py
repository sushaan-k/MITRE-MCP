#!/usr/bin/env python3
"""
Comprehensive Test Suite for MCP Threat Intelligence Framework
Validates all components, APIs, and MCP tools before production deployment
"""

import sys
import os
import json
import time
import asyncio
import subprocess
from typing import Dict, Any, List
from datetime import datetime

# Add src to path
sys.path.append('src')

from threat_analyzer import ThreatAnalyzer
from mitre_attack import MitreAttackFramework
from mcp_server import MCPThreatIntelligenceServer

class TestResult:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []
        
    def pass_test(self, name: str):
        print(f"✅ {name}")
        self.passed += 1
        
    def fail_test(self, name: str, error: str):
        print(f"❌ {name}: {error}")
        self.failed += 1
        self.errors.append(f"{name}: {error}")
        
    def get_summary(self):
        total = self.passed + self.failed
        success_rate = (self.passed / total * 100) if total > 0 else 0
        return {
            "total_tests": total,
            "passed": self.passed,
            "failed": self.failed,
            "success_rate": f"{success_rate:.1f}%",
            "errors": self.errors
        }

async def test_framework():
    """Run comprehensive tests on the MCP framework"""
    result = TestResult()
    
    print("🛡️ MCP THREAT INTELLIGENCE FRAMEWORK - PRODUCTION READINESS TESTS")
    print("=" * 70)
    print(f"Test started at: {datetime.now().isoformat()}")
    print()
    
    # 1. Core Component Tests
    print("📊 TESTING CORE COMPONENTS")
    print("-" * 40)
    
    try:
        # Test MITRE Framework
        mitre = MitreAttackFramework()
        tactics = mitre.get_all_tactics()
        if len(tactics) >= 12:
            result.pass_test("MITRE Framework - Tactics Loading")
        else:
            result.fail_test("MITRE Framework - Tactics Loading", f"Only {len(tactics)} tactics loaded")
            
        techniques = mitre.get_all_techniques()
        if len(techniques) >= 5:
            result.pass_test("MITRE Framework - Techniques Loading")
        else:
            result.fail_test("MITRE Framework - Techniques Loading", f"Only {len(techniques)} techniques loaded")
            
        # Test technique search
        search_results = mitre.search_techniques_by_keywords(["phishing"])
        if len(search_results) > 0:
            result.pass_test("MITRE Framework - Technique Search")
        else:
            result.fail_test("MITRE Framework - Technique Search", "No results for 'phishing'")
            
    except Exception as e:
        result.fail_test("MITRE Framework - Initialization", str(e))
    
    try:
        # Test Threat Analyzer
        analyzer = ThreatAnalyzer()
        test_threat = "Phishing email with PowerShell payload from 192.168.1.100"
        analysis = analyzer.analyze_threat_report(test_threat, "test")
        
        if analysis.risk_score >= 0 and analysis.risk_score <= 10:
            result.pass_test("Threat Analyzer - Risk Scoring")
        else:
            result.fail_test("Threat Analyzer - Risk Scoring", f"Invalid risk score: {analysis.risk_score}")
            
        if len(analysis.indicators) > 0:
            result.pass_test("Threat Analyzer - IOC Extraction")
        else:
            result.fail_test("Threat Analyzer - IOC Extraction", "No IOCs extracted")
            
        if len(analysis.mitre_mappings) > 0:
            result.pass_test("Threat Analyzer - MITRE Mapping")
        else:
            result.fail_test("Threat Analyzer - MITRE Mapping", "No MITRE mappings generated")
            
    except Exception as e:
        result.fail_test("Threat Analyzer - Core Functions", str(e))
    
    # 2. MCP Server Tests
    print("\n⚡ TESTING MCP SERVER")
    print("-" * 40)
    
    try:
        mcp_server = MCPThreatIntelligenceServer()
        
        # Test analyze_threat_report tool
        args = {"content": "Phishing attack detected", "source": "SOC"}
        response = await mcp_server.analyze_threat_report(args)
        if response.get("success"):
            result.pass_test("MCP Server - analyze_threat_report")
        else:
            result.fail_test("MCP Server - analyze_threat_report", response.get("error", "Unknown error"))
            
        # Test search_mitre_techniques tool
        args = {"keywords": ["phishing"], "min_confidence": 0.3}
        response = await mcp_server.search_mitre_techniques(args)
        if response.get("success") and response.get("results_count", 0) > 0:
            result.pass_test("MCP Server - search_mitre_techniques")
        else:
            result.fail_test("MCP Server - search_mitre_techniques", "No results returned")
            
        # Test get_mitre_tactic_details tool
        args = {"tactic_id": "TA0001"}
        response = await mcp_server.get_mitre_tactic_details(args)
        if response.get("success"):
            result.pass_test("MCP Server - get_mitre_tactic_details")
        else:
            result.fail_test("MCP Server - get_mitre_tactic_details", response.get("error", "Unknown error"))
            
        # Test list_all_tactics tool
        args = {}
        response = await mcp_server.list_all_tactics(args)
        if response.get("success") and response.get("tactics_count", 0) >= 12:
            result.pass_test("MCP Server - list_all_tactics")
        else:
            result.fail_test("MCP Server - list_all_tactics", "Insufficient tactics returned")
            
    except Exception as e:
        result.fail_test("MCP Server - Core Functions", str(e))
    
    # 3. Data Validation Tests
    print("\n📋 TESTING DATA VALIDATION")
    print("-" * 40)
    
    try:
        # Test IOC extraction patterns
        test_cases = [
            ("192.168.1.1", "ip"),
            ("malicious.com", "domain"), 
            ("test@evil.com", "email"),
            ("http://evil.com/malware", "url"),
            ("a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456", "hash")
        ]
        
        analyzer = ThreatAnalyzer()
        passed_extractions = 0
        
        for test_value, expected_type in test_cases:
            analysis = analyzer.analyze_threat_report(f"Detected {test_value}", "test")
            extracted = False
            
            for indicator in analysis.indicators:
                if test_value in indicator.value:
                    extracted = True
                    break
                    
            if extracted:
                passed_extractions += 1
                
        if passed_extractions >= len(test_cases) * 0.8:  # 80% success rate
            result.pass_test("Data Validation - IOC Pattern Recognition")
        else:
            result.fail_test("Data Validation - IOC Pattern Recognition", 
                           f"Only {passed_extractions}/{len(test_cases)} patterns detected")
            
    except Exception as e:
        result.fail_test("Data Validation - IOC Patterns", str(e))
    
    # 4. Performance Tests
    print("\n⚡ TESTING PERFORMANCE")
    print("-" * 40)
    
    try:
        # Test analysis speed
        analyzer = ThreatAnalyzer()
        large_threat = "Phishing attack " * 100 + " with PowerShell payload"
        
        start_time = time.time()
        analysis = analyzer.analyze_threat_report(large_threat, "test")
        end_time = time.time()
        
        analysis_time = end_time - start_time
        if analysis_time < 5.0:  # Should complete within 5 seconds
            result.pass_test(f"Performance - Analysis Speed ({analysis_time:.2f}s)")
        else:
            result.fail_test("Performance - Analysis Speed", f"Took {analysis_time:.2f}s (>5s limit)")
            
    except Exception as e:
        result.fail_test("Performance - Analysis Speed", str(e))
    
    # 5. Integration Tests
    print("\n🔗 TESTING INTEGRATIONS")
    print("-" * 40)
    
    try:
        # Test database connectivity
        mitre = MitreAttackFramework()
        tactic = mitre.get_tactic_by_id("TA0001")
        if tactic and tactic.name == "Initial Access":
            result.pass_test("Integration - Database Connectivity")
        else:
            result.fail_test("Integration - Database Connectivity", "Cannot retrieve known tactic")
            
        # Test technique by tactic query
        techniques = mitre.get_techniques_by_tactic("TA0001")
        if len(techniques) > 0:
            result.pass_test("Integration - Technique-Tactic Relationships")
        else:
            result.fail_test("Integration - Technique-Tactic Relationships", "No techniques found for Initial Access")
            
    except Exception as e:
        result.fail_test("Integration - Database Operations", str(e))
    
    # 6. Security Tests
    print("\n🔒 TESTING SECURITY")
    print("-" * 40)
    
    try:
        # Test input sanitization
        analyzer = ThreatAnalyzer()
        malicious_inputs = [
            "'; DROP TABLE tactics; --",
            "<script>alert('xss')</script>",
            "../../etc/passwd",
            "SELECT * FROM techniques"
        ]
        
        security_passed = 0
        for malicious_input in malicious_inputs:
            try:
                analysis = analyzer.analyze_threat_report(malicious_input, "test")
                # Should not crash and should return valid analysis
                if analysis and hasattr(analysis, 'risk_score'):
                    security_passed += 1
            except Exception:
                pass  # Crashes are acceptable for malicious input
                
        if security_passed == len(malicious_inputs):
            result.pass_test("Security - Input Sanitization")
        else:
            result.fail_test("Security - Input Sanitization", 
                           f"Failed {len(malicious_inputs) - security_passed} security tests")
            
    except Exception as e:
        result.fail_test("Security - Input Validation", str(e))
    
    # Test Summary
    print("\n📊 TEST SUMMARY")
    print("=" * 40)
    summary = result.get_summary()
    
    print(f"Total Tests: {summary['total_tests']}")
    print(f"Passed: {summary['passed']}")
    print(f"Failed: {summary['failed']}")
    print(f"Success Rate: {summary['success_rate']}")
    
    if summary['failed'] > 0:
        print("\n❌ FAILED TESTS:")
        for error in summary['errors']:
            print(f"  • {error}")
    
    # Overall verdict
    success_rate = float(summary['success_rate'].rstrip('%'))
    if success_rate >= 95:
        print(f"\n🎉 PRODUCTION READY: {summary['success_rate']} success rate")
        return True
    elif success_rate >= 80:
        print(f"\n⚠️ NEEDS ATTENTION: {summary['success_rate']} success rate")
        return False
    else:
        print(f"\n🚨 NOT READY: {summary['success_rate']} success rate")
        return False

def main():
    """Run all tests"""
    print("Starting comprehensive test suite...")
    ready = asyncio.run(test_framework())
    
    if ready:
        print("\n✅ Framework is ready for production deployment!")
        return 0
    else:
        print("\n❌ Framework needs fixes before production deployment.")
        return 1

if __name__ == "__main__":
    exit(main())
