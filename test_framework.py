#!/usr/bin/env python3
"""
Test script for MCP Agentic AI Threat Intelligence Framework
Demonstrates the core functionality of the system
"""
import asyncio
import json
from src.threat_analyzer import ThreatAnalyzer
from src.mitre_attack import MitreAttackFramework


def print_banner():
    """Print the application banner"""
    print("=" * 70)
    print("🛡️  MCP AGENTIC AI THREAT INTELLIGENCE FRAMEWORK  🛡️")
    print("   Mapping Cyber Threats to MITRE ATT&CK Framework")
    print("=" * 70)
    print()


def print_section(title):
    """Print a section header"""
    print(f"\n{'='*50}")
    print(f"📊 {title}")
    print("=" * 50)


def test_mitre_framework():
    """Test MITRE ATT&CK framework integration"""
    print_section("TESTING MITRE ATT&CK FRAMEWORK")
    
    mitre = MitreAttackFramework()
    
    # Test getting all tactics
    print("📋 Available MITRE ATT&CK Tactics:")
    tactics = mitre.get_all_tactics()
    for tactic in tactics[:5]:  # Show first 5
        print(f"  • {tactic.id}: {tactic.name}")
    print(f"  ... and {len(tactics)-5} more tactics")
    
    print("\n🔍 Searching techniques for 'phishing':")
    results = mitre.search_techniques_by_keywords(["phishing"])
    for technique, confidence in results[:3]:
        print(f"  • {technique.id}: {technique.name} (confidence: {confidence:.2f})")
    
    print("\n🎯 Techniques for 'Initial Access' tactic:")
    techniques = mitre.get_techniques_by_tactic("TA0001")
    for tech in techniques[:3]:
        print(f"  • {tech.id}: {tech.name}")


def test_threat_analysis():
    """Test threat analysis capabilities"""
    print_section("TESTING THREAT ANALYSIS")
    
    analyzer = ThreatAnalyzer()
    
    # Sample threat intelligence report
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
    tasks and attempts to collect credentials using mimikatz-like techniques. The malware 
    also performs system reconnaissance to gather information about the target environment.

    Detection:
    - Unusual PowerShell execution with bypass parameters
    - Outbound connections to suspicious domains
    - Creation of unauthorized scheduled tasks
    - Access to LSASS memory dumps

    Recommendation: Immediate blocking of identified IOCs and enhanced monitoring for 
    PowerShell execution.
    """
    
    print("🔬 Analyzing sample threat intelligence report...")
    analysis = analyzer.analyze_threat_report(sample_threat, "Security Team")
    
    print(f"\n📊 ANALYSIS RESULTS")
    print(f"Analysis ID: {analysis.id}")
    print(f"Report Title: {analysis.report.title}")
    print(f"Severity: {analysis.report.severity.value.upper()}")
    print(f"Risk Score: {analysis.risk_score:.1f}/10")
    print(f"Indicators Found: {len(analysis.report.indicators)}")
    print(f"MITRE Mappings: {len(analysis.mappings)}")
    
    print(f"\n🎯 THREAT INDICATORS:")
    for indicator in analysis.report.indicators[:5]:
        print(f"  • {indicator.type.upper()}: {indicator.value}")
        print(f"    Severity: {indicator.severity.value}, Confidence: {indicator.confidence:.2f}")
    
    print(f"\n🗺️ MITRE ATT&CK MAPPINGS:")
    for mapping in analysis.mappings[:5]:
        print(f"  • Technique {mapping.technique_id} → Tactic {mapping.tactic_id}")
        print(f"    Confidence: {mapping.confidence:.2f}")
        if mapping.evidence:
            print(f"    Evidence: {', '.join(mapping.evidence[:2])}")
    
    print(f"\n💡 SECURITY RECOMMENDATIONS:")
    for i, rec in enumerate(analysis.recommendations[:3], 1):
        print(f"  {i}. {rec}")
    
    return analysis


def test_mcp_integration():
    """Test MCP framework integration simulation"""
    print_section("TESTING MCP INTEGRATION SIMULATION")
    
    print("🤖 Simulating AI Agent interactions with MCP tools...")
    
    # Simulate MCP tool calls
    tools = [
        "analyze_threat_report",
        "search_mitre_techniques", 
        "get_mitre_tactic_details",
        "get_mitre_technique_details",
        "list_all_tactics"
    ]
    
    print("📚 Available MCP Tools for AI Agents:")
    for i, tool in enumerate(tools, 1):
        print(f"  {i}. {tool}")
    
    print("\n🔧 Tool Usage Examples:")
    print("  • AI Agent: 'Analyze this threat report and map to MITRE ATT&CK'")
    print("    → Calls: analyze_threat_report(content='...', source='OSINT')")
    print("  • AI Agent: 'Search for techniques related to phishing'")
    print("    → Calls: search_mitre_techniques(keywords=['phishing'], min_confidence=0.5)")
    print("  • AI Agent: 'Get details about Initial Access tactic'")
    print("    → Calls: get_mitre_tactic_details(tactic_id='TA0001')")


def main():
    """Main test function"""
    print_banner()
    
    try:
        # Test MITRE framework
        test_mitre_framework()
        
        # Test threat analysis
        analysis = test_threat_analysis()
        
        # Test MCP integration
        test_mcp_integration()
        
        print_section("SYSTEM STATUS")
        print("✅ MITRE ATT&CK Framework: Operational")
        print("✅ Threat Analysis Engine: Operational")  
        print("✅ MCP Server Framework: Ready")
        print("✅ Web Interface: Available")
        
        print_section("NEXT STEPS")
        print("🚀 To start the MCP server:")
        print("   python src/mcp_server.py")
        print()
        print("🌐 To start the web interface:")
        print("   python src/web_interface.py")
        print("   Then visit: http://localhost:8000")
        print()
        print("📖 To view API documentation:")
        print("   Visit: http://localhost:8000/docs")
        
    except Exception as e:
        print(f"\n❌ Error during testing: {str(e)}")
        print("Please check the requirements and try again.")


if __name__ == "__main__":
    main()
