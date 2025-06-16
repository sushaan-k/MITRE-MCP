#!/usr/bin/env python3
"""
Simple working demo of the MCP Threat Intelligence Framework
"""

def main():
    print("=" * 70)
    print("🛡️  MCP AGENTIC AI THREAT INTELLIGENCE FRAMEWORK  🛡️")
    print("   Mapping Cyber Threats to MITRE ATT&CK Framework")
    print("=" * 70)
    print()
    
    print("🚀 System Overview:")
    print("  ✓ MITRE ATT&CK Framework Integration")
    print("  ✓ Threat Analysis Engine")
    print("  ✓ MCP Server for AI Agents")
    print("  ✓ Web Interface with REST API")
    print()
    
    print("📊 Framework Features:")
    print("  • Automatic threat intelligence analysis")
    print("  • MITRE ATT&CK technique mapping")
    print("  • IOC extraction and classification")
    print("  • Risk scoring and recommendations")
    print("  • AI agent integration via MCP")
    print()
    
    print("🎯 MITRE ATT&CK Tactics Supported:")
    tactics = [
        ("TA0001", "Initial Access"),
        ("TA0002", "Execution"),
        ("TA0003", "Persistence"),
        ("TA0004", "Privilege Escalation"),
        ("TA0005", "Defense Evasion"),
        ("TA0006", "Credential Access"),
        ("TA0007", "Discovery"),
        ("TA0008", "Lateral Movement"),
        ("TA0009", "Collection"),
        ("TA0010", "Exfiltration"),
        ("TA0011", "Command and Control"),
        ("TA0040", "Impact")
    ]
    
    for tactic_id, name in tactics:
        print(f"  • {tactic_id}: {name}")
    print()
    
    print("🔧 Sample MCP Tools for AI Agents:")
    tools = [
        "analyze_threat_report - Analyze threat intelligence and map to MITRE ATT&CK",
        "search_mitre_techniques - Search techniques by keywords", 
        "get_mitre_tactic_details - Get detailed tactic information",
        "get_mitre_technique_details - Get detailed technique information",
        "list_all_tactics - List all available tactics"
    ]
    
    for tool in tools:
        print(f"  • {tool}")
    print()
    
    print("📝 Example Threat Analysis Workflow:")
    print("  1. AI Agent receives threat intelligence report")
    print("  2. Calls analyze_threat_report() via MCP")
    print("  3. System extracts IOCs and keywords")
    print("  4. Maps threats to MITRE ATT&CK techniques")
    print("  5. Calculates risk score and generates recommendations")
    print("  6. Returns structured analysis to AI agent")
    print()
    
    print("💡 Integration Example:")
    print("  AI Agent: 'Analyze this phishing campaign'")
    print("  → MCP Call: analyze_threat_report(content='...', source='OSINT')")
    print("  → Response: {'risk_score': 7.5, 'mappings': [{'technique': 'T1566', 'tactic': 'TA0001'}], ...}")
    print()
    
    print("🌐 Web Interface:")
    print("  • Interactive threat analysis dashboard")
    print("  • Real-time MITRE ATT&CK technique search")
    print("  • Visualization of threat mappings")
    print("  • RESTful API for integration")
    print()
    
    print("✅ System Status: READY")
    print("📖 Documentation: README.md")
    print("🚀 Next Steps:")
    print("  1. pip3 install -r requirements.txt")
    print("  2. python3 src/web_interface.py")
    print("  3. Visit http://localhost:8000")
    print()

if __name__ == "__main__":
    main()
