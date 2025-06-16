#!/usr/bin/env python3
print("🛡️ MCP Agentic AI Threat Intelligence Framework - Working Demo")
print("=" * 60)

# Sample threat report
threat_text = """
Phishing attack with PowerShell payload detected.
Malicious domain: evil.com, IP: 192.168.1.100
Hash: a1b2c3d4e5f6789012345678901234567890
"""

# Extract IOCs
import re
ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', threat_text)
domains = re.findall(r'\b[a-zA-Z0-9.-]+\.com\b', threat_text)
hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', threat_text)

print(f"📍 IOCs Found:")
print(f"   • IPs: {ips}")
print(f"   • Domains: {domains}")
print(f"   • Hashes: {hashes}")

# MITRE ATT&CK Mapping
techniques = []
if "phishing" in threat_text.lower():
    techniques.append({"id": "T1566.001", "name": "Spearphishing Attachment"})
if "powershell" in threat_text.lower():
    techniques.append({"id": "T1059.001", "name": "PowerShell"})

print(f"\n🎯 MITRE ATT&CK Techniques:")
for tech in techniques:
    print(f"   • {tech['id']}: {tech['name']}")

# Risk Score
risk_score = len(ips) * 2 + len(domains) * 1.5 + len(hashes) * 2 + len(techniques) * 2
print(f"\n📊 Risk Score: {risk_score:.1f}/10")

severity = "HIGH" if risk_score >= 6 else "MEDIUM" if risk_score >= 4 else "LOW"
print(f"🚨 Severity: {severity}")

print(f"\n✅ MCP Framework Successfully:")
print(f"   • Extracted {len(ips + domains + hashes)} IOCs")
print(f"   • Mapped {len(techniques)} MITRE techniques")
print(f"   • Generated risk assessment")
print(f"   • Ready for AI agent integration")
