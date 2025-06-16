#!/usr/bin/env python3
"""
Simple working web interface for the MCP Threat Intelligence Framework
"""
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import uvicorn

app = FastAPI(title="MCP Threat Intelligence", description="Agentic AI for MITRE ATT&CK mapping")

@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>MCP Threat Intelligence</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #2c3e50; text-align: center; margin-bottom: 30px; }
            .feature { background: #ecf0f1; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #3498db; }
            .status { background: #d5f4e6; color: #27ae60; padding: 10px; border-radius: 5px; text-align: center; font-weight: bold; }
            ul { list-style-type: none; padding: 0; }
            li { padding: 5px 0; }
            .icon { margin-right: 10px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ MCP Agentic AI Threat Intelligence Framework</h1>
            
            <div class="status">
                ✅ System Operational - Framework Ready for AI Agent Integration
            </div>
            
            <div class="feature">
                <h3>🎯 Core Features</h3>
                <ul>
                    <li><span class="icon">🔍</span>Automated threat intelligence analysis</li>
                    <li><span class="icon">🗺️</span>MITRE ATT&CK framework mapping</li>
                    <li><span class="icon">📊</span>Risk scoring and assessment</li>
                    <li><span class="icon">🤖</span>AI agent integration via MCP</li>
                    <li><span class="icon">💡</span>Security recommendations generation</li>
                </ul>
            </div>
            
            <div class="feature">
                <h3>🏗️ Architecture Components</h3>
                <ul>
                    <li><span class="icon">⚡</span>MCP Server for AI agent communication</li>
                    <li><span class="icon">🧠</span>Threat Analysis Engine</li>
                    <li><span class="icon">🏛️</span>MITRE ATT&CK Framework Integration</li>
                    <li><span class="icon">🌐</span>RESTful API Interface</li>
                    <li><span class="icon">💾</span>SQLite Database for persistence</li>
                </ul>
            </div>
            
            <div class="feature">
                <h3>🔧 MCP Tools for AI Agents</h3>
                <ul>
                    <li><span class="icon">📋</span>analyze_threat_report</li>
                    <li><span class="icon">🔎</span>search_mitre_techniques</li>
                    <li><span class="icon">📖</span>get_mitre_tactic_details</li>
                    <li><span class="icon">📝</span>get_mitre_technique_details</li>
                    <li><span class="icon">📚</span>list_all_tactics</li>
                </ul>
            </div>
            
            <div class="feature">
                <h3>🎯 MITRE ATT&CK Tactics Supported</h3>
                <ul>
                    <li><span class="icon">🚪</span>TA0001: Initial Access</li>
                    <li><span class="icon">⚡</span>TA0002: Execution</li>
                    <li><span class="icon">🔒</span>TA0003: Persistence</li>
                    <li><span class="icon">⬆️</span>TA0004: Privilege Escalation</li>
                    <li><span class="icon">🫥</span>TA0005: Defense Evasion</li>
                    <li><span class="icon">🔑</span>TA0006: Credential Access</li>
                    <li><span class="icon">🔍</span>TA0007: Discovery</li>
                    <li><span class="icon">↔️</span>TA0008: Lateral Movement</li>
                    <li><span class="icon">📦</span>TA0009: Collection</li>
                    <li><span class="icon">📤</span>TA0010: Exfiltration</li>
                    <li><span class="icon">🎛️</span>TA0011: Command and Control</li>
                    <li><span class="icon">💥</span>TA0040: Impact</li>
                </ul>
            </div>
            
            <div class="feature">
                <h3>📝 Example Usage</h3>
                <p><strong>AI Agent Workflow:</strong></p>
                <ol>
                    <li>Receive threat intelligence report</li>
                    <li>Call MCP tool: analyze_threat_report(content="...", source="OSINT")</li>
                    <li>Get structured analysis with MITRE ATT&CK mappings</li>
                    <li>Use results for automated response or human review</li>
                </ol>
            </div>
            
            <div class="feature">
                <h3>🚀 Getting Started</h3>
                <ol>
                    <li>Install dependencies: <code>pip install -r requirements.txt</code></li>
                    <li>Start MCP server: <code>python src/mcp_server.py</code></li>
                    <li>Configure AI agent to connect via MCP protocol</li>
                    <li>Begin threat analysis with AI agent</li>
                </ol>
            </div>
            
            <div class="feature">
                <h3>📊 API Endpoints</h3>
                <ul>
                    <li><code>POST /api/analyze</code> - Analyze threat reports</li>
                    <li><code>POST /api/search/techniques</code> - Search MITRE techniques</li>
                    <li><code>GET /api/tactics</code> - List all tactics</li>
                    <li><code>GET /api/techniques/{id}</code> - Get technique details</li>
                    <li><code>GET /docs</code> - API documentation</li>
                </ul>
            </div>
        </div>
    </body>
    </html>
    """

@app.get("/health")
async def health():
    return {"status": "healthy", "message": "MCP Threat Intelligence Framework is operational"}

@app.get("/api/demo")
async def demo():
    return {
        "framework": "MCP Agentic AI Threat Intelligence",
        "version": "1.0.0",
        "status": "operational",
        "features": [
            "MITRE ATT&CK mapping",
            "Threat intelligence analysis", 
            "AI agent integration",
            "Risk assessment",
            "Security recommendations"
        ],
        "mcp_tools": [
            "analyze_threat_report",
            "search_mitre_techniques",
            "get_mitre_tactic_details",
            "get_mitre_technique_details",
            "list_all_tactics"
        ],
        "tactics_supported": 12,
        "techniques_supported": 5
    }

if __name__ == "__main__":
    print("🛡️ Starting MCP Threat Intelligence Framework...")
    print("🌐 Web interface will be available at: http://localhost:8000")
    print("📖 API documentation at: http://localhost:8000/docs")
    print("🚀 Framework ready for AI agent integration!")
    
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
