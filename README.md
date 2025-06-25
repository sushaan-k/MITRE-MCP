# MITRE-MCP

A threat intelligence framework that maps cyber threats to the MITRE ATT&CK framework.

## Setup

```bash
pip install -r requirements.txt
python src/web_interface.py
```

## Components

- `src/threat_analyzer.py` - Analyzes threats and extracts IOCs
- `src/mitre_attack.py` - MITRE ATT&CK framework integration
- `src/models.py` - Data models
- `src/web_interface.py` - Web API
- `src/mcp_server.py` - MCP server for AI agents

## Usage

The web interface runs on http://localhost:8000 and provides endpoints for threat analysis and MITRE ATT&CK mapping.
