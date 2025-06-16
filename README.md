# MCP Agentic AI Framework for MITRE ATT&CK Mapping

This project implements a Model Context Protocol (MCP) framework for an Agentic AI system that maps cyber threats to the MITRE ATT&CK framework.

## Features

- **Threat Intelligence Analysis**: Parse and analyze cyber threat data
- **MITRE ATT&CK Mapping**: Automatically map threats to tactics, techniques, and procedures
- **MCP Server**: Provides tools for AI agents to interact with the threat intelligence system
- **RESTful API**: Web interface for threat analysis and visualization
- **Extensible Architecture**: Easy to add new threat sources and analysis capabilities

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the MCP server:
```bash
python src/mcp_server.py
```

3. Run the web interface:
```bash
python src/web_interface.py
```

## Architecture

- `src/mcp_server.py`: Main MCP server implementation
- `src/threat_analyzer.py`: Core threat analysis engine
- `src/mitre_attack.py`: MITRE ATT&CK framework integration
- `src/models.py`: Data models and schemas
- `src/web_interface.py`: FastAPI web interface
- `data/`: Threat intelligence data and MITRE ATT&CK database

## Usage

The system provides MCP tools that AI agents can use to:
- Analyze threat intelligence reports
- Map threats to MITRE ATT&CK framework
- Generate threat assessment reports
- Query historical threat data
