#!/usr/bin/env python3
"""
MITRE MCP Server

A Model Context Protocol (MCP) server that provides comprehensive threat intelligence
analysis and MITRE ATT&CK framework integration for AI applications.

This server enables AI assistants to:
- Analyze threat intelligence reports
- Extract indicators of compromise (IOCs)
- Map threats to MITRE ATT&CK tactics and techniques
- Search and explore the MITRE ATT&CK framework

Author: Development Team
Version: 1.0.0
License: MIT
"""

import asyncio
import json
import sys
import logging
from typing import Any, Dict, List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp-server")

# Initialize components lazily to avoid startup timeouts
threat_analyzer = None
mitre_framework = None

def get_threat_analyzer():
    global threat_analyzer
    if threat_analyzer is None:
        from threat_analyzer import ThreatAnalyzer
        threat_analyzer = ThreatAnalyzer()
    return threat_analyzer

def get_mitre_framework():
    global mitre_framework
    if mitre_framework is None:
        from mitre_attack import MitreAttackFramework
        mitre_framework = MitreAttackFramework()
    return mitre_framework


class MCPServer:
    def __init__(self):
        self.tools = self._get_tools()

    def _get_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "analyze_threat_report",
                "description": "Analyze threat intelligence reports and map to MITRE ATT&CK framework",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "content": {
                            "type": "string",
                            "description": "Raw threat intelligence content"
                        },
                        "source": {
                            "type": "string",
                            "description": "Source of the threat intelligence"
                        }
                    },
                    "required": ["content"],
                    "additionalProperties": False
                }
            },
            {
                "name": "search_mitre_techniques",
                "description": "Search MITRE ATT&CK techniques by keywords",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "keywords": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Keywords to search for"
                        },
                        "min_confidence": {
                            "type": "number",
                            "description": "Minimum confidence score",
                            "minimum": 0,
                            "maximum": 1
                        }
                    },
                    "required": ["keywords"],
                    "additionalProperties": False
                }
            },
            {
                "name": "get_mitre_tactic_details",
                "description": "Get detailed information about a specific MITRE ATT&CK tactic",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tactic_id": {
                            "type": "string",
                            "description": "MITRE ATT&CK Tactic ID (e.g., TA0001)"
                        }
                    },
                    "required": ["tactic_id"],
                    "additionalProperties": False
                }
            },
            {
                "name": "get_mitre_technique_details",
                "description": "Get detailed information about a specific MITRE ATT&CK technique",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "technique_id": {
                            "type": "string",
                            "description": "MITRE ATT&CK Technique ID (e.g., T1059)"
                        }
                    },
                    "required": ["technique_id"],
                    "additionalProperties": False
                }
            },
            {
                "name": "get_techniques_by_tactic",
                "description": "Get all techniques associated with a specific tactic",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tactic_id": {
                            "type": "string",
                            "description": "MITRE ATT&CK Tactic ID (e.g., TA0001)"
                        }
                    },
                    "required": ["tactic_id"],
                    "additionalProperties": False
                }
            },
            {
                "name": "list_all_tactics",
                "description": "List all MITRE ATT&CK tactics",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": [],
                    "additionalProperties": False
                }
            }
        ]

    async def list_tools(self) -> List[Dict[str, Any]]:
        return self.tools

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        try:
            logger.info(f"Tool called: {name} with arguments: {arguments}")

            # Ensure arguments is a dict
            if arguments is None:
                arguments = {}

            if name == "analyze_threat_report":
                return await self.analyze_threat_report(arguments)
            elif name == "search_mitre_techniques":
                return await self.search_mitre_techniques(arguments)
            elif name == "get_mitre_tactic_details":
                return await self.get_mitre_tactic_details(arguments)
            elif name == "get_mitre_technique_details":
                return await self.get_mitre_technique_details(arguments)
            elif name == "get_techniques_by_tactic":
                return await self.get_techniques_by_tactic(arguments)
            elif name == "list_all_tactics":
                return await self.list_all_tactics(arguments)
            else:
                return {
                    "success": False,
                    "error": f"Unknown tool: {name}"
                }

        except Exception as e:
            logger.error(f"Error in tool {name}: {str(e)}")
            return {
                "success": False,
                "error": f"Error executing tool {name}: {str(e)}"
            }

    async def analyze_threat_report(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        content = arguments.get("content", "")
        source = arguments.get("source", "Unknown")

        if not content.strip():
            return {"success": False, "error": "Empty content provided for analysis"}

        analyzer = get_threat_analyzer()
        analysis = analyzer.analyze_threat_report(content, source)

        result = {
            "success": True,
            "analysis_id": analysis.id,
            "report": {
                "id": analysis.report.id,
                "title": analysis.report.title,
                "source": analysis.report.source,
                "severity": analysis.report.severity.value,
                "indicators_count": len(analysis.report.indicators),
                "indicators": [
                    {
                        "type": ind.type,
                        "value": ind.value,
                        "severity": ind.severity.value,
                        "confidence": ind.confidence,
                        "tags": ind.tags
                    } for ind in analysis.report.indicators[:10]
                ]
            },
            "mitre_mappings": [
                {
                    "tactic_id": mapping.tactic_id,
                    "technique_id": mapping.technique_id,
                    "confidence": mapping.confidence,
                    "evidence": mapping.evidence
                } for mapping in analysis.mappings
            ],
            "risk_score": analysis.risk_score,
            "recommendations": analysis.recommendations,
            "analysis_timestamp": analysis.analysis_timestamp.isoformat()
        }

        return result

    async def search_mitre_techniques(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        keywords = arguments.get("keywords", [])
        min_confidence = arguments.get("min_confidence", 0.3)

        if not keywords:
            return {"success": False, "error": "No keywords provided for search"}

        framework = get_mitre_framework()
        technique_matches = framework.search_techniques_by_keywords(keywords)

        filtered_matches = [(tech, conf) for tech, conf in technique_matches if conf >= min_confidence]

        result = {
            "success": True,
            "results_count": len(filtered_matches),
            "results": [
                {
                    "technique_id": tech.id,
                    "name": tech.name,
                    "description": tech.description[:200] + "..." if len(tech.description) > 200 else tech.description,
                    "confidence": conf,
                    "tactic_ids": tech.tactic_ids,
                    "platforms": tech.platforms
                } for tech, conf in filtered_matches[:20]
            ]
        }

        return result

    async def get_mitre_tactic_details(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        tactic_id = arguments.get("tactic_id", "")

        if not tactic_id:
            return {"success": False, "error": "No tactic_id provided"}

        framework = get_mitre_framework()
        tactic = framework.get_tactic_by_id(tactic_id)

        if not tactic:
            return {"success": False, "error": f"Tactic {tactic_id} not found"}

        techniques = framework.get_techniques_by_tactic(tactic_id)

        result = {
            "success": True,
            "tactic": {
                "id": tactic.id,
                "name": tactic.name,
                "description": tactic.description,
                "external_id": tactic.external_id
            },
            "techniques_count": len(techniques),
            "techniques": [
                {
                    "id": tech.id,
                    "name": tech.name,
                    "description": tech.description[:150] + "..." if len(tech.description) > 150 else tech.description
                } for tech in techniques[:10]
            ]
        }

        return result

    async def get_mitre_technique_details(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        technique_id = arguments.get("technique_id", "")

        if not technique_id:
            return {"success": False, "error": "No technique_id provided"}

        framework = get_mitre_framework()
        technique = framework.get_technique_by_id(technique_id)

        if not technique:
            return {"success": False, "error": f"Technique {technique_id} not found"}

        tactics = []
        for tactic_id in technique.tactic_ids:
            tactic = framework.get_tactic_by_id(tactic_id)
            if tactic:
                tactics.append({
                    "id": tactic.id,
                    "name": tactic.name
                })

        result = {
            "success": True,
            "technique": {
                "id": technique.id,
                "name": technique.name,
                "description": technique.description,
                "platforms": technique.platforms,
                "data_sources": technique.data_sources,
                "mitigations": technique.mitigations
            },
            "tactics": tactics
        }

        return result

    async def get_techniques_by_tactic(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        tactic_id = arguments.get("tactic_id", "")

        if not tactic_id:
            return {"success": False, "error": "No tactic_id provided"}

        framework = get_mitre_framework()
        techniques = framework.get_techniques_by_tactic(tactic_id)

        if not techniques:
            return {"success": False, "error": f"No techniques found for tactic {tactic_id}"}

        result = {
            "success": True,
            "tactic_id": tactic_id,
            "techniques_count": len(techniques),
            "techniques": [
                {
                    "id": tech.id,
                    "name": tech.name,
                    "description": tech.description[:150] + "..." if len(tech.description) > 150 else tech.description,
                    "platforms": tech.platforms
                } for tech in techniques
            ]
        }

        return result

    async def list_all_tactics(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List all MITRE ATT&CK tactics."""
        # arguments parameter is required for interface consistency but not used
        framework = get_mitre_framework()
        tactics = framework.get_all_tactics()

        result = {
            "success": True,
            "tactics_count": len(tactics),
            "tactics": [
                {
                    "id": tactic.id,
                    "name": tactic.name,
                    "description": tactic.description,
                    "external_id": tactic.external_id
                } for tactic in tactics
            ]
        }

        return result


# Create server instance
mcp_server = MCPServer()

async def handle_mcp_request(request):
    request_id = request.get("id")
    method = request.get("method")
    params = request.get("params", {})

    try:
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "mitre-mcp",
                        "version": "1.0.0"
                    }
                }
            }
        elif method == "tools/list":
            tools = await mcp_server.list_tools()
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "tools": tools
                }
            }
        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})

            # Validate required parameters
            if not tool_name:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": -32602,
                        "message": "Invalid params: 'name' is required"
                    }
                }

            result = await mcp_server.call_tool(tool_name, arguments)

            # Format result as proper MCP response with correct structure
            if isinstance(result, dict):
                if result.get("success"):
                    content = [{"type": "text", "text": json.dumps(result.get("data", result), indent=2)}]
                else:
                    content = [{"type": "text", "text": result.get("error", "Unknown error")}]
            else:
                content = [{"type": "text", "text": str(result)}]

            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": content,
                    "isError": False
                }
            }
        else:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}"
                }
            }
    except Exception as e:
        logger.error(f"Error handling MCP request: {e}")
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32603,
                "message": f"Internal error: {str(e)}"
            }
        }


def main():
    logger.info("Starting MITRE MCP Server")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
            response = asyncio.run(handle_mcp_request(request))
            print(json.dumps(response))
            sys.stdout.flush()
        except json.JSONDecodeError as e:
            error_response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32700,
                    "message": f"Parse error: {str(e)}"
                }
            }
            print(json.dumps(error_response))
            sys.stdout.flush()
        except Exception as e:
            error_response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32603,
                    "message": f"Internal error: {str(e)}"
                }
            }
            print(json.dumps(error_response))
            sys.stdout.flush()


if __name__ == "__main__":
    main()
