#!/usr/bin/env python3

import asyncio
import json
import sys
import logging
from typing import Any, Dict, List

from threat_analyzer import ThreatAnalyzer
from mitre_attack import MitreAttackFramework

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp-server")

threat_analyzer = ThreatAnalyzer()
mitre_framework = MitreAttackFramework()


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
                        "content": {"type": "string", "description": "Raw threat intelligence content"},
                        "source": {"type": "string", "description": "Source of the threat intelligence", "default": "Unknown"}
                    },
                    "required": ["content"]
                }
            },
            {
                "name": "search_mitre_techniques",
                "description": "Search MITRE ATT&CK techniques by keywords",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "keywords": {"type": "array", "items": {"type": "string"}, "description": "Keywords to search for"},
                        "min_confidence": {"type": "number", "description": "Minimum confidence score", "default": 0.3}
                    },
                    "required": ["keywords"]
                }
            },
            {
                "name": "get_mitre_tactic_details",
                "description": "Get detailed information about a specific MITRE ATT&CK tactic",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tactic_id": {"type": "string", "description": "MITRE ATT&CK Tactic ID (e.g., TA0001)"}
                    },
                    "required": ["tactic_id"]
                }
            },
            {
                "name": "get_mitre_technique_details",
                "description": "Get detailed information about a specific MITRE ATT&CK technique",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "technique_id": {"type": "string", "description": "MITRE ATT&CK Technique ID (e.g., T1059)"}
                    },
                    "required": ["technique_id"]
                }
            },
            {
                "name": "get_techniques_by_tactic",
                "description": "Get all techniques associated with a specific tactic",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tactic_id": {"type": "string", "description": "MITRE ATT&CK Tactic ID (e.g., TA0001)"}
                    },
                    "required": ["tactic_id"]
                }
            },
            {
                "name": "list_all_tactics",
                "description": "List all MITRE ATT&CK tactics",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False
                }
            }
        ]
    
    async def list_tools(self) -> List[Dict[str, Any]]:
        return self.tools

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        try:
            logger.info(f"Tool called: {name}")

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
                raise ValueError(f"Unknown tool: {name}")

        except Exception as e:
            logger.error(f"Error in tool {name}: {str(e)}")
            return {
                "success": False,
                "error": f"Error executing tool {name}: {str(e)}"
            }

    async def analyze_threat_report(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a threat intelligence report"""
        content = arguments.get("content", "")
        source = arguments.get("source", "Unknown")
        
        if not content.strip():
            return {"success": False, "error": "Empty content provided for analysis"}
        
        # Perform threat analysis
        analysis = threat_analyzer.analyze_threat_report(content, source)
        
        # Format results
        result = {
            "success": True,
            "analysis_id": analysis.id,
            "report": {
                "id": analysis.report.id,
                "title": analysis.report.title,
                "severity": analysis.report.severity.value,
                "source": analysis.report.source,
                "indicators_count": len(analysis.report.indicators),
                "indicators": [
                    {
                        "type": ind.type,
                        "value": ind.value,
                        "severity": ind.severity.value,
                        "confidence": ind.confidence
                    } for ind in analysis.report.indicators
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
        """Search MITRE ATT&CK techniques by keywords"""
        keywords = arguments.get("keywords", [])
        min_confidence = arguments.get("min_confidence", 0.3)
        
        if not keywords:
            return {"success": False, "error": "No keywords provided for search"}
        
        # Search techniques
        technique_matches = mitre_framework.search_techniques_by_keywords(keywords)
        
        # Filter by minimum confidence
        filtered_matches = [(tech, conf) for tech, conf in technique_matches if conf >= min_confidence]
        
        # Format results
        results = []
        for technique, confidence in filtered_matches[:10]:  # Limit to top 10
            results.append({
                "technique_id": technique.id,
                "name": technique.name,
                "description": technique.description[:200] + "..." if len(technique.description) > 200 else technique.description,
                "confidence": confidence,
                "tactics": technique.tactic_ids,
                "platforms": technique.platforms
            })
        
        return {
            "success": True,
            "keywords": keywords,
            "min_confidence": min_confidence,
            "results_count": len(results),
            "results": results
        }

    async def get_mitre_tactic_details(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get details about a specific MITRE ATT&CK tactic"""
        tactic_id = arguments.get("tactic_id", "")
        
        if not tactic_id:
            return {"success": False, "error": "No tactic_id provided"}
        
        tactic = mitre_framework.get_tactic_by_id(tactic_id)
        
        if not tactic:
            return {"success": False, "error": f"Tactic {tactic_id} not found"}
        
        # Get associated techniques
        techniques = mitre_framework.get_techniques_by_tactic(tactic_id)
        
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
                    "description": tech.description[:100] + "..." if len(tech.description) > 100 else tech.description
                } for tech in techniques
            ]
        }
        
        return result

    async def get_mitre_technique_details(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get details about a specific MITRE ATT&CK technique"""
        technique_id = arguments.get("technique_id", "")
        
        if not technique_id:
            return {"success": False, "error": "No technique_id provided"}
        
        technique = mitre_framework.get_technique_by_id(technique_id)
        
        if not technique:
            return {"success": False, "error": f"Technique {technique_id} not found"}
        
        # Get associated tactics
        tactics = []
        for tactic_id in technique.tactic_ids:
            tactic = mitre_framework.get_tactic_by_id(tactic_id)
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
                "mitigations": technique.mitigations,
                "sub_techniques": technique.sub_techniques
            },
            "tactics": tactics
        }
        
        return result

    async def get_techniques_by_tactic(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get all techniques for a specific tactic"""
        tactic_id = arguments.get("tactic_id", "")
        
        if not tactic_id:
            return {"success": False, "error": "No tactic_id provided"}
        
        techniques = mitre_framework.get_techniques_by_tactic(tactic_id)
        
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
        tactics = mitre_framework.get_all_tactics()
        
        result = {
            "success": True,
            "tactics_count": len(tactics),
            "tactics": [
                {
                    "id": tactic.id,
                    "name": tactic.name,
                    "description": tactic.description[:100] + "..." if len(tactic.description) > 100 else tactic.description
                } for tactic in tactics
            ]
        }
        
        return result


# Create server instance
mcp_server = MCPServer()


async def handle_mcp_request(request):
    method = request.get("method")
    params = request.get("params", {})

    if method == "tools/list":
        tools = await mcp_server.list_tools()
        return {"tools": tools}
    elif method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        result = await mcp_server.call_tool(tool_name, arguments)
        return {"content": [{"type": "text", "text": str(result)}]}
    else:
        return {"error": f"Unknown method: {method}"}


def main():
    import json
    import sys

    logger.info("Starting MITRE MCP Server")

    # Simple MCP server implementation
    for line in sys.stdin:
        try:
            request = json.loads(line.strip())
            response = asyncio.run(handle_mcp_request(request))
            print(json.dumps(response))
            sys.stdout.flush()
        except Exception as e:
            error_response = {"error": str(e)}
            print(json.dumps(error_response))
            sys.stdout.flush()


if __name__ == "__main__":
    main()
