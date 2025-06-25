#!/usr/bin/env python3

import json
import sys
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("simple-mcp-server")

def handle_request(request):
    """Handle MCP requests"""
    method = request.get("method", "")
    
    if method == "tools/list":
        return {
            "tools": [
                {
                    "name": "analyze_threat_report",
                    "description": "Analyze threat intelligence reports",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "content": {"type": "string", "description": "Threat content to analyze"}
                        },
                        "required": ["content"]
                    }
                },
                {
                    "name": "search_mitre_techniques",
                    "description": "Search MITRE ATT&CK techniques",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "keywords": {"type": "array", "items": {"type": "string"}}
                        },
                        "required": ["keywords"]
                    }
                }
            ]
        }
    elif method == "tools/call":
        tool_name = request.get("params", {}).get("name", "")
        if tool_name == "analyze_threat_report":
            return {"content": [{"type": "text", "text": "Threat analysis completed"}]}
        elif tool_name == "search_mitre_techniques":
            return {"content": [{"type": "text", "text": "MITRE techniques found"}]}
        else:
            return {"error": f"Unknown tool: {tool_name}"}
    else:
        return {"error": f"Unknown method: {method}"}

def main():
    """Main MCP server loop"""
    logger.info("Starting Simple MCP Server")
    
    for line in sys.stdin:
        try:
            request = json.loads(line.strip())
            response = handle_request(request)
            print(json.dumps(response))
            sys.stdout.flush()
        except Exception as e:
            error_response = {"error": str(e)}
            print(json.dumps(error_response))
            sys.stdout.flush()

if __name__ == "__main__":
    main()
