#!/usr/bin/env python3
"""
HTTP MCP Server for Smithery deployment.
Provides HTTP endpoint for Model Context Protocol communication.
"""

import os
import json
import asyncio
from typing import Dict, Any, Optional
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from urllib.parse import parse_qs

from mcp_server import MCPThreatIntelligenceServer

# Initialize MCP server
mcp_server = MCPThreatIntelligenceServer()

# Create FastAPI app for HTTP MCP transport
app = FastAPI(
    title="MCP Threat Intelligence Framework",
    description="AI-powered threat intelligence analysis with MITRE ATT&CK mapping",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def parse_config_from_query(query_string: str) -> Dict[str, Any]:
    """Parse Smithery configuration from query parameters using dot-notation."""
    config = {}
    
    if not query_string:
        return config
    
    # Parse query parameters
    params = parse_qs(query_string)
    
    for key, values in params.items():
        if not values:
            continue
            
        value = values[0]  # Take first value
        
        # Handle dot-notation (e.g., server.host -> {"server": {"host": "..."}})
        if '.' in key:
            parts = key.split('.')
            current = config
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]
            current[parts[-1]] = value
        else:
            config[key] = value
    
    return config

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "mcp-threat-intelligence"}

@app.get("/mcp")
async def handle_mcp_get(request: Request):
    """Handle MCP GET requests for capabilities discovery."""
    try:
        # Parse configuration from query parameters
        config = parse_config_from_query(str(request.url.query))
        
        # Apply configuration to MCP server if needed
        if config:
            await apply_configuration(config)
        
        # Return MCP server capabilities
        tools = await mcp_server.list_tools()
        
        return {
            "jsonrpc": "2.0",
            "result": {
                "capabilities": {
                    "tools": {
                        "listChanged": True
                    }
                },
                "serverInfo": {
                    "name": "mcp-threat-intelligence-framework",
                    "version": "1.0.0"
                },
                "tools": tools
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/mcp")
async def handle_mcp_post(request: Request):
    """Handle MCP POST requests for tool execution."""
    try:
        # Parse configuration from query parameters
        config = parse_config_from_query(str(request.url.query))
        
        # Apply configuration
        if config:
            await apply_configuration(config)
        
        # Get request body
        body = await request.json()
        
        # Handle different MCP request types
        method = body.get("method")
        params = body.get("params", {})
        
        if method == "tools/list":
            tools = await mcp_server.list_tools()
            return {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "result": {"tools": tools}
            }
        
        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            
            # Call the appropriate tool
            result = await mcp_server.call_tool(tool_name, tool_args)
            
            return {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, indent=2)
                        }
                    ]
                }
            }
        
        else:
            raise HTTPException(status_code=400, detail=f"Unknown method: {method}")
    
    except Exception as e:
        return {
            "jsonrpc": "2.0",
            "id": body.get("id") if "body" in locals() else None,
            "error": {
                "code": -32603,
                "message": "Internal error",
                "data": str(e)
            }
        }

@app.delete("/mcp")
async def handle_mcp_delete(request: Request):
    """Handle MCP DELETE requests for cleanup."""
    return {"status": "ok", "message": "Session cleaned up"}

async def apply_configuration(config: Dict[str, Any]):
    """Apply Smithery configuration to the MCP server."""
    # Apply API key if provided
    if "apiKey" in config and config["apiKey"]:
        os.environ["MCP_API_KEY"] = config["apiKey"]
    
    # Apply rate limiting
    if "maxRequestsPerHour" in config:
        os.environ["MAX_REQUESTS_PER_HOUR"] = str(config["maxRequestsPerHour"])
    
    # Apply logging level
    if "logLevel" in config:
        os.environ["THREAT_LOG_LEVEL"] = config["logLevel"]

@app.get("/")
async def root():
    """Root endpoint with service information."""
    return {
        "service": "MCP Threat Intelligence Framework",
        "version": "1.0.0",
        "description": "AI-powered threat intelligence analysis with MITRE ATT&CK mapping",
        "endpoints": {
            "mcp": "/mcp (GET, POST, DELETE)",
            "health": "/health",
            "docs": "/docs"
        },
        "tools": [
            "analyze_threat_report",
            "search_mitre_techniques", 
            "get_tactic_details",
            "extract_iocs",
            "calculate_risk_score",
            "generate_recommendations"
        ]
    }

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info"
    )
