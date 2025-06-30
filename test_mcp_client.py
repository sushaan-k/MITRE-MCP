#!/usr/bin/env python3

import json
import subprocess
import sys

def test_mcp_server():
    """Test the MCP server with basic requests using stdin/stdout."""

    # Start the MCP server process
    process = subprocess.Popen(
        [sys.executable, "mcp_server.py"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=0
    )

    try:
        # Test 1: Initialize
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        }

        process.stdin.write(json.dumps(init_request) + "\n")
        process.stdin.flush()
        response = process.stdout.readline()
        print("Initialize response:", json.dumps(json.loads(response), indent=2))

        # Test 2: List tools
        list_tools_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }

        process.stdin.write(json.dumps(list_tools_request) + "\n")
        process.stdin.flush()
        response = process.stdout.readline()
        print("Tools list response:", json.dumps(json.loads(response), indent=2))

        # Test 3: Call a tool
        call_tool_request = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "list_all_tactics",
                "arguments": {}
            }
        }

        process.stdin.write(json.dumps(call_tool_request) + "\n")
        process.stdin.flush()
        response = process.stdout.readline()
        print("Tool call response:", json.dumps(json.loads(response), indent=2))

    except Exception as e:
        print(f"Error: {e}")
        stderr_output = process.stderr.read()
        if stderr_output:
            print(f"Server stderr: {stderr_output}")
    finally:
        process.terminate()
        process.wait()

if __name__ == "__main__":
    test_mcp_server()
