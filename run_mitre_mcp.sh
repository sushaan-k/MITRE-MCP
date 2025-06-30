#!/bin/bash

# MITRE MCP Server Launcher
# This script launches the MITRE MCP server for Claude Desktop

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set the Python path to include the project directory
export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"

# Change to the script directory
cd "$SCRIPT_DIR"

# Launch the MCP server
exec python3 mcp_server.py
