#!/bin/bash

# MITRE MCP Server Installation Script
# This script sets up the MITRE MCP server for use with Claude Desktop

set -e

echo "🚀 Installing MITRE MCP Server..."

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "✅ Found Python $PYTHON_VERSION"

# Install dependencies
echo "📦 Installing dependencies..."
pip3 install -r requirements.txt

# Test the server
echo "🧪 Testing MCP server..."
echo '{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}' | python3 mcp_server.py > /dev/null

if [ $? -eq 0 ]; then
    echo "✅ MCP server test successful!"
else
    echo "❌ MCP server test failed!"
    exit 1
fi

# Get absolute path
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCP_SERVER_PATH="$SCRIPT_DIR/mcp_server.py"

echo ""
echo "🎉 Installation complete!"
echo ""
echo "📋 Next steps:"
echo "1. Add this configuration to your Claude Desktop config:"
echo ""
echo '{'
echo '  "mcpServers": {'
echo '    "mitre-mcp": {'
echo '      "command": "python3",'
echo "      \"args\": [\"$MCP_SERVER_PATH\"],"
echo '      "env": {'
echo "        \"PYTHONPATH\": \"$SCRIPT_DIR\""
echo '      }'
echo '    }'
echo '  }'
echo '}'
echo ""
echo "2. Restart Claude Desktop"
echo "3. Test by asking: 'What MITRE ATT&CK tools do you have available?'"
echo ""
echo "📖 For more information, see README.md"
