#!/usr/bin/env python3
"""
Claude Desktop Configuration Helper

This script helps configure Claude Desktop to use the MITRE MCP server.
"""

import json
import os
import sys
from pathlib import Path


def get_claude_config_path():
    """Get the Claude Desktop configuration file path."""
    if sys.platform == "darwin":  # macOS
        return Path.home() / "Library/Application Support/Claude/claude_desktop_config.json"
    elif sys.platform == "win32":  # Windows
        return Path(os.environ["APPDATA"]) / "Claude/claude_desktop_config.json"
    else:
        print("❌ Unsupported operating system")
        sys.exit(1)


def main():
    print("🔧 Claude Desktop Configuration Helper")
    print("=" * 50)
    
    # Get paths
    config_path = get_claude_config_path()
    script_dir = Path(__file__).parent.absolute()
    mcp_server_path = script_dir / "mcp_server.py"
    
    print(f"📁 Claude config: {config_path}")
    print(f"📁 MCP server: {mcp_server_path}")
    
    # Check if MCP server exists
    if not mcp_server_path.exists():
        print("❌ MCP server not found!")
        sys.exit(1)
    
    # Load existing config or create new one
    config = {"mcpServers": {}}
    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            print("✅ Loaded existing Claude config")
        except json.JSONDecodeError:
            print("⚠️  Invalid JSON in Claude config, creating new one")
    else:
        print("📝 Creating new Claude config")
        config_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Add MITRE MCP server
    if "mcpServers" not in config:
        config["mcpServers"] = {}
    
    config["mcpServers"]["mitre-mcp"] = {
        "command": "python3",
        "args": [str(mcp_server_path)],
        "env": {
            "PYTHONPATH": str(script_dir)
        }
    }
    
    # Save config
    try:
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        print("✅ Claude Desktop configuration updated!")
        print("")
        print("🎉 Setup complete!")
        print("📋 Next steps:")
        print("1. Restart Claude Desktop completely (Cmd+Q then reopen)")
        print("2. Test by asking: 'What MITRE ATT&CK tools do you have available?'")
        
    except Exception as e:
        print(f"❌ Failed to save config: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
