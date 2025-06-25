#!/usr/bin/env python3

import sys
import subprocess

def main():
    if len(sys.argv) < 2:
        print("Usage: python run.py [web|mcp|test]")
        print("  web  - Start web interface")
        print("  mcp  - Start MCP server")
        print("  test - Run tests")
        return

    command = sys.argv[1]

    if command == "web":
        subprocess.run([sys.executable, "web_interface.py"])
    elif command == "mcp":
        subprocess.run([sys.executable, "mcp_server.py"])
    elif command == "test":
        subprocess.run([sys.executable, "tests/test_basic.py"])
    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    main()
