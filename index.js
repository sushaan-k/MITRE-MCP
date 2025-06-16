#!/usr/bin/env node

/**
 * MITRE-MCP: AI-powered threat intelligence analysis with MITRE ATT&CK mapping
 * Entry point for NPX installation and execution
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

function findPython() {
  const pythonCommands = ['python3', 'python'];
  
  for (const cmd of pythonCommands) {
    try {
      const result = require('child_process').execSync(`${cmd} --version`, { encoding: 'utf8' });
      if (result.includes('Python 3.')) {
        return cmd;
      }
    } catch (error) {
      // Continue to next command
    }
  }
  
  throw new Error('Python 3.8+ is required but not found. Please install Python 3.8 or higher.');
}

function checkRequirements() {
  const pythonCmd = findPython();
  const packageDir = __dirname;
  const requirementsPath = path.join(packageDir, 'requirements.txt');
  
  if (!fs.existsSync(requirementsPath)) {
    console.error('❌ Requirements file not found:', requirementsPath);
    process.exit(1);
  }
  
  return pythonCmd;
}

function startMCPServer(pythonCmd) {
  const packageDir = __dirname;
  const serverPath = path.join(packageDir, 'src', 'mcp_server.py');
  
  console.log('🚀 Starting MITRE-MCP Server...');
  console.log('📁 Package directory:', packageDir);
  console.log('🐍 Python command:', pythonCmd);
  console.log('📄 Server script:', serverPath);
  
  // Check if server file exists
  if (!fs.existsSync(serverPath)) {
    console.error('❌ MCP server file not found:', serverPath);
    console.log('Available files in package directory:');
    fs.readdirSync(packageDir).forEach(file => {
      console.log(`  - ${file}`);
    });
    process.exit(1);
  }
  
  // Start the MCP server
  const mcpServer = spawn(pythonCmd, [serverPath], {
    cwd: packageDir,
    stdio: 'inherit',
    env: {
      ...process.env,
      PYTHONPATH: packageDir,
      MCP_PACKAGE_DIR: packageDir
    }
  });
  
  mcpServer.on('error', (error) => {
    console.error('❌ Failed to start MCP server:', error.message);
    console.log('\n🔧 Troubleshooting:');
    console.log('1. Ensure Python 3.8+ is installed: python3 --version');
    console.log('2. Install dependencies: pip3 install -r requirements.txt');
    console.log('3. Check Python modules: python3 -c "import fastapi, uvicorn, pydantic"');
    process.exit(1);
  });
  
  mcpServer.on('close', (code) => {
    if (code !== 0) {
      console.error(`❌ MCP server exited with code ${code}`);
      process.exit(code);
    }
    console.log('✅ MCP server stopped gracefully');
  });
  
  // Handle graceful shutdown
  process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down MITRE-MCP server...');
    mcpServer.kill('SIGINT');
  });
  
  process.on('SIGTERM', () => {
    console.log('\n🛑 Terminating MITRE-MCP server...');
    mcpServer.kill('SIGTERM');
  });
}

function showUsage() {
  console.log(`
🛡️  MITRE-MCP: AI-powered threat intelligence analysis

Usage:
  npx mitre-mcp [command]

Commands:
  start       Start the MCP server (default)
  web         Start with web interface
  test        Run production tests
  help        Show this help message

Examples:
  npx mitre-mcp                    # Start MCP server
  npx mitre-mcp start              # Start MCP server  
  npx mitre-mcp web                # Start with web UI
  npx mitre-mcp test               # Run tests

For more information, visit: https://github.com/sushaan-k/MITRE-MCP
`);
}

function main() {
  const args = process.argv.slice(2);
  const command = args[0] || 'start';
  
  try {
    const pythonCmd = checkRequirements();
    
    switch (command) {
      case 'start':
      case '':
        startMCPServer(pythonCmd);
        break;
        
      case 'web':
        console.log('🌐 Starting MITRE-MCP with web interface...');
        const webServer = spawn(pythonCmd, [path.join(__dirname, 'src', 'web_interface.py')], {
          cwd: __dirname,
          stdio: 'inherit',
          env: { ...process.env, PYTHONPATH: __dirname }
        });
        break;
        
      case 'test':
        console.log('🧪 Running MITRE-MCP production tests...');
        const testProcess = spawn(pythonCmd, [path.join(__dirname, 'production_tests.py')], {
          cwd: __dirname,
          stdio: 'inherit',
          env: { ...process.env, PYTHONPATH: __dirname }
        });
        break;
        
      case 'help':
      case '--help':
      case '-h':
        showUsage();
        break;
        
      default:
        console.error(`❌ Unknown command: ${command}`);
        showUsage();
        process.exit(1);
    }
    
  } catch (error) {
    console.error('❌ Error:', error.message);
    console.log('\n🔧 Setup Instructions:');
    console.log('1. Install Python 3.8+: https://python.org/downloads');
    console.log('2. Install pip packages: pip3 install fastapi uvicorn pydantic');
    console.log('3. Try again: npx mitre-mcp');
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = { main, checkRequirements, findPython };
