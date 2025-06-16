# 🛡️ MCP Threat Intelligence Framework - Installation Guide

## Quick Start (5 Minutes)

### Option 1: Docker Deployment (Recommended)

```bash
# Clone the repository
git clone https://github.com/ai-security/mcp-threat-intelligence.git
cd mcp-threat-intelligence

# Start with Docker Compose
docker-compose up -d

# Access the services
# - Web Interface: http://localhost:8000
# - MCP Server: localhost:3000
# - Prometheus: http://localhost:9090 (optional)
# - Grafana: http://localhost:3001 (optional, admin/admin)
```

### Option 2: Python Installation

```bash
# Clone repository
git clone https://github.com/ai-security/mcp-threat-intelligence.git
cd mcp-threat-intelligence

# Install dependencies
pip install -r requirements.txt

# Initialize database
python -c "from src.mitre_attack import MitreAttackFramework; MitreAttackFramework()"

# Start the framework
python src/web_interface.py &  # Web UI on port 8000
python src/mcp_server.py       # MCP server on port 3000
```

### Option 3: Smithery MCP Registry

```bash
# Install via Smithery (when published)
smithery install mcp-threat-intelligence-framework

# Or using npm (if packaged)
npm install -g @ai-security/mcp-threat-intelligence
```

## 🔧 System Requirements

- **Python**: 3.8+ (Recommended: 3.11+)
- **Memory**: 512MB minimum, 2GB recommended
- **Storage**: 100MB for framework + database
- **Network**: Internet access for updates (optional)
- **OS**: Linux, macOS, Windows

## 📦 Installation Methods Detailed

### Method 1: Local Development Setup

```bash
# 1. Clone and setup
git clone https://github.com/ai-security/mcp-threat-intelligence.git
cd mcp-threat-intelligence

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install in development mode
pip install -e .

# 5. Initialize MITRE ATT&CK database
python -c "from src.mitre_attack import MitreAttackFramework; MitreAttackFramework()"

# 6. Run tests
python production_tests.py

# 7. Start services
python src/mcp_server.py &     # MCP Server (port 3000)
python src/web_interface.py   # Web Interface (port 8000)
```

### Method 2: Production Deployment

```bash
# 1. Clone repository
git clone https://github.com/ai-security/mcp-threat-intelligence.git
cd mcp-threat-intelligence

# 2. Build Docker image
docker build -t mcp-threat-intelligence:latest .

# 3. Run with production configuration
docker run -d \
  --name mcp-threat-intel \
  -p 3000:3000 \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  -e MCP_THREAT_HOST=0.0.0.0 \
  -e THREAT_LOG_LEVEL=INFO \
  --restart unless-stopped \
  mcp-threat-intelligence:latest

# 4. Verify deployment
curl http://localhost:8000/health
```

### Method 3: Kubernetes Deployment

```bash
# 1. Apply Kubernetes manifests
kubectl apply -f k8s/

# 2. Check deployment status
kubectl get pods -l app=mcp-threat-intelligence

# 3. Get service URL
kubectl get service mcp-threat-intelligence-service
```

## 🚀 Usage Examples

### Example 1: AI Agent Integration

```python
import asyncio
from mcp_client import MCPClient

async def analyze_threat_with_ai():
    # Connect to MCP server
    client = MCPClient("localhost:3000")
    
    # Analyze threat intelligence
    threat_text = """
    Security Alert: Phishing campaign detected targeting finance department.
    Attackers using PowerShell payloads from IP 192.168.100.50.
    Malicious domain: evil-finance.com
    """
    
    # Call MCP tool
    result = await client.call_tool("analyze_threat_report", {
        "content": threat_text,
        "source": "SOC Alert"
    })
    
    print(f"Risk Score: {result['risk_score']}/10")
    print(f"MITRE Techniques: {len(result['mitre_mappings'])}")
    print(f"IOCs Found: {len(result['indicators'])}")
    
    # Search related techniques
    techniques = await client.call_tool("search_mitre_techniques", {
        "keywords": ["phishing", "powershell"],
        "min_confidence": 0.5
    })
    
    print(f"Related Techniques: {len(techniques['results'])}")

# Run the example
asyncio.run(analyze_threat_with_ai())
```

### Example 2: REST API Usage

```python
import requests

# Analyze threat via REST API
response = requests.post("http://localhost:8000/api/analyze", json={
    "content": "Suspicious PowerShell activity detected on endpoint",
    "source": "EDR Alert"
})

analysis = response.json()
print(f"Risk Score: {analysis['risk_score']}")
print(f"Recommendations: {analysis['recommendations']}")

# Search MITRE techniques
response = requests.post("http://localhost:8000/api/search/techniques", json={
    "keywords": ["lateral movement", "credentials"],
    "min_confidence": 0.4
})

techniques = response.json()
print(f"Found {techniques['results_count']} techniques")
```

### Example 3: Command Line Usage

```bash
# Run comprehensive demo
python working_demo.py

# Analyze specific threat
python -c "
from src.threat_analyzer import ThreatAnalyzer
analyzer = ThreatAnalyzer()
result = analyzer.analyze_threat_report('Malware detected: evil.exe', 'AV')
print(f'Risk: {result.risk_score}/10')
"

# Search MITRE techniques
python -c "
from src.mitre_attack import MitreAttackFramework
mitre = MitreAttackFramework()
results = mitre.search_techniques_by_keywords(['phishing'])
print(f'Found {len(results)} phishing techniques')
"
```

## 🔧 Configuration

### Environment Variables

```bash
# Core Configuration
export MCP_THREAT_HOST="0.0.0.0"          # Server host
export MCP_THREAT_PORT="3000"             # MCP server port
export MCP_WEB_PORT="8000"                # Web interface port

# Database Configuration
export MITRE_DB_PATH="data/mitre_attack.db"  # Database location
export DB_BACKUP_ENABLED="true"              # Enable backups

# Logging Configuration
export THREAT_LOG_LEVEL="INFO"            # Log level
export LOG_TO_FILE="true"                 # Enable file logging
export LOG_FILE_PATH="logs/mcp-threat.log"

# Security Configuration
export ENABLE_API_KEY="false"             # API key authentication
export API_KEY="your-secure-key"          # API key (if enabled)
export RATE_LIMIT_ENABLED="true"          # Enable rate limiting
export MAX_REQUESTS_PER_HOUR="1000"       # Rate limit

# Performance Configuration
export MAX_ANALYSIS_TIME="30"             # Max analysis time (seconds)
export CACHE_ENABLED="true"               # Enable result caching
export CACHE_TTL="3600"                   # Cache TTL (seconds)
```

### Configuration File (config.json)

```json
{
  "server": {
    "host": "0.0.0.0",
    "mcp_port": 3000,
    "web_port": 8000,
    "debug": false
  },
  "database": {
    "path": "data/mitre_attack.db",
    "backup_enabled": true,
    "auto_update": true
  },
  "analysis": {
    "max_content_size": "10MB",
    "timeout_seconds": 30,
    "confidence_threshold": 0.3,
    "enable_caching": true
  },
  "security": {
    "api_key_required": false,
    "rate_limiting": {
      "enabled": true,
      "requests_per_hour": 1000,
      "burst_limit": 50
    },
    "cors": {
      "enabled": true,
      "allowed_origins": ["*"]
    }
  },
  "logging": {
    "level": "INFO",
    "file_enabled": true,
    "file_path": "logs/mcp-threat.log",
    "rotation": "daily"
  }
}
```

## 📊 Monitoring & Health Checks

### Health Check Endpoints

```bash
# Overall system health
curl http://localhost:8000/health

# MCP server status
curl http://localhost:8000/health/mcp

# Database connectivity
curl http://localhost:8000/health/database

# Prometheus metrics
curl http://localhost:8000/metrics
```

### Expected Health Response

```json
{
  "status": "healthy",
  "timestamp": "2025-06-16T10:30:00Z",
  "version": "1.0.0",
  "components": {
    "mcp_server": "healthy",
    "database": "healthy",
    "mitre_framework": "healthy"
  },
  "metrics": {
    "uptime_seconds": 3600,
    "total_analyses": 150,
    "average_response_time": 0.8,
    "memory_usage_mb": 256
  }
}
```

## 🧪 Testing & Validation

### Run Test Suite

```bash
# Comprehensive production tests
python production_tests.py

# Individual component tests
python -m pytest tests/ -v

# Performance benchmarks
python tests/benchmark.py

# Security validation
python tests/security_tests.py
```

### Expected Test Results

```
🛡️ MCP THREAT INTELLIGENCE FRAMEWORK - PRODUCTION READINESS TESTS
======================================================================

📊 TESTING CORE COMPONENTS
✅ MITRE Framework - Tactics Loading
✅ MITRE Framework - Techniques Loading  
✅ MITRE Framework - Technique Search
✅ Threat Analyzer - Risk Scoring
✅ Threat Analyzer - IOC Extraction
✅ Threat Analyzer - MITRE Mapping

⚡ TESTING MCP SERVER
✅ MCP Server - analyze_threat_report
✅ MCP Server - search_mitre_techniques
✅ MCP Server - get_tactic_details
✅ MCP Server - list_all_tactics

📋 TESTING DATA VALIDATION
✅ Data Validation - IOC Pattern Recognition

⚡ TESTING PERFORMANCE
✅ Performance - Analysis Speed (0.85s)

🔗 TESTING INTEGRATIONS
✅ Integration - Database Connectivity
✅ Integration - Technique-Tactic Relationships

🔒 TESTING SECURITY
✅ Security - Input Sanitization

📊 TEST SUMMARY
Total Tests: 14
Passed: 14
Failed: 0
Success Rate: 100.0%

🎉 PRODUCTION READY: 100.0% success rate
```

## 🚨 Troubleshooting

### Common Issues

1. **Port Already in Use**
   ```bash
   # Check what's using the ports
   lsof -i :3000
   lsof -i :8000
   
   # Use different ports
   export MCP_THREAT_PORT=3001
   export MCP_WEB_PORT=8001
   ```

2. **Database Permission Errors**
   ```bash
   # Fix database permissions
   chmod 644 data/mitre_attack.db
   
   # Recreate database if corrupted
   rm data/mitre_attack.db
   python -c "from src.mitre_attack import MitreAttackFramework; MitreAttackFramework()"
   ```

3. **Memory Issues**
   ```bash
   # Monitor memory usage
   top -p $(pgrep -f mcp_server)
   
   # Increase memory limits (Docker)
   docker run --memory=2g mcp-threat-intelligence
   ```

4. **Import Errors**
   ```bash
   # Add src to Python path
   export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
   
   # Or install in development mode
   pip install -e .
   ```

### Debug Mode

```bash
# Enable debug logging
export THREAT_LOG_LEVEL=DEBUG

# Run with debug output
python src/mcp_server.py --debug

# Check logs
tail -f logs/mcp-threat.log
```

## 📞 Support & Community

- **Documentation**: https://ai-security.github.io/mcp-threat-intelligence/
- **GitHub Issues**: https://github.com/ai-security/mcp-threat-intelligence/issues
- **Discord Community**: https://discord.gg/ai-security
- **Email Support**: security@ai-framework.org

## 🔄 Updates & Maintenance

### Updating the Framework

```bash
# Pull latest changes
git pull origin main

# Update dependencies
pip install -r requirements.txt --upgrade

# Update MITRE ATT&CK database
python -c "
from src.mitre_attack import MitreAttackFramework
framework = MitreAttackFramework()
framework.update_database()
"

# Restart services
docker-compose restart
```

### Backup & Recovery

```bash
# Backup database
cp data/mitre_attack.db data/mitre_attack.db.backup.$(date +%Y%m%d)

# Backup configuration
tar -czf config_backup_$(date +%Y%m%d).tar.gz *.json *.env

# Restore from backup
cp data/mitre_attack.db.backup.20250616 data/mitre_attack.db
```

## ✅ Installation Checklist

- [ ] System requirements met (Python 3.8+, 512MB RAM)
- [ ] Repository cloned or package installed
- [ ] Dependencies installed successfully
- [ ] Database initialized and populated
- [ ] Configuration files updated
- [ ] Tests passing (100% success rate)
- [ ] Health checks responding
- [ ] Ports accessible (3000, 8000)
- [ ] Documentation reviewed
- [ ] Monitoring configured (optional)

**🎉 Your MCP Threat Intelligence Framework is now ready to use!**

Access the web interface at http://localhost:8000 and start analyzing threats with AI-powered MITRE ATT&CK mapping.
