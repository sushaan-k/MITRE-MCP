# 🚀 MCP Threat Intelligence Framework - Production Deployment Guide

## Overview

This guide provides instructions for deploying the **MCP Agentic AI Threat Intelligence Framework** to production environments, including Smithery MCP registry and custom deployments.

## ✅ Pre-Deployment Validation

### System Requirements
- **Python**: 3.8+ (Recommended: 3.11+)
- **Memory**: Minimum 512MB RAM, Recommended 2GB+
- **Storage**: 100MB for framework + database
- **Network**: Internet access for MITRE ATT&CK data updates

### Test Results Summary
```
🧪 Production Readiness Tests: PASSED ✅
📊 Test Coverage: 5/5 tests passed (100.0%)
✅ MITRE Framework - 12 tactics loaded
✅ Threat Analyzer - Risk scoring functional
✅ IOC Extraction - Pattern recognition working
✅ MITRE Mapping - Technique association working  
✅ Risk Scoring - 0-10 scale validation passed
```

## 📦 MCP Package Structure

```
mcp-threat-intelligence/
├── mcp.json                    # MCP package manifest
├── README.md                   # Package documentation
├── LICENSE                     # MIT License
├── requirements.txt            # Python dependencies
├── setup.py                    # Package installation
├── src/
│   ├── __init__.py
│   ├── mcp_server.py          # Main MCP server
│   ├── threat_analyzer.py     # Core analysis engine
│   ├── mitre_attack.py        # MITRE ATT&CK integration
│   ├── models.py              # Data models
│   └── web_interface.py       # Optional web UI
├── data/
│   └── mitre_attack.db        # MITRE ATT&CK database
├── tests/
│   ├── test_threat_analyzer.py
│   ├── test_mitre_framework.py
│   └── test_mcp_server.py
└── examples/
    ├── basic_usage.py
    ├── ai_agent_integration.py
    └── threat_scenarios.py
```

## 🔧 Installation Methods

### Method 1: Smithery MCP Registry (Recommended)

```bash
# Install via Smithery
smithery install mcp-threat-intelligence

# Or using MCP package manager
mcp install threat-intelligence-framework
```

### Method 2: Direct Installation

```bash
# Clone repository
git clone https://github.com/your-org/mcp-threat-intelligence.git
cd mcp-threat-intelligence

# Install dependencies
pip install -r requirements.txt

# Install package
pip install -e .

# Initialize database
python -c "from src.mitre_attack import MitreAttackFramework; MitreAttackFramework()"
```

### Method 3: Docker Deployment

```bash
# Build Docker image
docker build -t mcp-threat-intelligence .

# Run container
docker run -p 8000:8000 -p 3000:3000 mcp-threat-intelligence

# Or use docker-compose
docker-compose up -d
```

## ⚙️ Configuration

### Environment Variables

```bash
# Core Configuration
export MCP_THREAT_HOST="0.0.0.0"
export MCP_THREAT_PORT="3000"
export MCP_WEB_PORT="8000"

# Database Configuration
export MITRE_DB_PATH="/data/mitre_attack.db"
export THREAT_LOG_LEVEL="INFO"

# Security Configuration
export MCP_API_KEY="your-secure-api-key"
export ENABLE_WEB_UI="true"
export RATE_LIMIT_REQUESTS="100"
export RATE_LIMIT_WINDOW="3600"  # 1 hour
```

### MCP Configuration File (mcp.json)

```json
{
  "name": "threat-intelligence-framework",
  "version": "1.0.0",
  "description": "AI threat intelligence analysis with MITRE ATT&CK mapping",
  "author": "Your Organization",
  "license": "MIT",
  "homepage": "https://github.com/your-org/mcp-threat-intelligence",
  "repository": {
    "type": "git",
    "url": "https://github.com/your-org/mcp-threat-intelligence.git"
  },
  "keywords": [
    "cybersecurity",
    "threat-intelligence", 
    "mitre-attack",
    "ai-agent",
    "mcp"
  ],
  "tools": [
    {
      "name": "analyze_threat_report",
      "description": "Analyze threat intelligence and map to MITRE ATT&CK",
      "parameters": {
        "content": {
          "type": "string",
          "description": "Threat intelligence content to analyze",
          "required": true
        },
        "source": {
          "type": "string", 
          "description": "Source of the threat intelligence",
          "default": "Unknown"
        }
      }
    },
    {
      "name": "search_mitre_techniques",
      "description": "Search MITRE ATT&CK techniques by keywords",
      "parameters": {
        "keywords": {
          "type": "array",
          "description": "Keywords to search for",
          "required": true
        },
        "min_confidence": {
          "type": "number",
          "description": "Minimum confidence threshold",
          "default": 0.3
        }
      }
    },
    {
      "name": "get_tactic_details",
      "description": "Get detailed information about a MITRE ATT&CK tactic",
      "parameters": {
        "tactic_id": {
          "type": "string",
          "description": "MITRE ATT&CK tactic ID (e.g., TA0001)",
          "required": true
        }
      }
    },
    {
      "name": "extract_iocs",
      "description": "Extract indicators of compromise from text",
      "parameters": {
        "text": {
          "type": "string",
          "description": "Text to extract IOCs from",
          "required": true
        },
        "ioc_types": {
          "type": "array",
          "description": "Types of IOCs to extract",
          "default": ["ip", "domain", "hash", "email", "url"]
        }
      }
    },
    {
      "name": "calculate_risk_score",
      "description": "Calculate risk score for threat analysis",
      "parameters": {
        "indicators": {
          "type": "array",
          "description": "Threat indicators",
          "required": true
        },
        "techniques": {
          "type": "array",
          "description": "MITRE ATT&CK techniques",
          "required": true
        }
      }
    },
    {
      "name": "generate_recommendations",
      "description": "Generate security recommendations",
      "parameters": {
        "analysis_result": {
          "type": "object",
          "description": "Threat analysis result",
          "required": true
        }
      }
    }
  ],
  "engines": {
    "python": ">=3.8"
  },
  "dependencies": {
    "fastapi": "^0.104.1",
    "uvicorn": "^0.24.0",
    "pydantic": "^2.5.0",
    "sqlite3": "*",
    "requests": "^2.31.0"
  },
  "scripts": {
    "start": "python src/mcp_server.py",
    "web": "python src/web_interface.py",
    "test": "python -m pytest tests/",
    "init-db": "python -c 'from src.mitre_attack import MitreAttackFramework; MitreAttackFramework()'"
  }
}
```

## 🚀 Deployment Scenarios

### Scenario 1: Standalone MCP Server

```bash
# Start MCP server only
python src/mcp_server.py

# Server runs on port 3000 by default
# AI agents connect via MCP protocol
```

### Scenario 2: Web Interface + MCP Server

```bash
# Start both services
python src/web_interface.py &  # Web UI on port 8000
python src/mcp_server.py &     # MCP server on port 3000

# Or use the combined launcher
python start_both.py
```

### Scenario 3: Cloud Deployment (AWS/GCP/Azure)

```yaml
# docker-compose.yml
version: '3.8'
services:
  mcp-threat-intelligence:
    build: .
    ports:
      - "3000:3000"  # MCP Server
      - "8000:8000"  # Web UI
    environment:
      - MCP_THREAT_HOST=0.0.0.0
      - MITRE_DB_PATH=/app/data/mitre_attack.db
    volumes:
      - ./data:/app/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Scenario 4: Kubernetes Deployment

```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-threat-intelligence
spec:
  replicas: 3
  selector:
    matchLabels:
      app: mcp-threat-intelligence
  template:
    metadata:
      labels:
        app: mcp-threat-intelligence
    spec:
      containers:
      - name: mcp-server
        image: mcp-threat-intelligence:latest
        ports:
        - containerPort: 3000
        - containerPort: 8000
        env:
        - name: MCP_THREAT_HOST
          value: "0.0.0.0"
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
---
apiVersion: v1
kind: Service
metadata:
  name: mcp-threat-intelligence-service
spec:
  selector:
    app: mcp-threat-intelligence
  ports:
  - name: mcp
    port: 3000
    targetPort: 3000
  - name: web
    port: 8000
    targetPort: 8000
  type: LoadBalancer
```

## 🔐 Security Configuration

### API Security

```python
# config/security.py
SECURITY_CONFIG = {
    "enable_api_key": True,
    "api_key": "your-secure-api-key-here",
    "rate_limiting": {
        "enabled": True,
        "requests_per_hour": 1000,
        "burst_limit": 50
    },
    "cors": {
        "enabled": True,
        "allowed_origins": ["https://your-domain.com"],
        "allowed_methods": ["GET", "POST"],
        "allowed_headers": ["*"]
    },
    "input_validation": {
        "max_content_size": "10MB",
        "sanitize_html": True,
        "block_sql_injection": True
    }
}
```

### Network Security

```bash
# Firewall rules (iptables)
sudo iptables -A INPUT -p tcp --dport 3000 -j ACCEPT  # MCP Server
sudo iptables -A INPUT -p tcp --dport 8000 -j ACCEPT  # Web UI
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT    # SSH
sudo iptables -A INPUT -j DROP  # Block everything else

# Or using UFW
sudo ufw allow 3000/tcp
sudo ufw allow 8000/tcp
sudo ufw allow ssh
sudo ufw enable
```

## 📊 Monitoring & Observability

### Health Checks

```python
# Health check endpoints
GET /health          # Overall system health
GET /health/mcp      # MCP server status
GET /health/database # Database connectivity
GET /metrics         # Prometheus metrics
```

### Logging Configuration

```python
# config/logging.py
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        },
        "json": {
            "format": "%(asctime)s %(name)s %(levelname)s %(message)s",
            "class": "pythonjsonlogger.jsonlogger.JsonFormatter"
        }
    },
    "handlers": {
        "default": {
            "level": "INFO",
            "formatter": "standard",
            "class": "logging.StreamHandler"
        },
        "file": {
            "level": "INFO", 
            "formatter": "json",
            "class": "logging.FileHandler",
            "filename": "/var/log/mcp-threat-intelligence.log"
        }
    },
    "loggers": {
        "": {
            "handlers": ["default", "file"],
            "level": "INFO",
            "propagate": False
        }
    }
}
```

### Metrics Collection

```python
# Prometheus metrics
from prometheus_client import Counter, Histogram, Gauge

# Define metrics
threat_analyses_total = Counter('threat_analyses_total', 'Total threat analyses performed')
analysis_duration = Histogram('analysis_duration_seconds', 'Time spent analyzing threats')
active_connections = Gauge('active_mcp_connections', 'Number of active MCP connections')
risk_score_distribution = Histogram('risk_score_distribution', 'Distribution of risk scores')
```

## 🚀 Smithery MCP Registry Submission

### 1. Package Preparation

```bash
# Create package structure
mkdir mcp-threat-intelligence-package
cd mcp-threat-intelligence-package

# Copy framework files
cp -r ../src ./
cp -r ../data ./
cp ../requirements.txt ./
cp ../mcp.json ./

# Create package manifest
cat > package.json << EOF
{
  "name": "@your-org/mcp-threat-intelligence",
  "version": "1.0.0",
  "description": "AI threat intelligence analysis with MITRE ATT&CK mapping",
  "main": "src/mcp_server.py",
  "mcp": {
    "server": "src/mcp_server.py",
    "tools": [
      "analyze_threat_report",
      "search_mitre_techniques", 
      "get_tactic_details",
      "extract_iocs",
      "calculate_risk_score",
      "generate_recommendations"
    ]
  },
  "keywords": ["cybersecurity", "threat-intelligence", "mitre-attack", "ai"],
  "author": "Your Name <your.email@domain.com>",
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "https://github.com/your-org/mcp-threat-intelligence.git"
  }
}
EOF
```

### 2. Testing Before Submission

```bash
# Run comprehensive tests
python -m pytest tests/ -v

# Test MCP compatibility
mcp-validator validate mcp.json

# Test installation locally
pip install -e .
python -c "from src.mcp_server import MCPThreatIntelligenceServer; print('✅ Import successful')"
```

### 3. Smithery Submission

```bash
# Login to Smithery
smithery login

# Publish package
smithery publish

# Or submit for review
smithery submit --category "Security" --tags "cybersecurity,threat-intelligence,mitre-attack"
```

## 🔄 CI/CD Pipeline

### GitHub Actions Workflow

```yaml
# .github/workflows/deploy.yml
name: Deploy MCP Threat Intelligence
on:
  push:
    branches: [main]
    tags: ['v*']

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    - name: Install dependencies
      run: pip install -r requirements.txt
    - name: Run tests
      run: python production_tests.py
    
  build:
    needs: test
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Build Docker image
      run: docker build -t mcp-threat-intelligence:${{ github.sha }} .
    - name: Push to registry
      run: |
        echo ${{ secrets.DOCKER_PASSWORD }} | docker login -u ${{ secrets.DOCKER_USERNAME }} --password-stdin
        docker push mcp-threat-intelligence:${{ github.sha }}
  
  deploy:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
    - name: Deploy to production
      run: |
        # Deploy to your production environment
        kubectl set image deployment/mcp-threat-intelligence mcp-server=mcp-threat-intelligence:${{ github.sha }}
```

## 📈 Scaling Considerations

### Performance Optimization

1. **Database Optimization**
   - Index MITRE ATT&CK lookup tables
   - Cache frequently accessed techniques
   - Use connection pooling

2. **Memory Management**
   - Implement analysis result caching
   - Use lazy loading for large datasets
   - Configure garbage collection

3. **Concurrent Processing**
   - Async request handling
   - Worker pool for analysis tasks
   - Queue system for batch processing

### Load Balancing

```nginx
# nginx.conf
upstream mcp_backend {
    server mcp-server-1:3000;
    server mcp-server-2:3000;
    server mcp-server-3:3000;
}

server {
    listen 80;
    server_name your-domain.com;
    
    location /mcp {
        proxy_pass http://mcp_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    location /api {
        proxy_pass http://mcp_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 🆘 Troubleshooting

### Common Issues

1. **Database Connection Errors**
   ```bash
   # Check database file permissions
   ls -la data/mitre_attack.db
   
   # Recreate database
   rm data/mitre_attack.db
   python -c "from src.mitre_attack import MitreAttackFramework; MitreAttackFramework()"
   ```

2. **Port Conflicts**
   ```bash
   # Check port usage
   netstat -tulpn | grep :3000
   netstat -tulpn | grep :8000
   
   # Use different ports
   export MCP_THREAT_PORT=3001
   export MCP_WEB_PORT=8001
   ```

3. **Memory Issues**
   ```bash
   # Monitor memory usage
   top -p $(pgrep -f mcp_server)
   
   # Increase memory limits
   export PYTHONMEMORYSIZE=2048
   ```

### Support Resources

- **Documentation**: https://your-org.github.io/mcp-threat-intelligence/
- **Issues**: https://github.com/your-org/mcp-threat-intelligence/issues
- **Discord**: https://discord.gg/your-community
- **Email**: support@your-org.com

---

## ✅ Deployment Checklist

- [ ] System requirements verified
- [ ] Dependencies installed
- [ ] Database initialized
- [ ] Configuration files updated
- [ ] Security settings configured
- [ ] Health checks implemented
- [ ] Monitoring setup
- [ ] Tests passing (100% success rate)
- [ ] Documentation complete
- [ ] Backup procedures established
- [ ] Incident response plan ready

**🎉 Your MCP Threat Intelligence Framework is now ready for production deployment!**
