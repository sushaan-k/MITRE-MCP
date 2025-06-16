# Use Python 3.11 slim image for smaller footprint
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create non-root user for security
RUN groupadd -r mcpuser && useradd -r -g mcpuser mcpuser

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY data/ ./data/
COPY templates/ ./templates/
COPY mcp.json setup.py ./
COPY *.py ./

# Create necessary directories and set permissions
RUN mkdir -p /app/logs /app/data && \
    chown -R mcpuser:mcpuser /app

# Switch to non-root user
USER mcpuser

# Initialize database
RUN python -c "from src.mitre_attack import MitreAttackFramework; MitreAttackFramework()"

# Expose ports
EXPOSE 3000 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command
CMD ["python", "src/web_interface.py"]

# Labels for metadata
LABEL maintainer="AI Security Framework Team <security@ai-framework.org>" \
      version="1.0.0" \
      description="MCP Threat Intelligence Framework with MITRE ATT&CK mapping" \
      org.opencontainers.image.title="MCP Threat Intelligence Framework" \
      org.opencontainers.image.description="AI-powered threat intelligence analysis with automated MITRE ATT&CK mapping" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.authors="AI Security Framework Team" \
      org.opencontainers.image.url="https://github.com/ai-security/mcp-threat-intelligence" \
      org.opencontainers.image.source="https://github.com/ai-security/mcp-threat-intelligence" \
      org.opencontainers.image.licenses="MIT"
