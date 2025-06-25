FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Set Python path
ENV PYTHONPATH="/app"

# Run the MCP server
CMD ["python", "mcp_server.py"]
