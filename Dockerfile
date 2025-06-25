FROM python:3.9-slim

WORKDIR /app
COPY simple_mcp_server.py .
CMD ["python", "simple_mcp_server.py"]
