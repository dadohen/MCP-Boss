FROM python:3.11-slim

# Security: run as non-root user
RUN groupadd -r mcpuser && useradd -r -g mcpuser mcpuser

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .
COPY static/ static/

# Switch to non-root user
USER mcpuser

EXPOSE 8080
CMD ["python", "main.py"]
