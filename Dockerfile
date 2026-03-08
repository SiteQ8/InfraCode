FROM python:3.12-slim

LABEL maintainer="Ali AlEnezi <Site@hotmail.com>"
LABEL description="InfraCode — Infrastructure as Code Platform"

# Security: run as non-root
RUN groupadd -r infracode && useradd -r -g infracode -d /app -s /sbin/nologin infracode

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create data directories
RUN mkdir -p .infracode/state .infracode/history .infracode/vault && \
    chown -R infracode:infracode /app

USER infracode

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "api.server:app", "--host", "0.0.0.0", "--port", "8000"]
