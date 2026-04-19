FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY vault_cli.py .

RUN mkdir -p /data
ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import httpx; exit(0 if httpx.get('http://localhost:8200/health').status_code == 200 else 1)"

CMD ["python", "-m", "src.main"]
