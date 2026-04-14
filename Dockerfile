FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY vault_cli.py .

RUN mkdir -p /data

ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "src.main"]
