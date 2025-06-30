FROM python:3.12-slim-bookworm

RUN apt-get update && \
    apt-get install -y curl --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/vAPI/app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

RUN adduser --system --group appuser

RUN chown -R appuser:appuser /opt/vAPI/app

USER appuser

EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 CMD curl -f http://localhost:8081/ || exit 1

CMD ["python", "vAPI.py"]
