# Build from the repository root: docker build -f key-service/Dockerfile .
FROM python:3.12-slim
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10003 warden-keys \
    && useradd --system --uid 10003 --gid warden-keys --home-dir /app --shell /usr/sbin/nologin warden-keys
WORKDIR /app
COPY key-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY key-service/app.py key-service/config.py key-service/gunicorn.conf.py key-service/healthcheck.py ./
COPY server/services/tenant_crypto.py server/services/platform_secrets.py server/services/key_service_client.py ./services/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10003:10001
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 CMD ["python", "healthcheck.py"]
CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]
