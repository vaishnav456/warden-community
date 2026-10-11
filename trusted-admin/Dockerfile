# Build from repository root. Install this app separately from public Warden.
FROM python:3.12-slim
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10004 warden-admin \
    && useradd --system --uid 10004 --gid warden-admin --home-dir /app --shell /usr/sbin/nologin warden-admin
WORKDIR /app
COPY trusted-admin/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY trusted-admin/warden_admin ./warden_admin
COPY trusted-admin/wsgi.py trusted-admin/gunicorn.conf.py ./
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10004:10004
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 CMD ["python", "-c", "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('WARDEN_ADMIN_PORT','35750')+'/health',timeout=3).close()"]
CMD ["gunicorn", "-c", "gunicorn.conf.py", "wsgi:app"]
