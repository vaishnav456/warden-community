# Compile Tailwind ahead of time — the templates were briefly wired to the
# cdn.tailwindcss.com runtime script instead, which cdn.tailwindcss.com's own
# console warning says not to use in production, and whose JS-injected
# <style> tag has no way to satisfy this app's CSP (no 'unsafe-inline' on
# style-src). A real compiled stylesheet needs neither.
FROM node:20-alpine AS tailwind-build
WORKDIR /build
RUN npm install -g tailwindcss@3.4.17
COPY tailwind.config.js ./
COPY templates ./templates
COPY static/css/tailwind-src.css ./static/css/tailwind-src.css
RUN tailwindcss -i ./static/css/tailwind-src.css -o ./static/css/tailwind.css --minify

FROM python:3.12-slim

# System deps for bcrypt (libffi) and python-magic
# Refresh inherited base packages, not just newly installed dependencies.
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
    libffi-dev libmagic1 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 warden \
    && useradd --system --uid 10001 --gid warden --home-dir /app --shell /usr/sbin/nologin warden

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=warden:warden . .
COPY --from=tailwind-build /build/static/css/tailwind.css ./static/css/tailwind.css

# CSP-safe Alpine and Fontsource fonts are committed under static/. Runtime
# assets are therefore reproducible, auditable, and never fetched from a CDN.

# Create directories the app expects
RUN mkdir -p /app/../uploads/apps /app/../agent-dist /var/lib/warden/device-ca \
    && chown -R warden:warden /app /app/../uploads /app/../agent-dist /var/lib/warden

ENV PYTHONDONTWRITEBYTECODE=1

USER 10001:10001

EXPOSE 35020

CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]
