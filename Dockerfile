# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Robi (@robi44610)
# Szlaban – obraz kontenera. Tylko biblioteka standardowa Pythona, bez pip.
FROM python:3-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8080

WORKDIR /app
COPY server.py scanner.py forensics.py mdlite.py zgody.py binance_relay.py Dockerfile .dockerignore .gitignore /app/
COPY static/ /app/static/
COPY tests/ /app/tests/
COPY cloudflare/ /app/cloudflare/
COPY README.md WHITEPAPER.md LICENSE NOTICE TRADEMARK.md AUTHORS /app/
COPY WHITEPAPER.md LICENSE NOTICE TRADEMARK.md AUTHORS /app/docs/

RUN useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin szlaban
USER 10001

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT','8080'),timeout=4)" || exit 1

CMD ["python3", "/app/server.py"]
