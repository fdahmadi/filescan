FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    wget \
    libfuzzy-dev \
    libmagic1 \
    libjansson-dev \
    libssl-dev \
    libyara-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt requirements-optional.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir flare-capa || true \
    && pip install --no-cache-dir flare-floss || true \
    && pip install --no-cache-dir ssdeep pytlsh || true

# CAPA rules are not bundled in the pip wheel — fetch free mandiant/capa-rules.
RUN set -eux; \
    mkdir -p /opt; \
    if curl -fsSL -o /tmp/capa-rules.tar.gz \
      https://codeload.github.com/mandiant/capa-rules/tar.gz/refs/heads/master; then \
      tar -xzf /tmp/capa-rules.tar.gz -C /opt; \
      mv /opt/capa-rules-* /opt/capa-rules; \
      rm -f /tmp/capa-rules.tar.gz; \
    else \
      mkdir -p /opt/capa-rules; \
      echo "capa-rules download skipped/failed"; \
    fi

# Best-effort LMD install (free). If it fails, lmd engine stays unavailable.
RUN set -eux; \
    mkdir -p /usr/local/src; \
    cd /usr/local/src; \
    if curl -fsSL -o maldetect-current.tar.gz https://www.rfxn.com/downloads/maldetect-current.tar.gz; then \
      tar -xzf maldetect-current.tar.gz; \
      cd maldetect-*; \
      ./install.sh || true; \
    else \
      echo "LMD download skipped/failed"; \
    fi; \
    ln -sf /usr/local/sbin/maldet /usr/local/bin/maldet 2>/dev/null || true; \
    ln -sf /usr/local/maldetect/maldet /usr/local/bin/maldet 2>/dev/null || true

COPY app ./app
COPY rules ./rules
COPY config ./config
COPY scripts ./scripts
COPY testdata ./testdata

ENV FILESCAN_YARA_RULES_DIR=/app/rules/yara \
    FILESCAN_UPLOAD_DIR=/tmp/filescan/uploads \
    FILESCAN_RESULTS_DIR=/tmp/filescan/results \
    FILESCAN_CACHE_PATH=/tmp/filescan/hash_cache.json \
    FILESCAN_ALLOWLIST_PATH=/tmp/filescan/allowlist.json \
    FILESCAN_DENYLIST_PATH=/tmp/filescan/denylist.json \
    FILESCAN_CLAMAV_HOST=127.0.0.1 \
    FILESCAN_CLAMAV_PORT=3310 \
    FILESCAN_CAPA_BIN=capa \
    FILESCAN_CAPA_RULES_DIR=/opt/capa-rules \
    FILESCAN_FLOSS_BIN=floss \
    FILESCAN_LMD_BIN=maldet \
    PATH="/usr/local/sbin:/usr/local/bin:${PATH}"

EXPOSE 8001

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
