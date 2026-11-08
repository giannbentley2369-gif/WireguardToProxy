# syntax=docker/dockerfile:1

ARG SING_BOX_VERSION=1.14.4

# -----------------------------------------------------------------------------
# Official sing-box release binary, pinned by version and SHA-256.
# The release build includes with_gvisor (userspace network stack) and with_wireguard.
# -----------------------------------------------------------------------------
FROM debian:trixie-slim AS sing-box
ARG SING_BOX_VERSION
ARG TARGETARCH
ARG SING_BOX_SHA256_AMD64=699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968
ARG SING_BOX_SHA256_ARM64=436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "$arch" in \
        amd64) sha="$SING_BOX_SHA256_AMD64" ;; \
        arm64) sha="$SING_BOX_SHA256_ARM64" ;; \
        *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    name="sing-box-${SING_BOX_VERSION}-linux-${arch}"; \
    curl -fsSL --retry 3 -o /tmp/sing-box.tar.gz \
        "https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/${name}.tar.gz"; \
    echo "${sha}  /tmp/sing-box.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/sing-box.tar.gz -C /tmp; \
    install -m 0755 "/tmp/${name}/sing-box" /usr/local/bin/sing-box; \
    /usr/local/bin/sing-box version

# -----------------------------------------------------------------------------
# Runtime: Python WebUI + supervisor. The sing-box release binary needs glibc.
# -----------------------------------------------------------------------------
FROM python:3.12-slim
ARG SING_BOX_VERSION
LABEL org.opencontainers.image.title="WireGuard to Proxy" \
      org.opencontainers.image.description="WireGuard configs as local SOCKS5/HTTP proxies (userspace sing-box)" \
      org.opencontainers.image.licenses="MIT" \
      io.github.sagernet.sing-box.version="${SING_BOX_VERSION}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/opt/wgproxy \
    WGPROXY_DATA_DIR=/data \
    WGPROXY_SING_BOX=/usr/local/bin/sing-box \
    WGPROXY_WEBUI_PORT=8080

RUN groupadd --system --gid 1000 wgproxy \
    && useradd --system --uid 1000 --gid wgproxy --home-dir /nonexistent --no-create-home \
        --shell /usr/sbin/nologin wgproxy

WORKDIR /opt/wgproxy
COPY requirements.txt ./
RUN pip install --no-compile -r requirements.txt

COPY --from=sing-box /usr/local/bin/sing-box /usr/local/bin/sing-box
COPY wgproxy ./wgproxy
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh \
    && install -d -o wgproxy -g wgproxy -m 0700 /data

VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-m", "wgproxy", "healthcheck"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["python", "-m", "wgproxy", "serve"]
