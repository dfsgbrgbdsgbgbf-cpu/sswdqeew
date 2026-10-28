FROM python:3.11-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data XRAY_BIN=/usr/local/bin/xray

# Xray-core (هسته‌ی واقعی پروتکل‌ها: VLESS/VMess/Trojan/SS × TCP/WS/gRPC/XHTTP × None/TLS/Reality)
ARG XRAY_VERSION=latest
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates \
 && arch="$(uname -m)"; case "$arch" in x86_64) A=64;; aarch64) A=arm64-v8a;; armv7l) A=arm32-v7a;; *) echo "arch $arch unsupported"; exit 1;; esac \
 && if [ "$XRAY_VERSION" = "latest" ]; then U="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-$A.zip"; \
    else U="https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION/Xray-linux-$A.zip"; fi \
 && curl -fsSL "$U" -o /tmp/xray.zip && mkdir -p /usr/local/share/xray \
 && unzip -q /tmp/xray.zip xray geoip.dat geosite.dat -d /tmp/x \
 && mv /tmp/x/xray /usr/local/bin/xray && mv /tmp/x/*.dat /usr/local/share/xray/ \
 && chmod +x /usr/local/bin/xray && /usr/local/bin/xray version | head -1 \
 && rm -rf /tmp/xray.zip /tmp/x /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*' ${UVICORN_SSL_ARGS:-}"]
