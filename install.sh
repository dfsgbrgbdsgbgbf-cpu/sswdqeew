#!/usr/bin/env bash
# نصب / مدیریت پنل — فقط با یک دستور:   sudo bash install.sh
# بعد از نصب، دستور  vpanel  منوی مدیریت را باز می‌کند (مثل x-ui).
set -euo pipefail
APP_DIR=/opt/vpanel
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; N='\033[0m'
[ "$(id -u)" -eq 0 ] || { echo -e "${R}با root اجرا کنید: sudo bash install.sh${N}"; exit 1; }

rand() { head -c 64 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c "$1"; }
server_ip() { curl -4 -fsS -m 8 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}'; }
dc() { (cd "$APP_DIR" && docker compose "$@"); }

install_docker() {
  command -v docker >/dev/null 2>&1 || { echo "نصب Docker ..."; curl -fsSL https://get.docker.com | sh; }
  systemctl enable --now docker >/dev/null 2>&1 || true
}

open_ports() {
  command -v ufw >/dev/null 2>&1 || return 0
  ufw status | grep -q inactive && return 0
  for p in "$@"; do ufw allow "$p" >/dev/null 2>&1 || true; done
}

do_install() {
  install_docker
  mkdir -p "$APP_DIR/data"
  # کپی سورس (بدون .env/data فعلی)
  tar -C "$SRC_DIR" --exclude=.env --exclude=data --exclude=tests --exclude='__pycache__' -cf - . | tar -C "$APP_DIR" -xf -
  IP="$(server_ip)"
  if [ ! -f "$APP_DIR/.env" ]; then
    read -rp "پورت پنل [تصادفی]: " PORT; PORT=${PORT:-$((RANDOM % 30000 + 20000))}
    read -rp "نام کاربری ادمین [تصادفی]: " U; U=${U:-$(rand 8)}
    read -rsp "رمز ادمین [تصادفی]: " P; echo; P=${P:-$(rand 14)}
    read -rp "دامنه (اختیاری — برای TLS واقعی با Let's Encrypt؛ خالی = فقط IP): " DOMAIN
    read -rp "توکن ربات تلگرام (اختیاری): " TT
    read -rp "آیدی عددی ادمین تلگرام (اختیاری): " TI
    SSL_ARGS=""; CERT=""; KEY=""; HOST="$IP"; SCHEME=http
    if [ -n "$DOMAIN" ]; then
      echo "گرفتن گواهی برای $DOMAIN (پورت 80 باید باز و دامنه به این سرور وصل باشد) ..."
      apt-get install -y -qq certbot >/dev/null 2>&1 || true
      if certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email; then
        CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"; KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
        SSL_ARGS="--ssl-keyfile $KEY --ssl-certfile $CERT"; HOST="$DOMAIN"; SCHEME=https
        (crontab -l 2>/dev/null | grep -v vpanel-renew; echo "0 4 * * 1 certbot renew -q --deploy-hook 'docker restart vpanel' # vpanel-renew") | crontab -
      else
        echo -e "${Y}گرفتن گواهی ناموفق بود؛ با IP ادامه می‌دهم (TLS با گواهی self-signed + pin).${N}"
      fi
    fi
    cat > "$APP_DIR/.env" <<EOT
PORT=$PORT
ADMIN_USERNAME=$U
ADMIN_PASSWORD=$P
SECRET_KEY=$(rand 48)
PUBLIC_BASE_URL=$SCHEME://$HOST:$PORT
TCP_PUBLIC_HOST=$HOST
TCP_LISTEN_PORT=6543
TELEGRAM_BOT_TOKEN=$TT
TELEGRAM_ADMIN_IDS=$TI
XRAY_TLS_CERT=$CERT
XRAY_TLS_KEY=$KEY
UVICORN_SSL_ARGS=$SSL_ARGS
EOT
    chmod 600 "$APP_DIR/.env"
  fi
  open_ports 22/tcp "$(grep ^PORT= "$APP_DIR/.env" | cut -d= -f2)/tcp" 80/tcp 443/tcp
  install -m 755 "$SRC_DIR/install.sh" /usr/local/bin/vpanel
  sed -i "s#^SRC_DIR=.*#SRC_DIR=$APP_DIR#" /usr/local/bin/vpanel
  dc up -d --build
  show_info
}

show_info() {
  . "$APP_DIR/.env"
  echo -e "\n${G}✅ پنل آماده است${N}"
  echo "  آدرس   : $PUBLIC_BASE_URL"
  echo "  کاربر  : $ADMIN_USERNAME"
  echo "  رمز    : $ADMIN_PASSWORD"
  echo "  مدیریت : vpanel   (منو)"
  echo "  توجه   : برای هر اینباند، پورتش را در فایروال سرور/دیتاسنتر باز کنید."
}

menu() {
  while true; do
    echo -e "\n${G}── مدیریت پنل ──${N}\n 1) وضعیت   2) ری‌استارت   3) توقف   4) شروع\n 5) لاگ‌ها  6) آپدیت (از پوشه‌ی جدید)  7) نمایش اطلاعات ورود\n 8) حذف کامل   0) خروج"
    read -rp "انتخاب: " c
    case "$c" in
      1) dc ps ;; 2) dc restart ;; 3) dc stop ;; 4) dc up -d ;;
      5) dc logs --tail 120 -f ;;
      6) read -rp "مسیر پوشه‌ی نسخه‌ی جدید: " NEW; [ -f "$NEW/main.py" ] && { tar -C "$NEW" --exclude=.env --exclude=data --exclude=tests -cf - . | tar -C "$APP_DIR" -xf -; dc up -d --build; } || echo "main.py پیدا نشد" ;;
      7) show_info ;;
      8) read -rp "مطمئنید؟ همه‌ی داده‌ها پاک می‌شود (yes): " a; [ "$a" = yes ] && { dc down -v || true; rm -rf "$APP_DIR" /usr/local/bin/vpanel; echo حذف شد; exit 0; } ;;
      0) exit 0 ;;
    esac
  done
}

if [ "$SRC_DIR" = "$APP_DIR" ]; then menu; else do_install; fi
