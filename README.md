# VodiWalker — نصب روی سرور مجازی

    unzip vpanel.zip -d vpanel && cd vpanel && sudo bash install.sh

بعد از نصب دستور `vpanel` منوی مدیریت (وضعیت / ری‌استارت / لاگ / آپدیت / حذف) را باز می‌کند.

- هسته‌ی پروتکل‌ها Xray-core است: VLESS · VMess · Trojan · Shadowsocks × TCP · WS · gRPC · XHTTP × None · TLS · Reality
- هر اینباند پورت اختصاصی خودش را دارد؛ آن پورت را در فایروال سرور باز کنید.
- TLS: با دامنه (installer گواهی Let's Encrypt می‌گیرد) یا با IP (گواهی self-signed + pin در لینک).
- تست: `XRAY_BIN=/path/xray XRAY_ALLOW_PRIVATE=1 python3 tests/test_integration.py`
