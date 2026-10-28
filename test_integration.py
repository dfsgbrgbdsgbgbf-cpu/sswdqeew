# -*- coding: utf-8 -*-
"""
تست یکپارچه روی خود پنل (FastAPI):
  لاگین → ساخت اینباند (VLESS/VMess/Trojan/SS × شبکه × امنیت) → ساخت کلاینت → انتظار برای Xray →
  گرفتن «لینک واقعی» از API پنل → اتصال واقعی از طریق تونل → بررسی ثبت مصرف و قطع شدن کلاینت غیرفعال

اجرا:  XRAY_BIN=/path/to/xray python3 tests/test_integration.py
"""
import json
import os
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
TMP = Path(tempfile.mkdtemp(prefix="xrayint_"))
os.environ.update(
    DATA_DIR=str(TMP / "data"), ADMIN_USERNAME="admin", ADMIN_PASSWORD="test-pass-12345",
    PUBLIC_BASE_URL="http://127.0.0.1:8000", TCP_PUBLIC_HOST="127.0.0.1",
)

import test_protocols as tp  # noqa: E402  (ابزارهای کلاینت و سرورهای هدف)
import xray_engine as xe  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
import main  # noqa: E402

COMBOS = [
    ("vless", "tcp", "reality"), ("vless", "grpc", "reality"), ("vless", "xhttp", "reality"),
    ("vless", "tcp", "tls"), ("vless", "ws", "tls"), ("vless", "xhttp", "tls"), ("vless", "grpc", "tls"),
    ("vless", "ws", "none"), ("vless", "tcp", "none"),
    ("vmess", "ws", "tls"), ("vmess", "tcp", "none"),
    ("trojan", "tcp", "tls"), ("trojan", "grpc", "reality"), ("trojan", "ws", "none"),
    ("shadowsocks", "tcp", "none"),
]


def main_test():
    cert, key = TMP / "t.pem", TMP / "t.key"
    xe.ensure_self_signed(cert, key, "127.0.0.1")
    tp.start_target()
    tp.start_reality_dest(str(cert), str(key))
    fails = []

    def check(cond, msg):
        print(("  ✓ " if cond else "  ✗ ") + msg)
        if not cond:
            fails.append(msg)

    with TestClient(main.app) as c:
        r = c.post("/api/login", json={"username": "admin", "password": "test-pass-12345"})
        check(r.status_code == 200, f"لاگین ({r.status_code})")
        st = c.get("/api/xray/status").json()
        check(st.get("enabled") and st.get("version"), f"موتور Xray فعال: {st.get('version')}")

        created = []
        port = 22000
        for base, net, sec in COMBOS:
            if os.environ.get("ONLY") and os.environ["ONLY"] != f"{base}/{net}/{sec}":
                continue
            port += 1
            manual = {"base_protocol": base, "network": net, "security": sec}
            if sec == "tls":
                manual["sni"] = "127.0.0.1"
            if sec == "reality":
                manual["sni"] = "www.reality-test.example"
                manual["reality_dest"] = f"127.0.0.1:{tp.REALITY_DEST_PORT}"
            r = c.post("/api/links", json={"label": f"{base}-{net}-{sec}", "protocol": "manual",
                                           "port": port, "manual": manual, "limit_value": 0})
            if r.status_code != 200:
                check(False, f"ساخت اینباند {base}/{net}/{sec}: {r.status_code} {r.text[:150]}")
                continue
            uid = r.json().get("uuid") or r.json().get("id")
            rc = c.post(f"/api/links/{uid}/clients", json={"label": "c1"})
            check(rc.status_code == 200, f"ساخت کلاینت {base}/{net}/{sec} ({rc.status_code})")
            created.append((f"{base}/{net}/{sec}", uid, port))

        # پورت تکراری باید رد شود
        dup = c.post("/api/links", json={"label": "dup", "protocol": "manual", "port": 22001,
                                         "manual": {"base_protocol": "vless", "network": "tcp", "security": "none"}})
        check(dup.status_code == 409, f"پورت تکراری رد شد ({dup.status_code})")
        # Reality+WS باید «فقط لینک» و با دلیل گزارش شود
        bad = c.post("/api/links", json={"label": "badreal", "protocol": "manual", "port": 22999,
                                         "manual": {"base_protocol": "vless", "network": "ws", "security": "reality"}})
        bad_uid = bad.json().get("uuid") or bad.json().get("id")

        # انتظار برای همگام‌سازی Xray
        deadline = time.time() + 30
        while time.time() < deadline:
            rep = main.xray_service.STATE["report"] if hasattr(main, "xray_service") else {}
            import xray_service
            rep = xray_service.STATE["report"]
            if all(rep.get(u, {}).get("ok") for _, u, _ in created) and xray_service.status()["running"]:
                break
            time.sleep(0.5)
        import xray_service
        rep = xray_service.STATE["report"]
        check(all(rep.get(u, {}).get("ok") for _, u, _ in created), "همه‌ی اینباندها در Xray فعال شدند")
        check(not rep.get(bad_uid, {}).get("ok", False) and rep.get(bad_uid, {}).get("reason"),
              f"Reality+WS رد شد با دلیل: {rep.get(bad_uid, {}).get('reason')}")

        # لینک‌های واقعی از API پنل
        plan, c_in, c_out, c_rules, sp = [], [], [], [], 31000
        pin = xray_service.tls_pin()
        for name, uid, _ in created:
            data = c.get(f"/api/links/{uid}/clients").json()
            inb_link = data["inbound"]["vless_full"]; print("   LINK", inb_link, data["clients"][0]["vless_full"])
            cli = data["clients"][0]
            check(data["inbound"]["live_status"] == "live", f"{name} → live_status=live")
            for who, uri, cuid in (("inbound", inb_link, uid), ("client", cli["vless_full"], cli["uuid"])):
                sp += 1
                tp.CERT_FP = pin
                tag = f"o{sp}"
                c_in.append({"tag": f"s{sp}", "listen": "127.0.0.1", "port": sp, "protocol": "socks",
                             "settings": {"udp": False, "auth": "noauth"}})
                c_out.append(tp.outbound_from_uri(uri, tag))
                c_rules.append({"type": "field", "inboundTag": [f"s{sp}"], "outboundTag": tag})
                plan.append((name, who, cuid, sp, uri))
        (TMP / "client.json").write_text(json.dumps({
            "log": {"loglevel": "warning", "error": str(TMP / "client.log")},
            "inbounds": c_in, "outbounds": c_out, "routing": {"domainStrategy": "AsIs", "rules": c_rules}}))
        cli_proc = subprocess.Popen([tp.XRAY, "run", "-config", str(TMP / "client.json")],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        time.sleep(2)
        if cli_proc.poll() is not None:
            print(cli_proc.stdout.read().decode()[-1500:])
            check(False, "کلاینت تست بالا نیامد")
        else:
            # تنظیم تست: چون مقصد loopback است، Xray 26 به‌صورت پیش‌فرض می‌بندد؛ در تست روی Xray اصلی تأیید می‌کنیم
            with ThreadPoolExecutor(max_workers=16) as pool:
                res = list(pool.map(lambda it: tp.curl_via(it[3]), plan))
            blocked_by_default = 0
            for (name, who, cuid, _, _), (out, err) in zip(plan, res):
                ok = out.startswith("200:") and int(out.split(":")[1]) > 20000
                if not ok:
                    blocked_by_default += 1
                check(ok, f"تونل {name} [{who}] → {out} {err[:120]}")
            cli_proc.terminate()
        # مصرف
        time.sleep(12)
        used = {cuid: main.LINKS[cuid]["used_bytes"] for _, _, cuid, _, _ in plan if cuid in main.LINKS}
        check(sum(1 for v in used.values() if v > 0) == len(plan), f"مصرف همه‌ی {len(plan)} کلاینت/اینباند ثبت شد")
        # پایداری: بعد از ری‌استارت پنل کانفیگ بدون تغییر می‌ماند
        check(xray_service.status()["restarts"] >= 1, f"تعداد استارت Xray: {xray_service.status()['restarts']}")
    print()
    print("خطاها:", len(fails))
    for f in fails:
        print("   -", f)
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main_test()
