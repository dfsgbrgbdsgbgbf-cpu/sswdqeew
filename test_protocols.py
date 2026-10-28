# -*- coding: utf-8 -*-
"""
تست واقعی همه‌ی ترکیب‌های پروتکل با Xray-core.

برای هر ترکیب (پروتکل × ترنسپورت × امنیت):
  1) یک اینباند + یک کلاینت با همان ساختار رکوردهای پنل ساخته می‌شود
  2) کانفیگ سرور با xray_engine.build_config ساخته و اجرا می‌شود
  3) «لینک اشتراک» واقعی را با build_manual_uri همین پنل می‌سازیم، از روی همان لینک
     یک کلاینت Xray می‌سازیم و واقعاً از طریق تونل به یک وب‌سرور محلی درخواست می‌زنیم
  4) هم اینباند (والد) و هم کلاینت فرزند تست می‌شوند و در پایان مصرف از Stats API خوانده می‌شود

اجرا:  XRAY_BIN=/path/to/xray python3 tests/test_protocols.py
"""
import asyncio
import base64
import http.server
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
TMP = Path(tempfile.mkdtemp(prefix="xraytest_"))
os.environ.setdefault("DATA_DIR", str(TMP / "data"))
os.environ.setdefault("ADMIN_PASSWORD", "test-pass-12345")

import xray_engine as xe  # noqa: E402
from main import build_manual_uri  # noqa: E402

XRAY = xe.find_xray()
assert XRAY, "xray پیدا نشد (XRAY_BIN را تنظیم کنید)"

BASES = ["vless", "vmess", "trojan", "shadowsocks"]
NETWORKS = ["tcp", "ws", "grpc", "xhttp"]
SECURITIES = ["none", "tls", "reality"]
TARGET_PORT = 18080
REALITY_DEST_PORT = 18443
HOST = "127.0.0.1"


# ───────────── وب‌سرور هدف + سرور TLS1.3 برای dest ریالیتی ─────────────
class _H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"OK-" + b"x" * 20000
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def start_target():
    srv = http.server.ThreadingHTTPServer((HOST, TARGET_PORT), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def start_reality_dest(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    srv = http.server.ThreadingHTTPServer((HOST, REALITY_DEST_PORT), _H)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ───────────── ساخت رکورد مثل پنل ─────────────
def make_record(label, base, network, security, port, parent=None):
    rec = {
        "label": label, "protocol": "manual", "active": True, "used_bytes": 0, "limit_bytes": 0,
        "expires_at": None, "port": port, "parent_inbound_id": parent,
        "base_protocol": base, "network": network, "security": security,
        "address": "", "path": "", "host_header": "", "sni": "", "flow": "",
        "grpc_service_name": "", "grpc_mode": "gun", "xhttp_mode": "auto", "header_type": "",
        "allow_insecure": False, "fingerprint": "chrome", "alpn": "",
        "reality_public_key": "", "reality_short_id": "", "reality_spider_x": "/",
        "reality_private_key": "", "reality_dest": "",
        "ss_method": "chacha20-ietf-poly1305", "ss_password": "",
    }
    return rec


def finish_inbound(uid, rec):
    """همان کاری که ساخت اینباند در پنل باید بکند: مقادیر پیش‌فرض صریح و کلید Reality."""
    net, sec = rec["network"], rec["security"]
    if net in ("ws", "xhttp") and not rec["path"]:
        rec["path"] = f"/{net}-{uid[:8]}"
    if net == "grpc" and not rec["grpc_service_name"]:
        rec["grpc_service_name"] = f"svc{uid[:8]}"
    if sec == "reality":
        priv, pub = xe.reality_keypair()
        rec.update(reality_private_key=priv, reality_public_key=pub,
                   reality_short_id=xe.new_short_id(), reality_dest=f"{HOST}:{REALITY_DEST_PORT}",
                   sni="www.reality-test.example")
    if sec == "tls":
        rec["sni"] = HOST
        rec["allow_insecure"] = True
    if rec["base_protocol"] == "shadowsocks":
        rec["ss_password"] = uid
    if rec["base_protocol"] == "vless" and net == "tcp" and sec in ("tls", "reality"):
        rec["flow"] = xe.XTLS_FLOW
    return rec


# ───────────── از لینک اشتراک → اوتباند کلاینت Xray ─────────────
def _stream(net, sec, p):
    st = {"network": net, "security": sec}
    if sec == "tls":
        t = {"serverName": p.get("sni", ""), "fingerprint": p.get("fp", "chrome")}
        if p.get("pcs"):
            t["pinnedPeerCertSha256"] = p["pcs"]
        if p.get("alpn"):
            t["alpn"] = p["alpn"].split(",")
        st["tlsSettings"] = t
    elif sec == "reality":
        st["realitySettings"] = {
            "serverName": p.get("sni", ""), "fingerprint": p.get("fp", "chrome"),
            "password": p.get("pbk", ""), "shortId": p.get("sid", ""), "spiderX": p.get("spx", "/"),
        }
    if net == "ws":
        st["wsSettings"] = {"path": p.get("path", "/"), "host": p.get("host", "")}
    elif net == "grpc":
        st["grpcSettings"] = {"serviceName": p.get("serviceName", ""), "multiMode": p.get("mode") == "multi"}
    elif net == "xhttp":
        st["xhttpSettings"] = {"path": p.get("path", "/"), "host": p.get("host", ""), "mode": p.get("mode", "auto")}
    else:
        st["tcpSettings"] = {"header": {"type": p.get("headerType") or "none"}}
    return st


def outbound_from_uri(uri, tag):
    scheme = uri.split("://", 1)[0]
    if scheme == "vmess":
        d = json.loads(base64.b64decode(uri[8:] + "=="))
        p = {"sni": d.get("sni"), "fp": d.get("fp"), "path": d.get("path"), "host": d.get("host"),
             "serviceName": d.get("path"), "pcs": CERT_FP if d.get("tls") == "tls" else ""}
        net = d["net"]
        sec = d.get("tls") or "none"
        if net == "xhttp":
            p["mode"] = "auto"
        return {"tag": tag, "protocol": "vmess", "settings": {"vnext": [{
            "address": d["add"], "port": int(d["port"]),
            "users": [{"id": d["id"], "alterId": 0, "security": "auto"}]}]},
            "streamSettings": _stream(net, sec, p)}
    if scheme == "ss":
        u = urlsplit(uri)
        cred = u.netloc.rsplit("@", 1)[0]
        method, pw = base64.urlsafe_b64decode(cred + "=" * (-len(cred) % 4)).decode().split(":", 1)
        return {"tag": tag, "protocol": "shadowsocks", "settings": {"servers": [{
            "address": u.hostname, "port": u.port, "method": method, "password": pw}]},
            "streamSettings": {"network": "tcp"}}
    u = urlsplit(uri)
    p = {k: unquote(v[0]) for k, v in parse_qs(u.query).items()}
    net, sec = p.get("type", "tcp"), p.get("security", "none")
    if scheme == "vless":
        user = {"id": u.username, "encryption": "none"}
        if p.get("flow"):
            user["flow"] = p["flow"]
        return {"tag": tag, "protocol": "vless", "settings": {"vnext": [{
            "address": u.hostname, "port": u.port, "users": [user]}]},
            "streamSettings": _stream(net, sec, p)}
    return {"tag": tag, "protocol": "trojan", "settings": {"servers": [{
        "address": u.hostname, "port": u.port, "password": u.username}]},
        "streamSettings": _stream(net, sec, p)}


CERT_FP = ""


def add_pcs(uri):
    """لینک‌های TLS با گواهی self-signed باید pcs (اثرانگشت گواهی) داشته باشند."""
    if "security=tls" in uri and "pcs=" not in uri:
        return uri.replace("security=tls", "security=tls&pcs=" + CERT_FP, 1)
    return uri


def curl_via(socks_port):
    r = subprocess.run(
        ["curl", "-sS", "-m", "8", "--socks5-hostname", f"127.0.0.1:{socks_port}",
         f"http://{HOST}:{TARGET_PORT}/", "-o", "/dev/null", "-w", "%{http_code}:%{size_download}"],
        capture_output=True, text=True)
    return r.stdout.strip(), r.stderr.strip()


def main():
    cert, key = TMP / "c.pem", TMP / "k.pem"
    global CERT_FP
    CERT_FP = xe.ensure_self_signed(cert, key, HOST)
    start_target()
    start_reality_dest(str(cert), str(key))

    links, cases, port = {}, [], 21000
    for base in BASES:
        for net in NETWORKS:
            for sec in SECURITIES:
                if base == "shadowsocks" and not (net == "tcp" and sec == "none"):
                    continue
                if base == "vmess" and sec == "reality":
                    continue  # لینک vmess:// اصلاً Reality ندارد؛ پنل صریحاً رد می‌کند
                if net == "ws" and sec == "reality":
                    continue  # Xray این ترکیب را ندارد؛ پنل هم صریحاً رد می‌کند
                if os.environ.get("ONLY") and os.environ["ONLY"] not in f"{base}/{net}/{sec}":
                    continue
                port += 1
                pid, cid = str(uuid.uuid4()), str(uuid.uuid4())
                parent = finish_inbound(pid, make_record(f"{base}-{net}-{sec}", base, net, sec, port))
                child = make_record(f"{base}-{net}-{sec}-client", base, net, sec, port, parent=pid)
                for k in ("path", "grpc_service_name", "sni", "allow_insecure", "reality_public_key",
                          "reality_short_id", "flow", "ss_password"):
                    child[k] = parent[k]
                if base == "shadowsocks":
                    child["ss_password"] = cid
                links[pid], links[cid] = parent, child
                cases.append((f"{base}/{net}/{sec}", pid, cid))

    # کانفیگ سرور
    cfg, report = xe.build_config(
        links, is_allowed=lambda l: l.get("active", True), cert_file=str(cert), key_file=str(key),
        panel_ports=(8000,), api_port=10085, block_private=False, allow_private_targets=True, log_file=str(TMP / "server.log"), log_level=os.environ.get("XLOG", "warning"))
    bad = {k: v for k, v in report.items() if not v["ok"]}
    print(f"سرور: {len(cfg['inbounds'])-1} اینباند، خطاهای ساخت کانفیگ: {len(bad)}")
    for k, v in bad.items():
        print("  ✗", links[k]["label"], "→", v["reason"])

    # کانفیگ کلاینت: یک سوکس هر ترکیب
    c_in, c_out, c_rules, plan, sp = [], [], [], [], 30000
    for name, pid, cid in cases:
        for who, uid in (("inbound", pid), ("client", cid)):
            sp += 1
            uri = add_pcs(build_manual_uri(links[uid], uid, HOST))
            tag = f"o{sp}"
            c_in.append({"tag": f"s{sp}", "listen": "127.0.0.1", "port": sp, "protocol": "socks",
                         "settings": {"udp": False, "auth": "noauth"}})
            c_out.append(outbound_from_uri(uri, tag))
            c_rules.append({"type": "field", "inboundTag": [f"s{sp}"], "outboundTag": tag})
            plan.append((name, who, uid, sp, uri))
    (TMP / "client.json").write_text(json.dumps({
        "log": {"loglevel": os.environ.get("XLOG", "warning"), "error": str(TMP / "client.log")},
        "inbounds": c_in, "outbounds": c_out, "routing": {"domainStrategy": "AsIs", "rules": c_rules}}, indent=1))

    async def run():
        eng = xe.XrayEngine(TMP / "engine", api_port=10085, binary=XRAY)
        res = await eng.apply(cfg)
        print("apply:", res)
        if not res.get("ok"):
            print(eng.tail_log(30))
            return 1
        cli = subprocess.Popen([XRAY, "run", "-config", str(TMP / "client.json")],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        time.sleep(2.0)
        if cli.poll() is not None:
            print("کلاینت بالا نیامد:\n", cli.stdout.read().decode()[-2000:])
            return 1
        passed = failed = 0
        rows = []
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda it: curl_via(it[3]), plan))
        for (name, who, uid, sp_, uri), (out, err) in zip(plan, results):
            ok = out.startswith("200:") and int(out.split(":")[1]) > 20000
            rows.append((name, who, ok, out if ok else (out + " " + err[:160])))
            passed += ok
            failed += (not ok)
        stats = await eng.query_stats(reset=True)
        cli.terminate()
        await eng.stop()
        print("\nنتیجه هر ترکیب:")
        last = None
        for name, who, ok, info in rows:
            if name != last:
                print(f"  {name}")
                last = name
            print(f"      {'✓' if ok else '✗'} {who:8s} {info}")
        counted = sum(1 for _, _, uid, _, _ in plan if stats.get(uid, (0, 0))[1] > 0)
        print(f"\nموفق: {passed}  ناموفق: {failed}  | کلاینت‌هایی که مصرفشان در Stats ثبت شد: {counted}/{len(plan)}")
        if failed:
            print("\n--- server.log ---\n", (TMP / "server.log").read_text()[-1500:] if (TMP / "server.log").exists() else "")
            print("\n--- client.log ---\n", (TMP / "client.log").read_text()[-1500:] if (TMP / "client.log").exists() else "")
        return 0 if failed == 0 and counted == len(plan) else 2

    code = asyncio.run(run())
    shutil.rmtree(TMP, ignore_errors=True)
    sys.exit(code)


if __name__ == "__main__":
    main()
