# -*- coding: utf-8 -*-
"""
Xray-core engine — موتور واقعی پروتکل‌ها (مثل 3x-ui / Sanaei)

این ماژول از روی اینباندها و کلاینت‌های پنل، یک config.json کامل برای Xray-core
می‌سازد، پروسه‌ی xray را مدیریت می‌کند (استارت / ری‌استارت امن / واچ‌داگ) و
مصرف هر کلاینت را از Stats API می‌خواند.

پروتکل‌ها : VLESS · VMess · Trojan · Shadowsocks
ترنسپورت‌ها: TCP · WebSocket · gRPC · XHTTP
امنیت      : None · TLS · Reality

بخش‌های «خالص» (build_config و ...) هیچ وابستگی‌ای به main.py ندارند تا قابل تست باشند.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import logging
import os
import shutil
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional

log = logging.getLogger("xray_engine")

SS_LEGACY_METHODS = ("chacha20-ietf-poly1305", "aes-128-gcm", "aes-256-gcm")
SS_2022_KEY_BYTES = {"2022-blake3-aes-128-gcm": 16, "2022-blake3-aes-256-gcm": 32}
XTLS_FLOW = "xtls-rprx-vision"


# ───────────────────────────── ابزارهای کمکی ─────────────────────────────

def find_xray() -> Optional[str]:
    for cand in (os.environ.get("XRAY_BIN"), shutil.which("xray"),
                 "/usr/local/bin/xray", "/usr/bin/xray", "/opt/xray/xray"):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64u_decode(text: str) -> bytes:
    text = text.strip()
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def reality_keypair() -> tuple[str, str]:
    """جفت‌کلید X25519 با همان فرمتی که Xray و کلاینت‌ها انتظار دارند (private, public)."""
    from cryptography.hazmat.primitives import serialization as s
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    key = X25519PrivateKey.generate()
    priv = key.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption())
    pub = key.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
    return _b64u(priv), _b64u(pub)


def reality_public_from_private(private_key: str) -> str:
    from cryptography.hazmat.primitives import serialization as s
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    key = X25519PrivateKey.from_private_bytes(_b64u_decode(private_key))
    return _b64u(key.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw))


def new_short_id(nbytes: int = 8) -> str:
    return os.urandom(nbytes).hex()


def ensure_self_signed(cert_path: Path, key_path: Path, host: str) -> str:
    """گواهی self-signed (EC P-256) برای حالت بدون دامنه. اگر معتبر باشد دست نمی‌زند.
    اثرانگشت SHA-256 گواهی را برمی‌گرداند."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    host = (host or "localhost").strip() or "localhost"
    cert_path, key_path = Path(cert_path), Path(key_path)
    if cert_path.exists() and key_path.exists():
        try:
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            names = {str(v.value) for v in sans}
            exp = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
            if host in names and exp > datetime.now(timezone.utc) + timedelta(days=30):
                return cert.fingerprint(hashes.SHA256()).hex()
        except Exception:
            pass

    key = ec.generate_private_key(ec.SECP256R1())
    try:
        san_first: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        san_first = x509.DNSName(host)
    sans_list = [san_first, x509.DNSName("localhost")]
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:60])])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(sans_list), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return cert.fingerprint(hashes.SHA256()).hex()


# ───────────────────────────── ساخت کانفیگ Xray ─────────────────────────────

def _s(v, default: str = "") -> str:
    return str(v if v is not None else default).strip()


def _split_alpn(value: str, network: str) -> list[str]:
    items = [a.strip() for a in _s(value).split(",") if a.strip()]
    if items:
        return items
    return ["h2", "http/1.1"] if network in ("xhttp", "grpc") else ["http/1.1"]


def inbound_tag(uid: str) -> str:
    return f"in-{uid}"


def validate_inbound(link: dict) -> Optional[str]:
    """None یعنی معتبر؛ در غیر این صورت متن خطا (فارسی)."""
    base = _s(link.get("base_protocol"), "vless").lower()
    network = _s(link.get("network"), "tcp").lower()
    security = _s(link.get("security"), "none").lower()
    try:
        port = int(link.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    if not 1 <= port <= 65535:
        return "پورت نامعتبر است"
    if base == "shadowsocks":
        method = _s(link.get("ss_method"), "chacha20-ietf-poly1305")
        if method in SS_2022_KEY_BYTES:
            try:
                if len(base64.b64decode(_s(link.get("ss_password")) + "==")) != SS_2022_KEY_BYTES[method]:
                    return f"برای {method} رمز باید کلید base64 با طول {SS_2022_KEY_BYTES[method]} بایت باشد"
            except Exception:
                return "رمز Shadowsocks 2022 باید base64 معتبر باشد"
        elif method not in SS_LEGACY_METHODS:
            return f"متد Shadowsocks پشتیبانی نمی‌شود: {method}"
        return None
    if security == "reality" and base not in ("vless", "trojan"):
        return "Reality فقط با VLESS یا Trojan کار می‌کند (مثل 3x-ui)"
    if network == "ws" and security == "reality":
        return "Reality با WebSocket سازگار نیست (از TCP / gRPC / XHTTP استفاده کنید)"
    if security == "reality":
        if not _s(link.get("reality_private_key")):
            return "کلید خصوصی Reality ثبت نشده (دکمه‌ی «ساخت کلید» را بزنید)"
        try:
            reality_public_from_private(_s(link.get("reality_private_key")))
        except Exception:
            return "کلید خصوصی Reality نامعتبر است"
        if not (_s(link.get("reality_dest")) or _s(link.get("sni"))):
            return "برای Reality مقصد (Dest) یا SNI لازم است"
    return None


def _stream_settings(link: dict, cert_file: str, key_file: str) -> dict:
    network = _s(link.get("network"), "tcp").lower()
    security = _s(link.get("security"), "none").lower()
    host_header = _s(link.get("host_header"))
    path = _s(link.get("path"))
    ss: dict = {"network": network, "security": security}

    if security == "tls":
        ss["tlsSettings"] = {
            "certificates": [{"certificateFile": cert_file, "keyFile": key_file}],
            "alpn": _split_alpn(link.get("alpn"), network),
        }
    elif security == "reality":
        dest = _s(link.get("reality_dest")) or _s(link.get("sni"))
        if ":" not in dest:
            dest += ":443"
        sni = _s(link.get("sni")) or dest.rsplit(":", 1)[0]
        sid = _s(link.get("reality_short_id"))
        ss["realitySettings"] = {
            "show": False,
            "dest": dest,
            "xver": 0,
            "serverNames": [sni],
            "privateKey": _s(link.get("reality_private_key")),
            "shortIds": [sid] if sid else [""],
        }

    if network == "ws":
        ws = {"path": path or "/"}
        if host_header:
            ws["host"] = host_header
        ss["wsSettings"] = ws
    elif network == "grpc":
        ss["grpcSettings"] = {"serviceName": _s(link.get("grpc_service_name")), "multiMode": _s(link.get("grpc_mode"), "gun") == "multi"}
    elif network == "xhttp":
        xh = {"path": path or "/", "mode": _s(link.get("xhttp_mode"), "auto") or "auto"}
        if host_header:
            xh["host"] = host_header
        ss["xhttpSettings"] = xh
    else:
        ss["tcpSettings"] = {"header": {"type": "none"}}
    return ss


def build_config(
    links: dict,
    *,
    is_allowed: Callable[[dict], bool],
    cert_file: str,
    key_file: str,
    panel_ports: tuple = (),
    api_port: int = 10085,
    block_private: bool = True,
    allow_private_targets: bool = False,
    proxy_lookup: Optional[Callable[[str], Optional[dict]]] = None,
    log_file: Optional[str] = None,
    log_level: str = "warning",
) -> tuple[dict, dict]:
    """(config, report). report[uid] = {ok, reason, inbound, port} برای اینباند و تک‌تک کلاینت‌هایش."""
    report: dict = {}
    inbounds: list = []
    outbounds: list = [
        # Xray 26+ به‌صورت پیش‌فرض مقصدهای private/loopback را در freedom می‌بندد (امن).
        # allow_private_targets فقط برای تست محلی است.
        {"tag": "direct", "protocol": "freedom",
         "settings": {"finalRules": [{"action": "allow"}]} if allow_private_targets else {}},
        {"tag": "blocked", "protocol": "blackhole", "settings": {}},
    ]
    rules: list = [{"type": "field", "inboundTag": ["api"], "outboundTag": "api"}]
    proxy_rules: list = []
    used_ports = set(int(p) for p in panel_ports) | {int(api_port)}

    children: dict[str, list] = {}
    for uid, l in links.items():
        pid = l.get("parent_inbound_id")
        if pid:
            children.setdefault(pid, []).append((uid, l))

    for uid, link in links.items():
        if link.get("parent_inbound_id") or link.get("protocol") != "manual":
            continue
        creds = [(uid, link)] + children.get(uid, [])
        allowed = [(cid, cl) for cid, cl in creds if is_allowed(cl)]

        def mark(ok: bool, reason: str = ""):
            for cid, _ in creds:
                report[cid] = {"ok": ok, "reason": reason, "inbound": uid, "port": link.get("port")}

        err = validate_inbound(link)
        if err:
            mark(False, err)
            continue
        port = int(link["port"])
        if port in used_ports:
            mark(False, f"پورت {port} قبلاً توسط پنل یا اینباند دیگری اشغال شده")
            continue
        if not allowed:
            mark(False, "هیچ کلاینت فعالی در این اینباند نیست")
            continue

        base = _s(link.get("base_protocol"), "vless").lower()
        network = _s(link.get("network"), "tcp").lower()
        security = _s(link.get("security"), "none").lower()
        tag = inbound_tag(uid)
        flow = _s(link.get("flow"))
        use_flow = flow == XTLS_FLOW and base == "vless" and network == "tcp" and security in ("tls", "reality")

        if base == "vless":
            clients = []
            for cid, cl in allowed:
                c = {"id": cid, "email": cid}
                if use_flow:
                    c["flow"] = XTLS_FLOW
                clients.append(c)
            settings = {"clients": clients, "decryption": "none"}
        elif base == "vmess":
            settings = {"clients": [{"id": cid, "email": cid, "alterId": 0} for cid, _ in allowed]}
        elif base == "trojan":
            settings = {"clients": [{"password": cid, "email": cid} for cid, _ in allowed]}
        else:  # shadowsocks
            method = _s(link.get("ss_method"), "chacha20-ietf-poly1305")
            if method in SS_2022_KEY_BYTES:
                settings = {"method": method, "password": _s(link.get("ss_password")),
                            "email": uid, "network": "tcp,udp"}
            else:
                seen, ss_clients = set(), []
                for cid, cl in allowed:
                    pw = _s(cl.get("ss_password")) or cid
                    if pw in seen:
                        continue
                    seen.add(pw)
                    ss_clients.append({"password": pw, "email": cid, "method": method})
                settings = {"clients": ss_clients, "network": "tcp,udp"}

        entry: dict = {
            "tag": tag, "listen": "0.0.0.0", "port": port, "protocol": base,
            "settings": settings,
        }
        if base != "shadowsocks":
            entry["streamSettings"] = _stream_settings(link, cert_file, key_file)
        inbounds.append(entry)
        used_ports.add(port)

        proxy_id = _s(link.get("outbound_proxy_id"))
        if proxy_id and proxy_lookup:
            p = proxy_lookup(proxy_id)
            if p and p.get("host") and p.get("port"):
                server = {"address": p["host"], "port": int(p["port"])}
                if p.get("username"):
                    server["users"] = [{"user": p["username"], "pass": p.get("password", "")}]
                out_tag = f"px-{proxy_id}"
                if not any(o["tag"] == out_tag for o in outbounds):
                    outbounds.append({"tag": out_tag, "protocol": "socks", "settings": {"servers": [server]}})
                proxy_rules.append({"type": "field", "inboundTag": [tag], "outboundTag": out_tag})
        mark(True)
        # کلاینت‌هایی که غیرفعال/منقضی/پرمصرف‌اند: روی همان اینباند هستند ولی وصل نمی‌شوند
        for cid, cl in creds:
            if not is_allowed(cl):
                report[cid] = {"ok": False, "reason": "غیرفعال، منقضی یا حجم تمام شده", "inbound": uid, "port": port}

    if block_private:
        rules.append({"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"})
    rules.extend(proxy_rules)

    inbounds.append({
        "tag": "api", "listen": "127.0.0.1", "port": int(api_port), "protocol": "dokodemo-door",
        "settings": {"address": "127.0.0.1"},
    })
    config = {
        "log": {"loglevel": log_level, "access": "none", **({"error": log_file} if log_file else {})},
        "api": {"tag": "api", "services": ["StatsService"]},
        "stats": {},
        "policy": {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True, "statsUserOnline": True}},
            "system": {"statsInboundUplink": True, "statsInboundDownlink": True},
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }
    return config, report


# ───────────────────────────── مدیریت پروسه ─────────────────────────────

class XrayEngine:
    def __init__(self, workdir: Path, api_port: int = 10085, binary: Optional[str] = None):
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.api_port = api_port
        self.binary = binary or find_xray()
        self.config_path = self.workdir / "config.json"
        self.log_path = self.workdir / "xray.log"
        self.proc: Optional[asyncio.subprocess.Process] = None
        self.config_hash = ""
        self.started_at = 0.0
        self.last_error = ""
        self.restarts = 0
        self.desired_running = False
        self._lock = asyncio.Lock()
        self._watchdog: Optional[asyncio.Task] = None

    # --- وضعیت
    @property
    def available(self) -> bool:
        return bool(self.binary)

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.returncode is None

    def version(self) -> str:
        if not self.binary:
            return ""
        try:
            out = subprocess.run([self.binary, "version"], capture_output=True, text=True, timeout=10).stdout
            return (out.splitlines() or [""])[0].strip()
        except Exception:
            return ""

    def tail_log(self, lines: int = 80) -> str:
        try:
            data = self.log_path.read_text(encoding="utf-8", errors="replace").splitlines()
            return "\n".join(data[-lines:])
        except Exception:
            return ""

    # --- تست و اعمال کانفیگ
    async def _test_config(self, path: Path) -> tuple[bool, str]:
        proc = await asyncio.create_subprocess_exec(
            self.binary, "run", "-test", "-config", str(path),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        except asyncio.TimeoutError:
            proc.kill()
            return False, "timeout در تست کانفیگ"
        text = out.decode("utf-8", errors="replace").strip()
        return proc.returncode == 0, text[-1500:]

    async def apply(self, config: dict) -> dict:
        if not self.binary:
            return {"ok": False, "changed": False, "error": "Xray-core نصب نیست"}
        async with self._lock:
            text = json.dumps(config, indent=2, sort_keys=True, ensure_ascii=False)
            digest = hashlib.sha256(text.encode()).hexdigest()
            if digest == self.config_hash and self.running:
                return {"ok": True, "changed": False}
            candidate = self.workdir / "config.candidate.json"
            candidate.write_text(text, encoding="utf-8")
            ok, out = await self._test_config(candidate)
            if not ok:
                self.last_error = out
                log.error("Xray config test failed: %s", out)
                return {"ok": False, "changed": False, "error": out}
            os.replace(candidate, self.config_path)
            await self._restart_locked()
            self.config_hash = digest
            self.desired_running = True
            self.last_error = "" if self.running else (self.tail_log(15) or "xray بالا نیامد")
            return {"ok": self.running, "changed": True, "error": self.last_error}

    async def _spawn(self):
        if self.log_path.exists() and self.log_path.stat().st_size > 5 * 1024 * 1024:
            self.log_path.replace(self.workdir / "xray.log.1")
        logf = open(self.log_path, "ab")
        self.proc = await asyncio.create_subprocess_exec(
            self.binary, "run", "-config", str(self.config_path),
            stdout=logf, stderr=logf, stdin=asyncio.subprocess.DEVNULL,
        )
        logf.close()
        self.started_at = time.time()
        self.restarts += 1
        await asyncio.sleep(0.8)  # اگر کانفیگ/پورت مشکل دارد همان لحظه می‌میرد

    async def _stop_locked(self):
        if self.proc and self.proc.returncode is None:
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=8)
            except asyncio.TimeoutError:
                self.proc.kill()
                await self.proc.wait()
        self.proc = None

    async def _restart_locked(self):
        await self._stop_locked()
        await self._spawn()

    async def stop(self):
        self.desired_running = False
        if self._watchdog:
            self._watchdog.cancel()
            self._watchdog = None
        async with self._lock:
            await self._stop_locked()

    def start_watchdog(self):
        if self._watchdog is None:
            self._watchdog = asyncio.create_task(self._watch())

    async def _watch(self):
        backoff = 3
        while True:
            try:
                await asyncio.sleep(5)
                if self.desired_running and not self.running and self.config_path.exists():
                    async with self._lock:
                        if self.desired_running and not self.running:
                            log.warning("xray exited — restarting (backoff %ss)", backoff)
                            await self._spawn()
                    backoff = min(backoff * 2, 60) if not self.running else 3
                    await asyncio.sleep(backoff if not self.running else 0)
            except asyncio.CancelledError:
                return
            except Exception as exc:
                log.warning("xray watchdog error: %s", exc)

    # --- آمار مصرف
    async def query_stats(self, reset: bool = True) -> dict[str, tuple[int, int]]:
        """{email: (uplink, downlink)} — مصرف از آخرین reset."""
        if not (self.binary and self.running):
            return {}
        args = [self.binary, "api", "statsquery", f"--server=127.0.0.1:{self.api_port}", "-pattern", "user>>>"]
        if reset:
            args.append("-reset")
        try:
            proc = await asyncio.create_subprocess_exec(
                *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            data = json.loads(out.decode() or "{}")
        except Exception as exc:
            log.debug("statsquery failed: %s", exc)
            return {}
        result: dict[str, list] = {}
        for item in data.get("stat", []) or []:
            parts = str(item.get("name", "")).split(">>>")
            if len(parts) == 4 and parts[0] == "user":
                email, direction = parts[1], parts[3]
                slot = result.setdefault(email, [0, 0])
                slot[0 if direction == "uplink" else 1] += int(item.get("value") or 0)
        return {k: (v[0], v[1]) for k, v in result.items()}
