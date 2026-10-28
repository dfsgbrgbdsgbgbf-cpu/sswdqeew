# -*- coding: utf-8 -*-
"""
اتصال پنل (main.py) به موتور Xray-core.

  • هر تغییر در اینباند/کلاینت (save_state) → request_sync() → کانفیگ دوباره ساخته می‌شود
    و فقط اگر واقعاً تغییر کرده باشد Xray ری‌استارت می‌شود
  • هر ۱۰ ثانیه مصرف هر کلاینت از Stats API خوانده و به used_bytes اضافه می‌شود؛
    کلاینتی که حجمش تمام یا منقضی شود خودکار از Xray حذف می‌شود
  • اگر Xray نصب نباشد، پنل مثل قبل کار می‌کند (فقط لینک‌ساز) و دلیلش در status() است
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

import xray_engine as xe

log = logging.getLogger("xray_service")

STATE: dict = {
    "enabled": False, "available": False, "running": False, "version": "",
    "error": "", "report": {}, "tls_mode": "", "tls_pin": "",
    "last_sync": 0.0, "last_apply_error": "", "inbounds": 0,
}
_engine: Optional[xe.XrayEngine] = None
_event: Optional[asyncio.Event] = None
_tasks: list = []
_dirty_since_save = 0.0


def _m():
    import main  # noqa: WPS433 — import تنبل برای جلوگیری از چرخه
    return main


# ───────────────────────────── API عمومی ─────────────────────────────

def enabled() -> bool:
    return bool(STATE["enabled"])


def request_sync():
    if _event is not None:
        try:
            _event.set()
        except Exception:
            pass


def link_report(uid: str) -> Optional[dict]:
    """None = موتور فعال نیست؛ وگرنه {ok, reason, ...}"""
    if not STATE["enabled"]:
        return None
    return STATE["report"].get(uid) or {"ok": False, "reason": "هنوز اعمال نشده (چند ثانیه صبر کنید)"}


def tls_pin() -> str:
    """اثرانگشت SHA-256 گواهی self-signed (برای pcs در لینک)؛ با گواهی واقعی خالی است."""
    return STATE.get("tls_pin") or ""


def status() -> dict:
    eng = _engine
    return {
        "enabled": STATE["enabled"], "available": STATE["available"],
        "running": bool(eng and eng.running), "version": STATE["version"],
        "error": STATE["error"] or STATE["last_apply_error"],
        "tls_mode": STATE["tls_mode"], "inbounds": STATE["inbounds"],
        "restarts": eng.restarts if eng else 0,
        "uptime": int(time.time() - eng.started_at) if (eng and eng.running) else 0,
        "last_sync": STATE["last_sync"],
    }


def tail_log(lines: int = 100) -> str:
    return _engine.tail_log(lines) if _engine else ""


async def restart_now() -> dict:
    if not _engine:
        return {"ok": False, "error": "Xray-core فعال نیست"}
    _engine.config_hash = ""  # اجبار به ری‌استارت
    res = await _sync_once()
    return res


# ───────────────────────────── مسیر گواهی TLS ─────────────────────────────

def _public_host() -> str:
    m = _m()
    for cand in (m.CONFIG.get("tcp_public_host"),):
        if cand:
            return str(cand).strip()
    try:
        _, host = m._split_base_url(m.CONFIG.get("public_base_url"))
        if host:
            return host
    except Exception:
        pass
    return "localhost"


def _cert_paths() -> tuple[str, str, str]:
    """(cert, key, mode) — mode: custom | self-signed"""
    m = _m()
    cert = str(m.CONFIG.get("tls_cert_file") or os.environ.get("XRAY_TLS_CERT") or "").strip()
    key = str(m.CONFIG.get("tls_key_file") or os.environ.get("XRAY_TLS_KEY") or "").strip()
    if cert and key and Path(cert).is_file() and Path(key).is_file():
        return cert, key, "custom"
    d = Path(m.DATA_DIR) / "xray"
    return str(d / "cert.pem"), str(d / "key.pem"), "self-signed"


def _panel_ports() -> tuple:
    m = _m()
    ports = []
    try:
        ports.append(int(m.PORT))
    except Exception:
        ports.append(8000)
    try:
        ports.append(int(m._tcp_listen_port_snapshot()))
    except Exception:
        pass
    return tuple(p for p in ports if p)


def _allow_private() -> bool:
    """فقط برای تست محلی؛ در حالت عادی دسترسی کاربران به شبکه‌ی داخلی سرور (و خود پنل) بسته است."""
    return os.environ.get("XRAY_ALLOW_PRIVATE", "").strip() == "1"


# ───────────────────────────── همگام‌سازی ─────────────────────────────

async def _sync_once() -> dict:
    m = _m()
    eng = _engine
    if not eng:
        return {"ok": False, "error": "Xray-core فعال نیست"}
    cert, key, mode = _cert_paths()
    pin = ""
    if mode == "self-signed":
        try:
            pin = await asyncio.to_thread(xe.ensure_self_signed, Path(cert), Path(key), _public_host())
        except Exception as exc:
            log.error("self-signed cert failed: %s", exc)
    STATE["tls_mode"], STATE["tls_pin"] = mode, pin

    async with m.LINKS_LOCK:
        snapshot = {uid: dict(l) for uid, l in m.LINKS.items() if l.get("protocol") == "manual"}

    try:
        import outbound_proxy
        proxy_lookup = outbound_proxy.get_proxy
    except Exception:
        proxy_lookup = None

    cfg, report = xe.build_config(
        snapshot, is_allowed=m.is_link_allowed, cert_file=cert, key_file=key,
        panel_ports=_panel_ports(), api_port=eng.api_port,
        block_private=not _allow_private(), allow_private_targets=_allow_private(),
        proxy_lookup=proxy_lookup, log_file=str(eng.workdir / "xray-error.log"),
    )
    res = await eng.apply(cfg)
    STATE["last_sync"] = time.time()
    STATE["inbounds"] = sum(1 for i in cfg["inbounds"] if i["tag"] != "api")
    if not res.get("ok"):
        STATE["last_apply_error"] = res.get("error", "")[-600:]
        for uid in report:
            if report[uid].get("ok"):
                report[uid] = {**report[uid], "ok": False, "reason": "Xray کانفیگ را نپذیرفت: " + STATE["last_apply_error"][-160:]}
    else:
        STATE["last_apply_error"] = ""
    STATE["report"] = report
    STATE["running"] = eng.running
    return res


async def _sync_loop():
    while True:
        try:
            try:
                await asyncio.wait_for(_event.wait(), timeout=20)  # دوره‌ای: برای انقضای زمانی
            except asyncio.TimeoutError:
                pass
            _event.clear()
            await asyncio.sleep(1.0)  # debounce تغییرات پشت‌سرهم
            _event.clear()
            await _sync_once()
        except asyncio.CancelledError:
            return
        except Exception as exc:
            log.exception("xray sync error: %s", exc)
            await asyncio.sleep(5)


async def _stats_loop():
    global _dirty_since_save
    while True:
        try:
            await asyncio.sleep(10)
            eng = _engine
            if not eng or not eng.running:
                continue
            usage = await eng.query_stats(reset=True)
            if not usage:
                continue
            m = _m()
            need_sync = False
            async with m.LINKS_LOCK:
                for uid, (up, down) in usage.items():
                    link = m.LINKS.get(uid)
                    n = int(up) + int(down)
                    if link is None or n <= 0:
                        continue
                    link["used_bytes"] = int(link.get("used_bytes", 0) or 0) + n
                    m.stats["total_bytes"] += n
                    m.hourly_traffic[m.now_ir().strftime("%H:00")] += n
                    if not m.is_link_allowed(link):
                        need_sync = True  # سقف حجم رسید → از Xray حذف شود
            _dirty_since_save = _dirty_since_save or time.time()
            if need_sync or time.time() - _dirty_since_save > 60:
                _dirty_since_save = 0.0
                await m.save_state()  # save_state خودش request_sync می‌زند
        except asyncio.CancelledError:
            return
        except Exception as exc:
            log.warning("xray stats loop error: %s", exc)


# ───────────────────────────── چرخه‌ی عمر ─────────────────────────────

async def start(app_logger=None):
    global _engine, _event
    if os.environ.get("XRAY_DISABLE", "").strip() in ("1", "true", "yes"):
        STATE["error"] = "با XRAY_DISABLE غیرفعال شده"
        return
    m = _m()
    eng = xe.XrayEngine(Path(m.DATA_DIR) / "xray", api_port=int(os.environ.get("XRAY_API_PORT", "10085")))
    if not eng.available:
        STATE["error"] = "Xray-core پیدا نشد؛ پنل فقط لینک می‌سازد (install.sh آن را نصب می‌کند)"
        (app_logger or log).warning(STATE["error"])
        return
    _engine = eng
    _event = asyncio.Event()
    STATE.update(enabled=True, available=True, version=eng.version(), error="")
    eng.start_watchdog()
    _tasks[:] = [asyncio.create_task(_sync_loop()), asyncio.create_task(_stats_loop())]
    _event.set()
    (app_logger or log).info("Xray engine enabled: %s", STATE["version"])


async def stop():
    for t in _tasks:
        t.cancel()
    _tasks.clear()
    if _engine:
        await _engine.stop()
    STATE["enabled"] = False
