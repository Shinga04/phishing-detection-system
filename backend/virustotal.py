import base64
import json
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests


ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = ROOT / "models"
CACHE_PATH = MODELS_DIR / "vt_cache.sqlite"


def _now() -> int:
    return int(time.time())


def _base64url_no_pad(raw: str) -> str:
    b = raw.encode("utf-8", errors="ignore")
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _normalize_url(url: str) -> str:
    u = (url or "").strip()
    if not u:
        return ""
    if "://" not in u:
        u = "http://" + u
    return u


def _hostname(url: str) -> str:
    try:
        parsed = urlparse(_normalize_url(url))
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def _get_api_key() -> str:
    return (os.getenv("VT_API_KEY") or "").strip()


def vt_enabled() -> bool:
    return bool(_get_api_key())


def _timeout_sec() -> float:
    try:
        return float(os.getenv("VT_TIMEOUT_SEC") or "4")
    except Exception:
        return 4.0


def _ttl_url_sec() -> int:
    try:
        return int(os.getenv("VT_CACHE_URL_TTL_SEC") or "43200")  # 12h
    except Exception:
        return 43200


def _ttl_domain_sec() -> int:
    try:
        return int(os.getenv("VT_CACHE_DOMAIN_TTL_SEC") or "86400")  # 24h
    except Exception:
        return 86400


def _conn() -> sqlite3.Connection:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(CACHE_PATH))
    c.execute(
        "CREATE TABLE IF NOT EXISTS vt_url_cache (url TEXT PRIMARY KEY, json TEXT NOT NULL, updated_at INTEGER NOT NULL)"
    )
    c.execute(
        "CREATE TABLE IF NOT EXISTS vt_domain_cache (domain TEXT PRIMARY KEY, json TEXT NOT NULL, updated_at INTEGER NOT NULL)"
    )
    return c


def _cache_get(table: str, key_field: str, key: str) -> Optional[Dict[str, Any]]:
    try:
        with _conn() as c:
            row = c.execute(
                f"SELECT json, updated_at FROM {table} WHERE {key_field}=?",
                (key,),
            ).fetchone()
            if not row:
                return None
            payload, updated_at = row
            return {"payload": json.loads(payload), "updated_at": int(updated_at)}
    except Exception:
        return None


def _cache_put(table: str, key_field: str, key: str, payload: Dict[str, Any]) -> None:
    try:
        with _conn() as c:
            c.execute(
                f"INSERT OR REPLACE INTO {table} ({key_field}, json, updated_at) VALUES (?, ?, ?)",
                (key, json.dumps(payload), _now()),
            )
            c.commit()
    except Exception:
        return


def _summary_from_vt_json(data: Dict[str, Any]) -> Dict[str, Any]:
    attrs = (((data or {}).get("data") or {}).get("attributes") or {})
    stats = attrs.get("last_analysis_stats") or {}
    return {
        "malicious": int(stats.get("malicious") or 0),
        "suspicious": int(stats.get("suspicious") or 0),
        "harmless": int(stats.get("harmless") or 0),
        "undetected": int(stats.get("undetected") or 0),
        "timeout": int(stats.get("timeout") or 0),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "reputation": attrs.get("reputation"),
    }


def vt_lookup_url(url: str) -> Dict[str, Any]:
    """
    Returns: { status: ok|skipped|unavailable, url, summary }
    Uses cache; calls VT v3 only when enabled and cache is stale.
    """
    u = _normalize_url(url)
    if not u:
        return {"status": "skipped", "url": url, "summary": {}}
    if not vt_enabled():
        return {"status": "skipped", "url": u, "summary": {}}

    cached = _cache_get("vt_url_cache", "url", u)
    if cached and (_now() - int(cached["updated_at"])) <= _ttl_url_sec():
        return {"status": "ok", "url": u, "summary": cached["payload"], "cached": True}

    api_key = _get_api_key()
    url_id = _base64url_no_pad(u)
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    try:
        r = requests.get(endpoint, headers={"x-apikey": api_key}, timeout=_timeout_sec())
        if r.status_code == 200:
            summ = _summary_from_vt_json(r.json())
            _cache_put("vt_url_cache", "url", u, summ)
            return {"status": "ok", "url": u, "summary": summ, "cached": False}
        return {"status": "unavailable", "url": u, "http_status": r.status_code, "summary": {}}
    except Exception as exc:
        return {"status": "unavailable", "url": u, "error": str(exc), "summary": {}}


def vt_lookup_domain(domain_or_url: str) -> Dict[str, Any]:
    """
    Returns: { status: ok|skipped|unavailable, domain, summary }
    Accepts either a domain string or a URL.
    """
    dom = (domain_or_url or "").strip().lower()
    if "://" in dom or "/" in dom:
        dom = _hostname(dom)
    if not dom:
        return {"status": "skipped", "domain": "", "summary": {}}
    if not vt_enabled():
        return {"status": "skipped", "domain": dom, "summary": {}}

    cached = _cache_get("vt_domain_cache", "domain", dom)
    if cached and (_now() - int(cached["updated_at"])) <= _ttl_domain_sec():
        return {"status": "ok", "domain": dom, "summary": cached["payload"], "cached": True}

    api_key = _get_api_key()
    endpoint = f"https://www.virustotal.com/api/v3/domains/{dom}"
    try:
        r = requests.get(endpoint, headers={"x-apikey": api_key}, timeout=_timeout_sec())
        if r.status_code == 200:
            summ = _summary_from_vt_json(r.json())
            _cache_put("vt_domain_cache", "domain", dom, summ)
            return {"status": "ok", "domain": dom, "summary": summ, "cached": False}
        return {"status": "unavailable", "domain": dom, "http_status": r.status_code, "summary": {}}
    except Exception as exc:
        return {"status": "unavailable", "domain": dom, "error": str(exc), "summary": {}}

