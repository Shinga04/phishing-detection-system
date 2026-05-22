import math
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlparse

import numpy as np
import tldextract
from cryptography import x509


# Heuristic keywords used for a simple count feature (not the full model).
# Keep this list reasonably broad: "login" phishing + common advance-fee / money-transfer scams.
SUSPICIOUS_KEYWORDS = [
    # credential / account pressure
    "urgent",
    "verify",
    "login",
    "sign in",
    "signin",
    "password",
    "account",
    "security",
    "suspended",
    "locked",
    "confirm",
    # finance / advance-fee patterns
    "beneficiary",
    "inheritance",
    "winning",
    "fund",
    "funds",
    "million",
    "usd",
    "payment",
    "transfer",
    "transaction",
    "western union",
    "moneygram",
    "mtcn",
    "agent",
    "furnish",
    "kindly",
    "imf",
]

# Regex-style signals that should increment the same keyword-count feature.
# This keeps feature dimensionality stable while improving recall.
SUSPICIOUS_EMAIL_PATTERNS = [
    re.compile(r"\bmtcn\b", re.IGNORECASE),
    re.compile(r"\bwestern\s+union\b", re.IGNORECASE),
    re.compile(r"\bmoney\s*gram\b", re.IGNORECASE),
    re.compile(r"\binheritance\b", re.IGNORECASE),
    re.compile(r"\bbeneficiary\b", re.IGNORECASE),
    re.compile(r"\b(?:usd|us\\$|\\$)\\s*\\d{1,3}(?:,\\d{3})*(?:\\.\\d+)?\\b", re.IGNORECASE),
    # Common "fill in your details" / personal info harvesting in scams
    re.compile(r"\byour\\s+(?:name|address|country|occupation|phone|telephone|age|sex)\\b", re.IGNORECASE),
]

# Cap text used for numeric features so huge pastes/thread tails do not dominate length-based signals.
MAX_EMAIL_FEATURE_CHARS = 10000

_QUOTE_SPLIT_PATTERNS = (
    re.compile(r"\n-+original message-+\s*\n", re.IGNORECASE),
    re.compile(r"\nBegin forwarded message:\s*\n", re.IGNORECASE),
    re.compile(r"\nOn .+ wrote:\s*\n", re.IGNORECASE),
    re.compile(r"\nFrom:\s*.+\nSent:\s*.+\n", re.IGNORECASE),
)


def _strip_html_preserve_bracket_emails(raw: str) -> str:
    """Remove angle-bracket chunks that look like HTML tags, not `From: <user@host>`."""

    def repl(match: re.Match) -> str:
        inner = (match.group(1) or "").strip()
        if re.fullmatch(r"[\w.+%-]+@[\w.-]+", inner, re.IGNORECASE):
            return f" {inner} "
        return " "

    return re.sub(r"<([^>]+)>", repl, raw)


def preprocess_email_text(text: str) -> str:
    """Normalize pasted email / HTML for feature extraction."""
    raw = (text or "").strip()
    if not raw:
        return ""
    # Strip simple HTML tags (pasted "rich" mail); keep newlines for quote-boundary detection.
    plain = _strip_html_preserve_bracket_emails(raw)
    low = plain.lower()
    cut = len(low)
    for pat in _QUOTE_SPLIT_PATTERNS:
        m = pat.search(low)
        if m and m.start() < cut:
            cut = m.start()
    trimmed = plain[:cut].strip()
    trimmed = re.sub(r"\s+", " ", trimmed).strip()
    if len(trimmed) > MAX_EMAIL_FEATURE_CHARS:
        trimmed = trimmed[:MAX_EMAIL_FEATURE_CHARS]
    return trimmed.lower()


def _safe_bool(value: bool) -> int:
    return int(bool(value))


def _has_ip_in_domain(domain: str) -> bool:
    if not domain:
        return False
    try:
        socket.inet_aton(domain)
        return True
    except OSError:
        return False


def extract_url_features(url: str) -> dict:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    netloc = parsed.netloc or parsed.path

    hostname = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()

    # Exclude query string: reset tokens/parameters can otherwise dominate signals.
    domain_and_path = (hostname + path).lower()

    has_login_keyword = any(
        keyword in domain_and_path for keyword in ("login", "signin", "verify", "password")
    )

    url_text = url or ""
    url_length = min(len(url_text), 500)
    num_special_chars = len(re.findall(r"[@\\-_=\\?%&#]", url_text))
    num_special_chars = min(num_special_chars, 15)

    return {
        "url_length": url_length,
        "num_dots": hostname.count("."),
        "has_ip": _safe_bool(_has_ip_in_domain((netloc.split(":")[0] if netloc else ""))),
        "num_special_chars": num_special_chars,
        "uses_https": _safe_bool(parsed.scheme.lower() == "https"),
        "domain_age": -1,
        "has_login_keyword": _safe_bool(has_login_keyword),
    }


def extract_ssl_features(url: str) -> dict:
    defaults = {
        "ssl_valid": 0,
        "ssl_self_signed": 1,
        "ssl_expiry_days": -1,
        "ssl_issuer_len": 0,
    }
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        hostname = parsed.hostname
        if not hostname:
            return defaults

        cert_pem = ssl.get_server_certificate((hostname, 443))
        cert = x509.load_pem_x509_certificate(cert_pem.encode())

        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()
        not_after = getattr(cert, "not_valid_after_utc", None)
        if not_after is None:
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        expiry_days = max((not_after - datetime.now(timezone.utc)).days, -1)

        return {
            "ssl_valid": 1,
            "ssl_self_signed": _safe_bool(issuer == subject),
            "ssl_expiry_days": expiry_days,
            "ssl_issuer_len": len(issuer),
        }
    except Exception:
        return defaults


_SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "lnkd.in",
    "rb.gy",
    "shorturl.at",
    "adf.ly",
    "mcaf.ee",
}

_SUSPICIOUS_TLDS = {
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "top",
    "xyz",
    "work",
    "click",
    "support",
    "zip",
    "mov",
}

_PHISHING_KEYWORDS = (
    "login",
    "signin",
    "verify",
    "password",
    "account",
    "secure",
    "update",
    "confirm",
    "unlock",
    "suspended",
    "billing",
    "bank",
    "payment",
)


def _shannon_entropy(value: str) -> float:
    text = (value or "").strip()
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = float(len(text))
    return float(-sum((c / n) * math.log2(c / n) for c in freq.values()))


def extract_advanced_url_features(url: str) -> dict:
    parsed = urlparse(url if "://" in (url or "") else f"http://{url}")
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full = (url or "").lower()

    host_tokens = [t for t in re.split(r"[.\-]", hostname) if t]
    tld = tldextract.extract(hostname).suffix.lower() if hostname else ""

    letters = sum(1 for c in hostname if c.isalpha())
    digits = sum(1 for c in hostname if c.isdigit())
    total_alnum = letters + digits

    # Use query pair count first; fallback keeps behavior on malformed queries.
    param_count = len(parse_qsl(query, keep_blank_values=True)) if query else 0
    if param_count == 0 and query:
        param_count = query.count("&") + 1

    subdomain_parts = [p for p in hostname.split(".")[:-2] if p] if hostname.count(".") >= 2 else []
    avg_sub_len = (
        float(sum(len(p) for p in subdomain_parts)) / float(len(subdomain_parts))
        if subdomain_parts
        else 0.0
    )

    avg_token_len = (
        float(sum(len(t) for t in host_tokens)) / float(len(host_tokens))
        if host_tokens
        else 0.0
    )

    phishing_kw_count = sum(1 for kw in _PHISHING_KEYWORDS if kw in full)

    return {
        "shortening_services": _safe_bool(hostname in _SHORTENER_DOMAINS),
        "phish_suspicious_tld": _safe_bool(tld in _SUSPICIOUS_TLDS),
        "phish_many_subdomains": _safe_bool(len(subdomain_parts) >= 3),
        "phish_long_domain": _safe_bool(len(hostname) >= 35),
        "phish_hyphen_count": min(hostname.count("-"), 20),
        "phish_digit_count": min(digits, 30),
        "phish_param_count": min(param_count, 30),
        "phish_encoded_chars": min(full.count("%"), 30),
        "phish_has_redirect": _safe_bool(("redirect" in full) or ("url=" in query) or ("next=" in query)),
        "defac_path_depth": min(len([p for p in path.split("/") if p]), 20),
        "defac_is_deep_path": _safe_bool(len([p for p in path.split("/") if p]) >= 4),
        "defac_path_underscores": min(path.count("_"), 20),
        "adv_domain_ngram_entropy": float(_shannon_entropy(hostname)),
        "adv_subdomain_count": len(subdomain_parts),
        "adv_digit_ratio": (float(digits) / float(total_alnum)) if total_alnum else 0.0,
        "phish_keyword_count": min(phishing_kw_count, 20),
        # Additional compatible core URL/meta features from provided schema
        "web_security_score": 0.0,
        "web_is_live": 0,
        "web_forms_count": 0,
        "web_passwordfields": 0,
        "web_has_login": _safe_bool(any(k in full for k in ("login", "signin", "password"))),
        "web_ssl_valid": _safe_bool(parsed.scheme.lower() == "https"),
        "abnormal_url": _safe_bool(("@" in full) or (hostname.count(".") == 0)),
        "count_at": full.count("@"),
        "count_qmark": full.count("?"),
        "count_underscore": full.count("_"),
        "count_equal": full.count("="),
        "count_dot": full.count("."),
        "count_hash": full.count("#"),
        "count_percent": full.count("%"),
        "count_plus": full.count("+"),
        "count_dollar": full.count("$"),
        "count_exclam": full.count("!"),
        "count_star": full.count("*"),
        "count_dslash": full.count("//"),
        "digit_count": digits,
        "letter_count": letters,
        "adv_avg_subdomain_len": float(avg_sub_len),
        "adv_avg_token_length": float(avg_token_len),
    }


def extract_email_features_normalized(content: str) -> dict:
    if not (content or "").strip():
        return {
            "email_text_length": 0,
            "email_num_links": 0,
            "email_suspicious_keywords": 0,
            "email_has_spoofed_tld": 0,
        }
    links = re.findall(r"https?://[^\s<>\"')\]]+|www\.[^\s<>\"')\]]+", content)
    # Count suspicious terms/patterns; cap to keep feature within a sensible range.
    keyword_hits = 0
    for k in SUSPICIOUS_KEYWORDS:
        if k in content:
            keyword_hits += 1
    for pat in SUSPICIOUS_EMAIL_PATTERNS:
        if pat.search(content):
            keyword_hits += 1
    keyword_hits = min(keyword_hits, 12)
    sender_suffix = _extract_sender_registrable_suffix(content)

    return {
        "email_text_length": len(content),
        "email_num_links": len(links),
        "email_suspicious_keywords": keyword_hits,
        "email_has_spoofed_tld": _safe_bool(sender_suffix in {"ru", "tk", "xyz", "top", "gq"}),
    }


def extract_email_features(text: str) -> dict:
    return extract_email_features_normalized(preprocess_email_text(text))


def _sender_host_from_header_line(stripped: str) -> str:
    m = re.search(r"<[\w.+%-]+@([\w.-]+)>", stripped, re.IGNORECASE)
    if not m:
        m = re.search(r"[\w.+%-]+@([\w.-]+\.[\w.-]+)\b", stripped)
    return m.group(1).lower() if m else ""


def _extract_sender_registrable_suffix(text: str) -> str:
    """Parse From:/Reply-To: lines; return public suffix / registrable TLD hint for spoof heuristics."""
    for line in text.splitlines():
        stripped = line.strip()
        low = stripped.lower()
        if not (low.startswith("from:") or low.startswith("reply-to:")):
            continue
        host = _sender_host_from_header_line(stripped)
        if host:
            ext = tldextract.extract(host)
            return (ext.suffix or ext.domain or "").lower()
    # HTML-stripped pastes often become one line: "... From: Name <n@x.com> ..."
    m = re.search(
        r"(?:^|\s)(?:from|reply-to):\s*(?:[^<]*?<)?[\w.+%-]+@([\w.-]+\.[\w.-]+)\b",
        text,
        re.IGNORECASE,
    )
    if m:
        ext = tldextract.extract(m.group(1).lower())
        return (ext.suffix or ext.domain or "").lower()
    return ""


FEATURE_ORDER = [
    "url_length",
    "num_dots",
    "has_ip",
    "num_special_chars",
    "uses_https",
    "domain_age",
    "has_login_keyword",
    "ssl_valid",
    "ssl_self_signed",
    "ssl_expiry_days",
    "ssl_issuer_len",
    "email_text_length",
    "email_num_links",
    "email_suspicious_keywords",
    "email_has_spoofed_tld",
    # New URL-centric phishing signals from expanded dataset schema
    "shortening_services",
    "phish_suspicious_tld",
    "phish_many_subdomains",
    "phish_long_domain",
    "phish_hyphen_count",
    "phish_digit_count",
    "phish_param_count",
    "phish_encoded_chars",
    "phish_has_redirect",
    "defac_path_depth",
    "defac_is_deep_path",
    "defac_path_underscores",
    "adv_domain_ngram_entropy",
    "adv_subdomain_count",
    "adv_digit_ratio",
    "phish_keyword_count",
    # Extra compatible subset from provided schema (kept runtime-safe)
    "web_security_score",
    "web_is_live",
    "web_forms_count",
    "web_passwordfields",
    "web_has_login",
    "web_ssl_valid",
    "abnormal_url",
    "count_at",
    "count_qmark",
    "count_underscore",
    "count_equal",
    "count_dot",
    "count_hash",
    "count_percent",
    "count_plus",
    "count_dollar",
    "count_exclam",
    "count_star",
    "count_dslash",
    "digit_count",
    "letter_count",
    "adv_avg_subdomain_len",
    "adv_avg_token_length",
]


def combine_feature_vectors(url: str = "", email_text: str = "") -> dict:
    url_feats = extract_url_features(url)
    adv_url_feats = extract_advanced_url_features(url)
    ssl_feats = extract_ssl_features(url) if url else {
        "ssl_valid": 0,
        "ssl_self_signed": 1,
        "ssl_expiry_days": -1,
        "ssl_issuer_len": 0,
    }
    email_plain = preprocess_email_text(email_text)
    email_feats = extract_email_features_normalized(email_plain)
    email_login_signal = _safe_bool(
        any(keyword in email_plain for keyword in ("login", "signin", "verify", "password"))
    )
    all_features = {**url_feats, **ssl_feats, **email_feats, **adv_url_feats}
    all_features["has_login_keyword"] = max(all_features.get("has_login_keyword", 0), email_login_signal)
    for key in FEATURE_ORDER:
        all_features.setdefault(key, 0)
    return all_features


def dict_to_vector(feature_dict: dict) -> np.ndarray:
    return np.array([feature_dict[k] for k in FEATURE_ORDER], dtype=float).reshape(1, -1)
