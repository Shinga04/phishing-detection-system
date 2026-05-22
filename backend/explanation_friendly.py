"""
UI/UX layer: maps raw LIME explanation strings to friendly titles and impact text.
Does not modify ML, features, or LIME itself — consume output of explain_prediction().
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from feature_engineering import FEATURE_ORDER

# LIME lines look like: "feature <= 0.12: -0.2481" or "-0.42 < email_text_length <= 0.20: -0.2264"
_LIME_LINE_RE = re.compile(
    r"^(?P<condition>.+?):\s*(?P<weight>[-+]?(?:\d*\.\d+|\d+)(?:[eE][-+]?\d+)?)\s*$"
)

# Internal sklearn feature names -> professional security-oriented titles
FEATURE_TITLE_MAP: Dict[str, str] = {
    "url_length": "URL Structure Length",
    "num_dots": "Domain & Subdomain Complexity",
    "has_ip": "IP-Literal Host Detection",
    "num_special_chars": "Suspicious Character Density",
    "uses_https": "Transport Security (HTTPS)",
    "domain_age": "Domain Maturity & Age",
    "has_login_keyword": "Credential-Harvesting Language",
    "ssl_valid": "TLS Certificate Presence",
    "ssl_self_signed": "Certificate Integrity (Self-Signed Risk)",
    "ssl_expiry_days": "Certificate Validity Window",
    "ssl_issuer_len": "Certificate Authority Metadata",
    "email_text_length": "Message Body Scale",
    "email_num_links": "Embedded Hyperlink Density",
    "email_suspicious_keywords": "Urgency & Social-Engineering Language",
    "email_has_spoofed_tld": "Suspicious Sender / TLD Pattern",
    "shortening_services": "URL Shortener Usage",
    "phish_suspicious_tld": "Suspicious Top-Level Domain",
    "phish_many_subdomains": "Subdomain Chain Depth",
    "phish_long_domain": "Domain Length Risk",
    "phish_hyphen_count": "Hyphen Obfuscation Signal",
    "phish_digit_count": "Numeric Domain Pattern",
    "phish_param_count": "Query Parameter Complexity",
    "phish_encoded_chars": "Encoded Character Obfuscation",
    "phish_has_redirect": "Redirect/Relay Indicator",
    "defac_path_depth": "URL Path Depth",
    "defac_is_deep_path": "Deep Path Flag",
    "defac_path_underscores": "Path Underscore Density",
    "adv_domain_ngram_entropy": "Domain Entropy Anomaly",
    "adv_subdomain_count": "Subdomain Count",
    "adv_digit_ratio": "Digit-to-Letter Domain Ratio",
    "phish_keyword_count": "Phishing Keyword Density",
    "web_security_score": "Web Security Score",
    "web_is_live": "Website Availability Signal",
    "web_forms_count": "Form Element Count",
    "web_passwordfields": "Password Field Presence",
    "web_has_login": "Login Surface Presence",
    "web_ssl_valid": "Dataset SSL Validity",
    "abnormal_url": "Abnormal URL Pattern",
    "count_at": "At-Symbol Frequency",
    "count_qmark": "Question-Mark Frequency",
    "count_underscore": "Underscore Frequency",
    "count_equal": "Equals-Sign Frequency",
    "count_dot": "Dot Frequency",
    "count_hash": "Hash-Sign Frequency",
    "count_percent": "Percent-Encoding Frequency",
    "count_plus": "Plus-Sign Frequency",
    "count_dollar": "Dollar-Sign Frequency",
    "count_exclam": "Exclamation-Mark Frequency",
    "count_star": "Asterisk Frequency",
    "count_dslash": "Double-Slash Frequency",
    "digit_count": "Digit Count",
    "letter_count": "Letter Count",
    "adv_avg_subdomain_len": "Average Subdomain Length",
    "adv_avg_token_length": "Average Host Token Length",
}


def _clean_unknown_name(snippet: str) -> str:
    s = (snippet or "").strip()
    s = re.sub(r"[_]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    if not s:
        return "Additional signal"
    return s.replace("_", " ").title()


def _feature_key_from_condition(condition: str) -> Optional[str]:
    """Resolve which engineered feature the LIME condition refers to."""
    cond = condition.strip()
    for name in sorted(FEATURE_ORDER, key=len, reverse=True):
        if re.search(r"\b" + re.escape(name) + r"\b", cond):
            return name
    # Simple leading feature: "name <= ..." or "name > ..."
    m = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*[<>]=?", cond)
    if m and m.group(1) in FEATURE_ORDER:
        return m.group(1)
    # Bounded interval: "a < name < b" or "a <= name <= b"
    m = re.search(
        r"(?:<|<=)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:<|<=)",
        cond,
    )
    if m and m.group(1) in FEATURE_ORDER:
        return m.group(1)
    return None


def _title_for_key(key: Optional[str], condition: str) -> str:
    if key and key in FEATURE_TITLE_MAP:
        return FEATURE_TITLE_MAP[key]
    if key:
        return _clean_unknown_name(key)
    # No resolved key: use first plausible token from condition
    m = re.search(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b", condition)
    if m:
        return _clean_unknown_name(m.group(1))
    return "Model explanation signal"


def _security_impact(weight: float) -> tuple[str, str]:
    """
    Returns (polarity_label, prose).
    Positive LIME weight -> association with predicted (phishing) side in typical setups.
    """
    try:
        w = float(weight)
    except (TypeError, ValueError):
        return (
            "neutral",
            "This factor could not be scored numerically for this explanation line.",
        )
    if w != w:  # NaN
        return (
            "neutral",
            "This factor has negligible influence on the local explanation in this instance.",
        )
    if w > 0:
        return (
            "elevated_risk",
            "This factor pushes the explanation toward a higher phishing risk profile "
            "(red / elevated attention signal in the UI).",
        )
    if w < 0:
        return (
            "legitimacy_support",
            "This factor pushes the explanation toward a more legitimate profile "
            "(green / lower concern signal in the UI).",
        )
    return (
        "neutral",
        "This factor has negligible influence on the local explanation in this instance.",
    )


def _polarity_and_impact(weight: float) -> tuple[str, str]:
    """Always return a pair; never let bad types or return shapes crash the API."""
    try:
        out = _security_impact(weight)
        if isinstance(out, tuple) and len(out) == 2:
            a, b = out[0], out[1]
            if isinstance(a, str) and isinstance(b, str):
                return a, b
    except (TypeError, ValueError):
        pass
    return (
        "informational",
        "Could not format security impact for this explanation line.",
    )


def get_friendly_explanation(lime_results: Any) -> List[Dict[str, Any]]:
    """
    Transform raw LIME strings (or similar 'condition: weight' lines) into UI-ready dicts.

    Each output item includes:
      - title: professional heading
      - feature_key: resolved internal name or None
      - condition: parsed mathematical constraint (if any)
      - weight: numeric LIME weight (if parsed)
      - impact_polarity: elevated_risk | legitimacy_support | neutral | informational
      - security_impact: human-readable sentence
      - raw: original string
    """
    if lime_results is None:
        return []

    if isinstance(lime_results, str):
        items: List[str] = [lime_results]
    else:
        try:
            items = [str(x) for x in lime_results]
        except TypeError:
            return []

    out: List[Dict[str, Any]] = []
    for raw in items:
        line = raw.strip()
        if not line:
            continue

        m = _LIME_LINE_RE.match(line)
        if not m:
            out.append(
                {
                    "title": "System message",
                    "feature_key": None,
                    "condition": None,
                    "weight": None,
                    "impact_polarity": "informational",
                    "security_impact": line,
                    "raw": raw,
                }
            )
            continue

        condition = m.group("condition").strip()
        try:
            weight = float(m.group("weight"))
        except ValueError:
            out.append(
                {
                    "title": "System message",
                    "feature_key": None,
                    "condition": condition,
                    "weight": None,
                    "impact_polarity": "informational",
                    "security_impact": "Could not parse explanation weight; showing raw condition.",
                    "raw": raw,
                }
            )
            continue

        key = _feature_key_from_condition(condition)
        title = _title_for_key(key, condition)
        polarity, impact_text = _polarity_and_impact(weight)

        out.append(
            {
                "title": title,
                "feature_key": key,
                "condition": condition,
                "weight": weight,
                "impact_polarity": polarity,
                "security_impact": impact_text,
                "raw": raw,
            }
        )

    return out
