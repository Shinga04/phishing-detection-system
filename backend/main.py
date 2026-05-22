import logging
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

logger = logging.getLogger("phishing_api")

from explain import build_explainer, explain_prediction
from explanation_friendly import get_friendly_explanation
from feature_engineering import combine_feature_vectors, dict_to_vector
from model import load_model_bundle, train_and_save
from sample_store import append_sample, get_learning_stats, should_auto_store
from virustotal import vt_lookup_domain, vt_lookup_url, vt_enabled


app = FastAPI(title="Multi-Vector Phishing Detection API", version="1.0.0")

load_dotenv(Path(__file__).resolve().parent / ".env")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Non-Google brands: any subdomain may short-circuit to "safe".
# Google is handled separately — attackers commonly abuse real Google Forms/Docs/Drive URLs.
TRUSTED_DOMAINS = {"zoom.us", "youtube.com", "youtu.be", "microsoft.com"}

# Only these Google hosts may skip ML (search, accounts, mail, etc.). Anything else under
# *.google.com goes through normal URL analysis unless it is a known-benign host below.
_GOOGLE_INSTANT_SAFE_HOSTS = frozenset(
    {
        "google.com",
        "www.google.com",
        "accounts.google.com",
        "myaccount.google.com",
        "mail.google.com",
        "calendar.google.com",
        "meet.google.com",
        "chat.google.com",
        "photos.google.com",
        "play.google.com",
        "news.google.com",
        "maps.google.com",
        "translate.google.com",
        "support.google.com",
        "policies.google.com",
        "safety.google.com",
        "opensource.google.com",
        "pay.google.com",
        "wallet.google.com",
        "one.google.com",
        "about.google.com",
        "blog.google.com",
    }
)

# User-generated / form-like Google surfaces: always run feature extraction + model + VT path.
_GOOGLE_ALWAYS_ANALYZE_HOSTS = frozenset(
    {
        "docs.google.com",
        "drive.google.com",
        "script.google.com",
        "spreadsheets.google.com",
        "survey.google.com",
    }
)


def _google_requires_full_analysis(hostname: str, path_and_query: str) -> bool:
    """True when the URL must not use Google instant-safe short-circuit."""
    h = (hostname or "").lower()
    pq = (path_and_query or "").lower()

    if h == "forms.gle" or h.endswith(".forms.gle"):
        return True

    is_google = h == "google.com" or h.endswith(".google.com")
    if not is_google:
        return False

    if h in _GOOGLE_ALWAYS_ANALYZE_HOSTS:
        return True

    path_hints = (
        "viewform",
        "formresponse",
        "/forms/",
        "/forms/d/",
        "formkey=",
        "usp=form_",
    )
    return any(x in pq for x in path_hints)


def is_whitelisted(url: str) -> bool:
    """
    Whitelist common legitimate services to reduce false positives.
    Matches either the exact domain or any subdomain of trusted entries.

    Google is special-cased: many *.google.com hosts are still trusted, but forms, Docs,
    Drive, Apps Script, and spreadsheet-form patterns are analyzed like any other URL.
    """
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return False

        path_q = f"{parsed.path or ''}?{parsed.query or ''}"
        if _google_requires_full_analysis(hostname, path_q):
            return False

        if hostname == "google.com" or hostname.endswith(".google.com"):
            return hostname in _GOOGLE_INSTANT_SAFE_HOSTS

        for trusted in TRUSTED_DOMAINS:
            if hostname == trusted or hostname.endswith("." + trusted):
                return True
        return False
    except Exception:
        return False

model, scaler, train_features = load_model_bundle()
explainer = build_explainer(train_features)


def reload_model_bundle():
    """Reload ensemble + LIME background after manual or API-triggered retrain."""
    global model, scaler, train_features, explainer
    model, scaler, train_features = load_model_bundle()
    explainer = build_explainer(train_features)


class URLRequest(BaseModel):
    url: str = Field(..., example="http://example.com")


class EmailRequest(BaseModel):
    email_text: str = Field(..., example="Urgent: verify your account now at http://fake.com")


class FeedbackRequest(BaseModel):
    sample_type: str = Field(..., description="url or email")
    input_text: str = Field(..., min_length=3)
    label: int = Field(..., ge=0, le=1, description="0=safe, 1=phishing")
    features: dict = Field(default_factory=dict)
    prediction: str = ""
    confidence: float = 0.0
    p_phishing: float = 0.0


def _provisional_label(prediction: str) -> int:
    return 1 if (prediction or "").lower() == "phishing" else 0


def _maybe_auto_store(sample_type: str, input_text: str, base: dict) -> None:
    """Buffer uncertain predictions for semi-incremental retraining."""
    meta = base.get("_meta") or {}
    p_phish = float(meta.get("p_phishing", 0.0))
    confidence = float(base.get("confidence", 0.0))
    if not should_auto_store(p_phish, confidence):
        return
    features = base.get("features") or {}
    if not features:
        return
    append_sample(
        sample_type=sample_type,
        input_text=input_text,
        label=_provisional_label(base.get("prediction", "")),
        label_source="auto_low_confidence",
        features=features,
        prediction=str(base.get("prediction", "")),
        confidence=confidence,
        p_phishing=p_phish,
    )


def _finalize_explanation_ui(payload: dict) -> dict:
    """Attach human-friendly explanation rows without changing ML outputs."""
    payload["explanation_friendly"] = get_friendly_explanation(payload.get("explanation"))
    return payload


def _predict(feature_dict: dict):
    raw_vector = dict_to_vector(feature_dict)
    scaled = scaler.transform(raw_vector)
    probabilities = model.predict_proba(scaled)[0]

    # Avoid false positives: only classify as phishing if phishing probability is high enough.
    safe_prob = float(probabilities[0])
    phishing_prob = float(probabilities[1]) if len(probabilities) > 1 else 0.0
    if phishing_prob > 0.8:
        label = "phishing"
        confidence = phishing_prob
    else:
        label = "safe"
        confidence = safe_prob

    return {
        "prediction": label,
        "confidence": confidence,
        "features": feature_dict,
        "explanation": explain_prediction(explainer, model, scaled),
        "_meta": {"p_phishing": phishing_prob, "p_safe": safe_prob},
    }


def _is_uncertain(p_phishing: float, low: float = 0.35, high: float = 0.85) -> bool:
    try:
        p = float(p_phishing)
    except Exception:
        return False
    return low <= p <= high


def _apply_vt_override(base: dict, url: str = "", email_urls: list = None) -> dict:
    """
    Adds VirusTotal reputation signals (URL + domain) only when ML is uncertain.
    Keeps response contract stable; adds optional `vt` block.
    """
    email_urls = email_urls or []
    p_phish = float((base.get("_meta") or {}).get("p_phishing", 0.0))
    if not _is_uncertain(p_phish) or not vt_enabled():
        base.pop("_meta", None)
        return base

    vt_info = {"status": "ok", "used": True}
    override = False

    # URL flow
    if url:
        vt_u = vt_lookup_url(url)
        vt_d = vt_lookup_domain(url)
        vt_info["url"] = vt_u
        vt_info["domain"] = vt_d
        um = int((vt_u.get("summary") or {}).get("malicious", 0))
        us = int((vt_u.get("summary") or {}).get("suspicious", 0))
        dm = int((vt_d.get("summary") or {}).get("malicious", 0))
        ds = int((vt_d.get("summary") or {}).get("suspicious", 0))
        if um >= 1 or dm >= 2 or (um + us) >= 3 or (dm + ds) >= 4:
            override = True

    # Email flow: check extracted URLs/domains (limit)
    email_scans = []
    if email_urls:
        for u in email_urls[:10]:
            vt_u = vt_lookup_url(u)
            vt_d = vt_lookup_domain(u)
            email_scans.append({"url": u, "url_rep": vt_u, "domain_rep": vt_d})
            um = int((vt_u.get("summary") or {}).get("malicious", 0))
            us = int((vt_u.get("summary") or {}).get("suspicious", 0))
            dm = int((vt_d.get("summary") or {}).get("malicious", 0))
            ds = int((vt_d.get("summary") or {}).get("suspicious", 0))
            if um >= 1 or dm >= 2 or (um + us) >= 3 or (dm + ds) >= 4:
                override = True
        vt_info["email_links"] = email_scans

    vt_info["override"] = override
    base["vt"] = vt_info

    if override:
        base["prediction"] = "phishing"
        base["confidence"] = max(float(base.get("confidence", 0.0)), 0.9)
        base["explanation"] = (base.get("explanation") or []) + ["VirusTotal reputation override triggered."]

    base.pop("_meta", None)
    return base


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze/url")
def analyze_url(payload: URLRequest):
    try:
        if is_whitelisted(payload.url):
            return _finalize_explanation_ui(
                {
                    "prediction": "safe",
                    "confidence": 1.0,
                    "features": {},
                    "explanation": [],
                }
            )
        feature_dict = combine_feature_vectors(url=payload.url, email_text="")
        base = _predict(feature_dict)
        _maybe_auto_store("url", payload.url, base)
        return _finalize_explanation_ui(_apply_vt_override(base, url=payload.url))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"URL analysis failed: {exc}") from exc


@app.post("/analyze/email")
def analyze_email(payload: EmailRequest):
    try:
        # Fast heuristic override for obvious advance-fee / money-transfer scams.
        # This reduces false negatives without changing the API contract.
        low = (payload.email_text or "").lower()
        scam_signals = (
            ("western union" in low)
            or ("mtcn" in low)
            or ("inheritance" in low)
            or ("beneficiary" in low)
            or ("daily as per our office" in low)
        )
        if scam_signals:
            return _finalize_explanation_ui(
                {
                    "prediction": "phishing",
                    "confidence": 0.95,
                    "features": {"heuristic_override": 1},
                    "explanation": ["Heuristic override: advance-fee / money-transfer scam pattern detected."],
                }
            )
        feature_dict = combine_feature_vectors(url="", email_text=payload.email_text)
        base = _predict(feature_dict)
        _maybe_auto_store("email", payload.email_text, base)

        # If email ML is uncertain, optionally enrich using VT on extracted links/domains.
        text = (payload.email_text or "")[:7000]
        # Reuse simple patterns similar to extension; keep backend self-contained.
        email_urls = []
        for m in __import__("re").finditer(r"https?://[^\s<>\"')\]]+|www\.[^\s<>\"')\]]+", text, __import__("re").I):
            u = m.group(0)
            if u.lower().startswith("www."):
                u = "https://" + u
            email_urls.append(u.rstrip(".,;:!?"))

        return _finalize_explanation_ui(_apply_vt_override(base, email_urls=email_urls))
    except Exception as exc:
        logger.exception("Email analysis failed")
        raise HTTPException(status_code=500, detail=f"Email analysis failed: {exc}") from exc


@app.post("/feedback")
def submit_feedback(payload: FeedbackRequest):
    """User correction: Report as Phishing (1) or Mark as Safe (0)."""
    sample_type = (payload.sample_type or "").strip().lower()
    if sample_type not in {"url", "email"}:
        raise HTTPException(status_code=400, detail="sample_type must be 'url' or 'email'")

    features = dict(payload.features or {})
    if not features:
        if sample_type == "url":
            features = combine_feature_vectors(url=payload.input_text, email_text="")
        else:
            features = combine_feature_vectors(url="", email_text=payload.input_text)

    label_source = "user_phishing" if payload.label == 1 else "user_safe"
    stored = append_sample(
        sample_type=sample_type,
        input_text=payload.input_text,
        label=payload.label,
        label_source=label_source,
        features=features,
        prediction=payload.prediction,
        confidence=payload.confidence,
        p_phishing=payload.p_phishing,
    )
    if not stored:
        raise HTTPException(
            status_code=400,
            detail="Sample not stored (duplicate, invalid input, or malformed URL/email).",
        )
    return {"status": "ok", "stored": True, "label": payload.label}


@app.get("/learning/stats")
def learning_stats():
    return get_learning_stats()


@app.post("/learning/retrain")
def learning_retrain():
    """Merge new_samples.csv and retrain; reload model in this process."""
    try:
        train_and_save(include_new_samples=True, record_retrain=True)
        reload_model_bundle()
        return {"status": "ok", "reloaded": True, **get_learning_stats()}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Retrain failed: {exc}") from exc
