"""
Semi-incremental learning: buffer new labeled samples locally for periodic retraining.

Phishing campaigns evolve (new domains, social-engineering templates, obfuscation).
Retraining on user feedback and uncertain cases lets the ensemble adapt without
complex online deep learning or streaming updates.
"""

from __future__ import annotations

import csv
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import pandas as pd

from feature_engineering import FEATURE_ORDER

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
NEW_SAMPLES_PATH = DATA_DIR / "new_samples.csv"

MAX_URL_LEN = 2000
MAX_EMAIL_LEN = 7000

# Align with VirusTotal uncertain band in main.py
UNCERTAIN_LOW = 0.35
UNCERTAIN_HIGH = 0.85
LOW_CONFIDENCE_THRESHOLD = 0.65

META_COLUMNS = [
    "timestamp",
    "sample_type",
    "input_text",
    "label",
    "label_source",
    "prediction",
    "confidence",
    "p_phishing",
]

CSV_COLUMNS = META_COLUMNS + list(FEATURE_ORDER)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sanitize_input(text: str, sample_type: str) -> str:
    """Strip control chars and cap length to reduce injection / log abuse."""
    if not text:
        return ""
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", str(text)).strip()
    limit = MAX_URL_LEN if sample_type == "url" else MAX_EMAIL_LEN
    return cleaned[:limit]


def is_valid_sample_input(text: str, sample_type: str) -> bool:
    """Reject empty or obviously malformed inputs."""
    s = sanitize_input(text, sample_type)
    if len(s) < 3:
        return False
    if sample_type == "url":
        try:
            parsed = urlparse(s if "://" in s else f"http://{s}")
            return bool(parsed.hostname and len(parsed.hostname) >= 2)
        except Exception:
            return False
    if sample_type == "email":
        return len(s) >= 10
    return False


def normalize_for_dedupe(text: str, sample_type: str) -> str:
    s = sanitize_input(text, sample_type).lower()
    if sample_type == "url":
        s = re.sub(r"^https?://", "", s)
        s = s.rstrip("/")
    return s


def dedupe_key(text: str, sample_type: str) -> str:
    norm = normalize_for_dedupe(text, sample_type)
    return hashlib.sha256(f"{sample_type}:{norm}".encode("utf-8")).hexdigest()


def should_auto_store(p_phishing: float, confidence: float) -> bool:
    """Store uncertain ML decisions for later human review / retraining."""
    try:
        p = float(p_phishing)
        c = float(confidence)
    except (TypeError, ValueError):
        return False
    if UNCERTAIN_LOW <= p <= UNCERTAIN_HIGH:
        return True
    return c < LOW_CONFIDENCE_THRESHOLD


def _existing_dedupe_keys() -> Set[str]:
    if not NEW_SAMPLES_PATH.exists():
        return set()
    try:
        df = pd.read_csv(NEW_SAMPLES_PATH, usecols=["sample_type", "input_text"], dtype=str)
    except Exception:
        return set()
    keys: Set[str] = set()
    for _, row in df.iterrows():
        st = str(row.get("sample_type", "") or "").strip().lower()
        it = str(row.get("input_text", "") or "")
        if st in {"url", "email"} and it:
            keys.add(dedupe_key(it, st))
    return keys


def _ensure_header() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if NEW_SAMPLES_PATH.exists():
        return
    with NEW_SAMPLES_PATH.open("w", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=CSV_COLUMNS).writeheader()


def append_sample(
    *,
    sample_type: str,
    input_text: str,
    label: int,
    label_source: str,
    features: Dict[str, Any],
    prediction: str = "",
    confidence: float = 0.0,
    p_phishing: float = 0.0,
) -> bool:
    """
    Append one row to new_samples.csv. Returns True if stored, False if skipped
    (duplicate, invalid input, or bad label).
    """
    sample_type = (sample_type or "").strip().lower()
    if sample_type not in {"url", "email"}:
        return False
    if label not in (0, 1):
        return False

    text = sanitize_input(input_text, sample_type)
    if not is_valid_sample_input(text, sample_type):
        return False

    key = dedupe_key(text, sample_type)
    if key in _existing_dedupe_keys():
        return False

    row: Dict[str, Any] = {
        "timestamp": _utc_now_iso(),
        "sample_type": sample_type,
        "input_text": text,
        "label": int(label),
        "label_source": label_source,
        "prediction": prediction,
        "confidence": round(float(confidence), 6),
        "p_phishing": round(float(p_phishing), 6),
    }
    for feat in FEATURE_ORDER:
        row[feat] = float(features.get(feat, 0) or 0)

    _ensure_header()
    with NEW_SAMPLES_PATH.open("a", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=CSV_COLUMNS).writerow(row)
    return True


def load_new_samples_matrix() -> tuple[Optional[Any], Optional[Any]]:
    """Return (X, y) from new_samples.csv or (None, None) if empty."""
    import numpy as np

    if not NEW_SAMPLES_PATH.exists():
        return None, None
    try:
        df = pd.read_csv(NEW_SAMPLES_PATH)
    except Exception:
        return None, None
    if df.empty or "label" not in df.columns:
        return None, None

    y = pd.to_numeric(df["label"], errors="coerce")
    valid = y.isin([0, 1])
    if not valid.any():
        return None, None

    df = df.loc[valid].reset_index(drop=True)
    y = y.loc[valid].astype(int).values

    x = pd.DataFrame()
    for feat in FEATURE_ORDER:
        if feat in df.columns:
            x[feat] = pd.to_numeric(df[feat], errors="coerce").fillna(0)
        else:
            x[feat] = 0.0

    return x.values.astype(float), y


def get_learning_stats() -> Dict[str, Any]:
    """Counts for dashboard and model_meta enrichment."""
    total = 0
    threats = 0
    if NEW_SAMPLES_PATH.exists():
        try:
            df = pd.read_csv(NEW_SAMPLES_PATH)
            total = len(df)
            if "label" in df.columns:
                threats = int((pd.to_numeric(df["label"], errors="coerce") == 1).sum())
        except Exception:
            pass

    last_retrain = None
    cv_accuracy = None
    meta_path = ROOT / "models" / "model_meta.json"
    if meta_path.exists():
        try:
            import json

            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            last_retrain = meta.get("last_retrain")
            cv_accuracy = meta.get("cv_accuracy_mean")
        except Exception:
            pass

    return {
        "total_samples_learned": total,
        "new_threats_collected": threats,
        "last_retrain_time": last_retrain,
        "model_accuracy": cv_accuracy,
        "new_samples_path": str(NEW_SAMPLES_PATH),
    }
