from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
import json
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier, VotingClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from feature_engineering import FEATURE_ORDER, combine_feature_vectors


ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
MODELS_DIR = ROOT / "models"
MODEL_PATH = MODELS_DIR / "phishing_model.pkl"
SCALER_PATH = MODELS_DIR / "phishing_scaler.pkl"
TRAIN_FEATURES_PATH = MODELS_DIR / "train_features.npy"
META_PATH = MODELS_DIR / "model_meta.json"

# Bump this when feature extraction or training procedure changes enough to require retrain.
FEATURES_VERSION = 4


def _find_csv_dataset() -> Optional[Path]:
    csv_files = list(DATA_DIR.glob("*.csv"))
    return csv_files[0] if csv_files else None


NEW_SAMPLES_FILENAME = "new_samples.csv"


def _find_csv_datasets() -> List[Path]:
    # Semi-incremental buffer is merged only during explicit retrain (see train_and_save).
    return sorted(
        p for p in DATA_DIR.glob("*.csv") if p.name.lower() != NEW_SAMPLES_FILENAME
    )


def _generate_fallback_data(rows: int = 2000):
    rng = np.random.default_rng(42)
    X = rng.normal(0, 1, size=(rows, len(FEATURE_ORDER)))
    X[:, FEATURE_ORDER.index("url_length")] = rng.integers(10, 220, size=rows)
    X[:, FEATURE_ORDER.index("num_dots")] = rng.integers(1, 8, size=rows)
    X[:, FEATURE_ORDER.index("has_ip")] = rng.integers(0, 2, size=rows)
    X[:, FEATURE_ORDER.index("num_special_chars")] = rng.integers(0, 16, size=rows)
    X[:, FEATURE_ORDER.index("uses_https")] = rng.integers(0, 2, size=rows)
    X[:, FEATURE_ORDER.index("domain_age")] = rng.integers(0, 5000, size=rows)
    X[:, FEATURE_ORDER.index("has_login_keyword")] = rng.integers(0, 2, size=rows)
    X[:, FEATURE_ORDER.index("ssl_valid")] = rng.integers(0, 2, size=rows)
    X[:, FEATURE_ORDER.index("ssl_self_signed")] = rng.integers(0, 2, size=rows)
    X[:, FEATURE_ORDER.index("ssl_expiry_days")] = rng.integers(-1, 800, size=rows)
    X[:, FEATURE_ORDER.index("ssl_issuer_len")] = rng.integers(5, 120, size=rows)
    X[:, FEATURE_ORDER.index("email_text_length")] = rng.integers(20, 5000, size=rows)
    X[:, FEATURE_ORDER.index("email_num_links")] = rng.integers(0, 15, size=rows)
    X[:, FEATURE_ORDER.index("email_suspicious_keywords")] = rng.integers(0, 10, size=rows)
    X[:, FEATURE_ORDER.index("email_has_spoofed_tld")] = rng.integers(0, 2, size=rows)

    y = (
        (X[:, FEATURE_ORDER.index("has_ip")] > 0)
        | (X[:, FEATURE_ORDER.index("has_login_keyword")] > 0)
        | (X[:, FEATURE_ORDER.index("email_suspicious_keywords")] >= 3)
        | (X[:, FEATURE_ORDER.index("ssl_self_signed")] > 0)
        | (X[:, FEATURE_ORDER.index("uses_https")] == 0)
    ).astype(int)
    return X, y


def _dedupe_feature_rows(X: np.ndarray, y: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """Drop duplicate feature vectors (poisoning / repeated submissions)."""
    if len(y) == 0:
        return X, y
    df = pd.DataFrame(X, columns=FEATURE_ORDER)
    df["label"] = y.astype(int)
    df = df.drop_duplicates(subset=FEATURE_ORDER + ["label"], keep="first")
    return df[FEATURE_ORDER].values.astype(float), df["label"].values.astype(int)


def _prepare_dataset(include_new_samples: bool = False):
    dataset_paths = _find_csv_datasets()
    if not dataset_paths:
        return _generate_fallback_data()

    alias_map = {
        "has_https": "uses_https",
        "https": "uses_https",
        "has_ssl": "ssl_valid",
        "ssl": "ssl_valid",
        "has_suspicious_words": "email_suspicious_keywords",
        "suspicious_words": "email_suspicious_keywords",
        "suspicious_keyword_count": "email_suspicious_keywords",
        "domain_age_days": "domain_age",
        "url_domain_age": "domain_age",
        "contains_login_keyword": "has_login_keyword",
        # Common source-dataset names / typos
        "url_len": "url_length",
        "web_ssl_valid": "web_ssl_valid",
        "web_has_login": "web_has_login",
        "web_security_score": "web_security_score",
        "web_is_live": "web_is_live",
        "web_forms_count": "web_forms_count",
        "web_froms_count": "web_forms_count",
        "web_passwordfields": "web_passwordfields",
        "shortening_services": "shortening_services",
        "having_ip_address": "has_ip",
        "has_ip_flag": "has_ip",
        "abnormal_url": "abnormal_url",
        "abnormal url": "abnormal_url",
        "phish_in_brand_in_path": "phish_brand_in_path",
        "enh_subdomai_count": "enh_subdomain_count",
        "defa _has_option_param": "defac_has_option_param",
        # Symbol-derived dataset headers
        "@": "count_at",
        "?": "count_qmark",
        "_": "count_underscore",
        "=": "count_equal",
        ".": "count_dot",
        "#": "count_hash",
        "%": "count_percent",
        "+": "count_plus",
        "$": "count_dollar",
        "!": "count_exclam",
        "*": "count_star",
        "//": "count_dslash",
        "digits": "digit_count",
        "letter": "letter_count",
    }

    default_values = {
        "ssl_self_signed": 0,
        "ssl_expiry_days": 0,
        "ssl_issuer_len": 0,
        "email_text_length": 0,
        "email_num_links": 0,
        "email_has_spoofed_tld": 0,
    }

    x_frames = []
    y_frames = []

    def _parse_label_value(val):
        if pd.isna(val):
            return np.nan
        s = str(val).strip().lower()
        if s in {"1", "phishing", "true", "yes", "malicious", "fraud", "spam"}:
            return 1
        if s in {"0", "safe", "false", "no", "legit", "benign", "ham"}:
            return 0
        try:
            # Handles numeric strings like "0.0" too.
            return int(float(s))
        except Exception:
            return np.nan

    RAW_EMAIL_COLS = {"sender", "receiver", "date", "subject", "body", "urls"}

    def _normalize_column_name(col: str) -> str:
        c = str(col).strip().lower()
        c = c.replace("\u200b", "")
        c = c.replace(" ", "_")
        c = c.replace("-", "_")
        c = c.replace("__", "_")
        return c

    for dataset_path in dataset_paths:
        df = pd.read_csv(dataset_path)
        df.columns = [_normalize_column_name(c) for c in df.columns]

        if "label" not in df.columns:
            continue

        # If the CSV is "raw email" format (sender/receiver/date/subject/body/urls/label),
        # convert each row into a text blob and derive numeric features with feature_engineering.
        if RAW_EMAIL_COLS.issubset(set(df.columns)):
            current_y = df["label"].apply(_parse_label_value)
            valid_idx = current_y.isin([0, 1])
            if valid_idx.any():
                df_valid = df.loc[valid_idx].reset_index(drop=True)
                features_rows = []
                for _, row in df_valid.iterrows():
                    sender = str(row.get("sender", "") or "").strip()
                    receiver = str(row.get("receiver", "") or "").strip()
                    date = str(row.get("date", "") or "").strip()
                    subject = str(row.get("subject", "") or "").strip()
                    body = str(row.get("body", "") or "").strip()
                    urls_flag = row.get("urls", 0)
                    urls_present = str(urls_flag).strip() in {"1", "true", "yes"}
                    # Ensure headers exist for sender/domain parsing:
                    email_text = "\n".join(
                        [
                            f"From: {sender}",
                            f"To: {receiver}",
                            f"Date: {date}",
                            f"Subject: {subject}",
                            "",
                            body,
                            "",
                            urls_present and "URLs: https://example.com" or "",
                        ]
                    ).strip()
                    feat = combine_feature_vectors(url="", email_text=email_text)
                    features_rows.append([feat.get(f, 0) for f in FEATURE_ORDER])

                current_x = pd.DataFrame(features_rows, columns=FEATURE_ORDER).astype(float)
                x_frames.append(current_x.reset_index(drop=True))
                y_frames.append(current_y.loc[valid_idx].astype(int).reset_index(drop=True))
            continue

        # Otherwise: assume the CSV contains numeric feature columns (possibly with aliases).
        for source_col, target_col in alias_map.items():
            if source_col in df.columns and target_col not in df.columns:
                df[target_col] = df[source_col]

        current_x = pd.DataFrame()
        for feature in FEATURE_ORDER:
            current_x[feature] = df[feature] if feature in df.columns else default_values.get(feature, 0)

        current_x = current_x.apply(pd.to_numeric, errors="coerce").fillna(0)
        current_y = df["label"].apply(_parse_label_value)

        valid_idx = current_y.isin([0, 1])
        if valid_idx.any():
            x_frames.append(current_x.loc[valid_idx].reset_index(drop=True))
            y_frames.append(current_y.loc[valid_idx].astype(int).reset_index(drop=True))

    if not x_frames:
        raise ValueError("No valid labeled rows found. Ensure at least one CSV has label values 0/1.")

    X_df = pd.concat(x_frames, ignore_index=True)
    y = pd.concat(y_frames, ignore_index=True).values

    if include_new_samples:
        from sample_store import load_new_samples_matrix

        nx, ny = load_new_samples_matrix()
        if nx is not None and ny is not None and len(ny) > 0:
            X_df = pd.concat(
                [X_df, pd.DataFrame(nx, columns=FEATURE_ORDER)],
                ignore_index=True,
            )
            y = np.concatenate([y, ny])

    X, y = X_df.values.astype(float), y
    X, y = _dedupe_feature_rows(X, y)

    if len(np.unique(y)) < 2:
        raise ValueError("Training requires both classes (0=safe and 1=phishing) in the dataset.")

    return X, y


def _make_classifier_pipeline() -> Pipeline:
    rf = RandomForestClassifier(n_estimators=300, random_state=42, class_weight="balanced")
    gb = GradientBoostingClassifier(random_state=42)
    ensemble = VotingClassifier(
        estimators=[("rf", rf), ("gb", gb)],
        voting="soft",
    )
    return Pipeline(
        [
            ("scaler", StandardScaler()),
            ("clf", ensemble),
        ]
    )


def _stratified_cv_splits(y: np.ndarray, max_splits: int = 10) -> int:
    """StratifiedKFold needs at least n_splits samples in each class."""
    counts = np.bincount(y.astype(int))
    if len(counts) < 2 or counts.min() < 2:
        return 0
    return int(min(max_splits, counts.min()))


def train_and_save(include_new_samples: bool = False, record_retrain: bool = False):
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    X, y = _prepare_dataset(include_new_samples=include_new_samples)
    n_safe = int((y == 0).sum())
    n_phish = int((y == 1).sum())
    print(f"[training] rows={len(y)} safe={n_safe} phishing={n_phish}")

    n_splits = _stratified_cv_splits(y, max_splits=10)
    cv_scores = None
    if n_splits >= 2:
        pipe = _make_classifier_pipeline()
        cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
        cv_scores = cross_val_score(
            pipe,
            X,
            y,
            cv=cv,
            scoring="accuracy",
            n_jobs=-1,
        )
        print(
            f"[cv] stratified {n_splits}-fold accuracy: "
            f"mean={cv_scores.mean():.4f} std={cv_scores.std():.4f} "
            f"folds={list(np.round(cv_scores, 4))}"
        )
    else:
        print("[cv] skipped (need at least 2 samples per class for k-fold)")

    # Final model: fit scaler + ensemble on all labeled data (standard after CV reporting).
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    rf = RandomForestClassifier(n_estimators=300, random_state=42, class_weight="balanced")
    gb = GradientBoostingClassifier(random_state=42)
    ensemble = VotingClassifier(
        estimators=[("rf", rf), ("gb", gb)],
        voting="soft",
    )
    ensemble.fit(X_scaled, y)

    joblib.dump(ensemble, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    np.save(TRAIN_FEATURES_PATH, X_scaled)
    learned_stats = {}
    if include_new_samples or record_retrain:
        try:
            from sample_store import get_learning_stats

            learned_stats = get_learning_stats()
        except Exception:
            pass

    meta = {
        "features_version": FEATURES_VERSION,
        "feature_order": FEATURE_ORDER,
        "cv_n_splits": n_splits,
        "cv_accuracy_mean": float(cv_scores.mean()) if cv_scores is not None else None,
        "cv_accuracy_std": float(cv_scores.std()) if cv_scores is not None else None,
        "cv_accuracy_folds": [float(x) for x in cv_scores] if cv_scores is not None else None,
        "last_retrain": (
            datetime.now(timezone.utc).replace(microsecond=0).isoformat() if record_retrain else None
        ),
        "total_samples_learned": learned_stats.get("total_samples_learned"),
        "new_threats_collected": learned_stats.get("new_threats_collected"),
    }
    try:
        META_PATH.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    except Exception:
        pass


def load_model_bundle():
    """
    Load model artifacts from disk.

    If artifacts are missing or incompatible with the current environment
    (common when scikit-learn versions differ), this will retrain and overwrite
    the bundle automatically so the API can still start.
    """
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    def _meta_ok() -> bool:
        try:
            if not META_PATH.exists():
                return False
            meta = json.loads(META_PATH.read_text(encoding="utf-8"))
            if int(meta.get("features_version", 0)) != FEATURES_VERSION:
                return False
            # Guard against old artifacts with mismatched feature order.
            if list(meta.get("feature_order") or []) != list(FEATURE_ORDER):
                return False
            return True
        except Exception:
            return False

    if (
        not MODEL_PATH.exists()
        or not SCALER_PATH.exists()
        or not TRAIN_FEATURES_PATH.exists()
        or not _meta_ok()
    ):
        train_and_save()

    try:
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        train_features = np.load(TRAIN_FEATURES_PATH)
        return model, scaler, train_features
    except Exception as exc:
        print(f"[model] Failed to load model bundle ({type(exc).__name__}: {exc}). Retraining...")
        train_and_save()
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        train_features = np.load(TRAIN_FEATURES_PATH)
        return model, scaler, train_features
