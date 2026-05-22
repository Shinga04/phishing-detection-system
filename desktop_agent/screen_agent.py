import argparse
import re
import time
from typing import List, Tuple
from urllib.parse import urlparse

import mss
import pytesseract
import requests
from PIL import Image, ImageEnhance, ImageFilter

# Desktop OCR: slightly lower bar so borderline model scores still flag (OCR often garbles URLs).
DESKTOP_PHISH_CONFIDENCE = 0.42
MAX_URLS_TO_ANALYZE = 36

# Multiple patterns: full URLs, www, shorteners, bare domain.tld (+ optional path)
_SHORTENER = (
    r"bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|rebrand\.ly|"
    r"cutt\.ly|short\.link|rb\.gy|shorturl\.at|tiny\.cc|shorte\.st|adf\.ly|bc\.vc|"
    r"page\.link|qr\.ae|dis\.goo\.gl|vm\.tl|me\.se|tiny\.one|yourls\.org|cli\.gs|"
    r"wa\.me|chat\.whatsapp\.com|api\.whatsapp\.com"
)
URL_PATTERNS = [
    re.compile(r"https?://[^\s\]\)\}<>,\"']+", re.IGNORECASE),
    re.compile(r"www\.[^\s\]\)\}<>,\"']+", re.IGNORECASE),
    re.compile(rf"\b(?:{_SHORTENER})/[^\s\]\)\}}<>,\"']+", re.IGNORECASE),
    re.compile(
        r"\b(?=[a-z0-9./]*[a-z])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"(?:xn--[a-z0-9-]+|[a-z]{2,63})\b(?:/[^\s\]\)\}}<>,\"']*)?",
        re.IGNORECASE,
    ),
]

OCR_CONFIGS = [
    "--oem 3 --psm 6",  # uniform block of text
    "--oem 3 --psm 11",  # sparse text — chat apps, toolbars
    "--oem 3 --psm 3",  # fully automatic segmentation
]


def _strip_trailing_junk(s: str) -> str:
    return s.strip().rstrip(".,;:!?)\"'»«\\]}")


def repair_url_candidate(raw: str) -> str:
    u = raw.strip()
    u = re.sub(r"\s+", "", u)
    u = re.sub(r"^hxxp(s?)://", r"http\1://", u, flags=re.IGNORECASE)
    u = re.sub(r"^https?:/([^/])", r"https://\1", u, flags=re.IGNORECASE)
    return u


def normalize_ocr_text(text: str) -> str:
    if not text:
        return ""
    t = text
    t = re.sub(r"https?\s*:\s*/\s*/\s*", "https://", t, flags=re.IGNORECASE)
    t = re.sub(r"https?\s*:\s*/\s*([a-zA-Z0-9])", r"https://\1", t, flags=re.IGNORECASE)
    t = re.sub(r"[\u200b\u200c\u200d\ufeff]", "", t)
    t = re.sub(r"(?i)(www\.)\s+", r"\1", t)
    return t


def _hostname_for_filter(value: str) -> str:
    v = value
    if not v.lower().startswith(("http://", "https://")):
        v = "http://" + v.lstrip("/")
    try:
        return (urlparse(v).hostname or "").lower()
    except Exception:
        return ""


def extract_urls(text: str) -> List[str]:
    if not text:
        return []
    text = normalize_ocr_text(text)
    seen = set()
    normalized: List[str] = []
    for pat in URL_PATTERNS:
        for m in pat.finditer(text):
            raw = _strip_trailing_junk(repair_url_candidate(m.group(0)))
            if not raw or len(raw) < 4:
                continue
            value = raw
            if not value.lower().startswith(("http://", "https://")):
                value = "http://" + value.lstrip("/")
            host = _hostname_for_filter(value)
            if not host:
                continue
            labels = [p for p in host.split(".") if p]
            if labels and all(l.isdigit() for l in labels):
                continue
            if value not in seen:
                seen.add(value)
                normalized.append(value)
    return sorted(normalized)


def prepare_image_for_ocr(img: Image.Image) -> Image.Image:
    """Upscale and boost contrast — helps small UI text (e.g. WhatsApp Desktop)."""
    w, h = img.size
    max_side = max(w, h)
    factor = 2
    if max_side < 1600:
        factor = 2
    if max_side < 1100:
        factor = 3
    if max_side < 800:
        factor = 4
    img = img.resize((w * factor, h * factor), Image.Resampling.LANCZOS)
    gray = img.convert("L")
    gray = ImageEnhance.Contrast(gray).enhance(1.45)
    gray = ImageEnhance.Sharpness(gray).enhance(1.15)
    gray = gray.filter(ImageFilter.SHARPEN)
    return gray


def ocr_image_multipass(prepared: Image.Image) -> str:
    chunks: List[str] = []
    for cfg in OCR_CONFIGS:
        try:
            chunk = pytesseract.image_to_string(prepared, config=cfg)
            if chunk and len(chunk.strip()) > 8:
                chunks.append(chunk)
        except Exception:
            continue
    return "\n\n".join(chunks)


def capture_screen_rgb_images(sct: mss.mss, monitor_index: int) -> Tuple[List[Image.Image], int]:
    """
    Returns (images, monitors_scanned).
    monitor_index 0 = every physical monitor stitched as separate crops (true multi-screen).
    monitor_index >= 1 = that monitor only.
    """
    monitors = sct.monitors
    if monitor_index > 0:
        idx = monitor_index if monitor_index < len(monitors) else 1
        shot = sct.grab(monitors[idx])
        img = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
        return [img], 1

    images: List[Image.Image] = []
    for i in range(1, len(monitors)):
        shot = sct.grab(monitors[i])
        images.append(Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX"))
    if not images:
        shot = sct.grab(monitors[1])
        images.append(Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX"))
    return images, len(images)


def capture_and_analyze(api_base: str, monitor_index: int = 0, debug: bool = False):
    """
    Captures all connected displays when monitor_index=0, runs multi-pass OCR on each,
    merges text and URL lists, then calls the backend.
    """
    with mss.mss() as sct:
        rgb_images, n_mon = capture_screen_rgb_images(sct, monitor_index)

    ocr_parts: List[str] = []
    for rgb in rgb_images:
        prepared = prepare_image_for_ocr(rgb)
        ocr_parts.append(ocr_image_multipass(prepared))

    text = normalize_ocr_text("\n\n".join(ocr_parts))
    if debug:
        preview = (text or "").replace("\n", " ")[:900]
        print("[debug] monitors:", n_mon, "| OCR preview:", repr(preview))
        if len(text or "") > 900:
            print(f"[debug] ... ({len(text)} chars total)")

    urls = extract_urls(text)
    if debug and urls:
        print("[debug] URLs:", urls)

    result = analyze_with_backend(api_base, urls, text)
    uncertain = len(urls) < 2 and len(text) > 650
    suspicious_fragment = bool(
        uncertain and re.search(r"(?:https?\s*:|www\.|\.com|\.ru|\.tk|bit\.ly|tinyurl)", text, re.I)
    )
    result["ocr_meta"] = {
        "text_length": len(text),
        "url_count": len(urls),
        "monitors_scanned": n_mon,
        "uncertain": uncertain,
        "suspicious_fragment": suspicious_fragment,
    }
    if suspicious_fragment and result.get("risk_level") == "LOW":
        er = result["email_result"]
        ec = float(er.get("confidence", 0))
        if er.get("prediction") == "phishing" and ec >= 0.35:
            result["risk_level"] = "MEDIUM"
        elif er.get("prediction") == "safe" and ec < 0.55:
            result["risk_level"] = "MEDIUM"
            result["ocr_caution"] = (
                "OCR sees link-like fragments but may have misread URLs. "
                "Maximize the chat window, increase text size, or paste the link into the web analyzer."
            )

    return text, urls, result


def analyze_with_backend(api_base: str, urls: List[str], text: str):
    risky_urls: List[str] = []
    url_results: List[dict] = []
    for url in urls[:MAX_URLS_TO_ANALYZE]:
        try:
            resp = requests.post(f"{api_base.rstrip('/')}/analyze/url", json={"url": url}, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            url_results.append(
                {"url": url, "prediction": data["prediction"], "confidence": data["confidence"]}
            )
            if data["prediction"] == "phishing" and data["confidence"] >= DESKTOP_PHISH_CONFIDENCE:
                risky_urls.append(url)
        except Exception:
            continue

    email_result = {"prediction": "safe", "confidence": 0.0}
    try:
        resp = requests.post(
            f"{api_base.rstrip('/')}/analyze/email",
            json={"email_text": (text or "")[:7000]},
            timeout=12,
        )
        resp.raise_for_status()
        email_result = resp.json()
    except Exception:
        pass

    risk_level = "LOW"
    if len(risky_urls) > 5 or email_result.get("prediction") == "phishing":
        risk_level = "HIGH"
    elif risky_urls:
        risk_level = "MEDIUM"
    elif email_result.get("prediction") == "phishing" and float(email_result.get("confidence", 0)) >= 0.4:
        risk_level = "MEDIUM"

    return {
        "risk_level": risk_level,
        "risky_urls": risky_urls,
        "url_results": url_results,
        "email_result": email_result,
    }


def print_report(result: dict) -> None:
    print("\n===== Desktop Phishing Scan Report =====")
    print("Risk Level:", result["risk_level"])
    print("Risky URLs:", len(result["risky_urls"]))
    print("Email/Text Signal:", result["email_result"].get("prediction"), f"({result['email_result'].get('confidence', 0):.2f})")
    meta = result.get("ocr_meta") or {}
    if meta:
        print(
            f"OCR: {meta.get('monitors_scanned', '?')} monitor(s), "
            f"{meta.get('url_count', 0)} URL(s), {meta.get('text_length', 0)} chars"
        )
        if meta.get("uncertain"):
            print("Note: OCR uncertain — few URLs read; zoom app UI or use web analyzer for exact links.")
    if result.get("ocr_caution"):
        print("Caution:", result["ocr_caution"])
    if result["risky_urls"]:
        print("\nPotentially risky URLs:")
        for value in result["risky_urls"]:
            print("-", value)
    print("========================================\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Local desktop phishing scanner (OCR + FastAPI backend).")
    parser.add_argument("--api-base", default="http://127.0.0.1:8000", help="FastAPI base URL")
    parser.add_argument("--interval", type=int, default=0, help="Repeat scan interval in seconds. 0 = run once")
    parser.add_argument(
        "--monitor",
        type=int,
        default=0,
        help="mss monitor index: 0 = all displays (default), 1 = primary only, 2+ = other monitors",
    )
    parser.add_argument("--debug", action="store_true", help="Print OCR text preview to stdout")
    args = parser.parse_args()

    print("Desktop agent: multi-monitor capture + multi-pass OCR when --monitor 0.")
    print("Press Ctrl+C to stop.\n")

    while True:
        try:
            _, urls, result = capture_and_analyze(
                args.api_base, monitor_index=args.monitor, debug=args.debug
            )
            print("URLs detected on screen:", len(urls))
            print_report(result)
        except KeyboardInterrupt:
            print("Stopped by user.")
            break
        except Exception as exc:
            print("Scan error:", exc)

        if args.interval <= 0:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
