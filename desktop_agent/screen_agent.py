import argparse
import re
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import mss
import pytesseract
import requests
from PIL import Image, ImageEnhance, ImageFilter

# Desktop OCR: slightly lower bar so borderline model scores still flag (OCR often garbles URLs).
DESKTOP_PHISH_CONFIDENCE = 0.42
DESKTOP_UNCERTAIN_PHISH = 0.55
MAX_URLS_TO_ANALYZE = 36
MAX_BROWSER_WINDOWS = 3
MIN_BROWSER_WIDTH = 320
MIN_BROWSER_HEIGHT = 240

CAPTURE_MODE_BROWSER = "browser"
CAPTURE_MODE_FOREGROUND = "foreground"
CAPTURE_MODE_ALL = "all"
CAPTURE_MODES = (CAPTURE_MODE_BROWSER, CAPTURE_MODE_FOREGROUND, CAPTURE_MODE_ALL)

# Chromium-based browsers share this class on Windows.
BROWSER_WINDOW_CLASSES = frozenset(
    {
        "Chrome_WidgetWin_1",  # Chrome, Edge, Brave, Opera, Vivaldi
        "MozillaWindowClass",  # Firefox
    }
)

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


@dataclass
class BrowserWindowInfo:
    hwnd: int
    title: str
    window_class: str
    left: int
    top: int
    width: int
    height: int


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
    """Upscale and boost contrast — helps small UI text in browser chrome and pages."""
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


def _is_browser_class(class_name: str) -> bool:
    return class_name in BROWSER_WINDOW_CLASSES


def list_browser_windows(foreground_only: bool = False) -> List[BrowserWindowInfo]:
    """Return visible browser windows (Windows only). Empty on other OS."""
    if sys.platform != "win32":
        return []

    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    found: List[BrowserWindowInfo] = []
    foreground_hwnd = user32.GetForegroundWindow()

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def callback(hwnd, _lparam):
        if not user32.IsWindowVisible(hwnd):
            return True
        if foreground_only and hwnd != foreground_hwnd:
            return True

        class_buf = ctypes.create_unicode_buffer(256)
        if user32.GetClassNameW(hwnd, class_buf, 256) == 0:
            return True
        if not _is_browser_class(class_buf.value):
            return True

        title_buf = ctypes.create_unicode_buffer(512)
        user32.GetWindowTextW(hwnd, title_buf, 512)
        title = title_buf.value.strip()
        if not title:
            return True

        rect = wintypes.RECT()
        if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
            return True
        width = rect.right - rect.left
        height = rect.bottom - rect.top
        if width < MIN_BROWSER_WIDTH or height < MIN_BROWSER_HEIGHT:
            return True

        found.append(
            BrowserWindowInfo(
                hwnd=int(hwnd),
                title=title,
                window_class=class_buf.value,
                left=int(rect.left),
                top=int(rect.top),
                width=int(width),
                height=int(height),
            )
        )
        return True

    user32.EnumWindows(callback, 0)

    # Largest windows first; dedupe identical geometry (rare).
    found.sort(key=lambda w: w.width * w.height, reverse=True)
    unique: List[BrowserWindowInfo] = []
    seen_rects = set()
    for win in found:
        key = (win.left, win.top, win.width, win.height)
        if key in seen_rects:
            continue
        seen_rects.add(key)
        unique.append(win)
    return unique


def _grab_region(sct: mss.mss, left: int, top: int, width: int, height: int) -> Image.Image:
    shot = sct.grab({"left": left, "top": top, "width": width, "height": height})
    return Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")


def capture_screen_rgb_images(sct: mss.mss, monitor_index: int) -> Tuple[List[Image.Image], int]:
    """
    Full-monitor capture (legacy).
    monitor_index 0 = every physical monitor; >= 1 = that monitor only.
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


def capture_browser_rgb_images(
    sct: mss.mss,
    *,
    foreground_only: bool,
) -> Tuple[List[Image.Image], List[BrowserWindowInfo]]:
    windows = list_browser_windows(foreground_only=foreground_only)
    if not windows:
        return [], []

    images: List[Image.Image] = []
    selected: List[BrowserWindowInfo] = []
    for win in windows[:MAX_BROWSER_WINDOWS]:
        try:
            images.append(_grab_region(sct, win.left, win.top, win.width, win.height))
            selected.append(win)
        except Exception:
            continue
    return images, selected


def capture_for_ocr(
    sct: mss.mss,
    *,
    capture_mode: str = CAPTURE_MODE_BROWSER,
    monitor_index: int = 0,
    fallback_all: bool = True,
) -> Tuple[List[Image.Image], Dict]:
    """
    capture_mode:
      - browser: all visible Chrome/Edge/Firefox windows (default)
      - foreground: active window only if it is a browser
      - all: legacy full-monitor capture
    """
    mode = capture_mode if capture_mode in CAPTURE_MODES else CAPTURE_MODE_BROWSER
    meta: Dict = {"capture_mode": mode, "capture_source": mode, "browser_windows": []}

    if mode == CAPTURE_MODE_ALL:
        images, n_mon = capture_screen_rgb_images(sct, monitor_index)
        meta["monitors_scanned"] = n_mon
        meta["windows_captured"] = len(images)
        return images, meta

    if sys.platform != "win32":
        meta["capture_source"] = "fallback_monitors"
        meta["warning"] = "Browser capture requires Windows; using all monitors."
        images, n_mon = capture_screen_rgb_images(sct, monitor_index)
        meta["monitors_scanned"] = n_mon
        meta["windows_captured"] = len(images)
        return images, meta

    foreground_only = mode == CAPTURE_MODE_FOREGROUND
    images, windows = capture_browser_rgb_images(sct, foreground_only=foreground_only)
    meta["browser_windows"] = [w.title for w in windows]

    if images:
        meta["windows_captured"] = len(images)
        return images, meta

    if fallback_all:
        meta["capture_source"] = "fallback_monitors"
        meta["warning"] = (
            "No browser window found"
            + (" (foreground is not a browser)." if foreground_only else ".")
            + " Falling back to all monitors."
        )
        images, n_mon = capture_screen_rgb_images(sct, monitor_index)
        meta["monitors_scanned"] = n_mon
        meta["windows_captured"] = len(images)
        return images, meta

    meta["capture_source"] = "none"
    meta["warning"] = (
        "No browser window found"
        + (" (foreground is not a browser)." if foreground_only else ".")
        + " Focus a browser or use --capture-mode all."
    )
    meta["windows_captured"] = 0
    return [], meta


def _url_result_is_risky(data: dict) -> bool:
    if data.get("prediction") == "phishing" and float(data.get("confidence", 0)) >= DESKTOP_PHISH_CONFIDENCE:
        return True
    try:
        p = float(data.get("p_phishing", 0))
        return p >= DESKTOP_UNCERTAIN_PHISH
    except (TypeError, ValueError):
        return False


def capture_and_analyze(
    api_base: str,
    monitor_index: int = 0,
    capture_mode: str = CAPTURE_MODE_BROWSER,
    fallback_all: bool = True,
    debug: bool = False,
):
    """OCR browser windows (default) or full screen, then analyze via FastAPI."""
    with mss.mss() as sct:
        rgb_images, capture_meta = capture_for_ocr(
            sct,
            capture_mode=capture_mode,
            monitor_index=monitor_index,
            fallback_all=fallback_all,
        )

    ocr_parts: List[str] = []
    for rgb in rgb_images:
        prepared = prepare_image_for_ocr(rgb)
        ocr_parts.append(ocr_image_multipass(prepared))

    text = normalize_ocr_text("\n\n".join(ocr_parts))
    if debug:
        preview = (text or "").replace("\n", " ")[:900]
        print("[debug] capture:", capture_meta)
        print("[debug] OCR preview:", repr(preview))
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
        "uncertain": uncertain,
        "suspicious_fragment": suspicious_fragment,
        **capture_meta,
    }
    if capture_meta.get("monitors_scanned") is not None:
        result["ocr_meta"]["monitors_scanned"] = capture_meta["monitors_scanned"]
    elif capture_meta.get("windows_captured") is not None:
        result["ocr_meta"]["windows_captured"] = capture_meta["windows_captured"]

    if suspicious_fragment and result.get("risk_level") == "LOW":
        er = result["email_result"]
        ec = float(er.get("confidence", 0))
        if er.get("prediction") == "phishing" and ec >= 0.35:
            result["risk_level"] = "MEDIUM"
        elif er.get("prediction") == "safe" and ec < 0.55:
            result["risk_level"] = "MEDIUM"
            result["ocr_caution"] = (
                "OCR sees link-like fragments but may have misread URLs. "
                "Maximize the browser window or paste the link into the web analyzer."
            )

    if capture_meta.get("warning") and result.get("risk_level") == "LOW" and not text.strip():
        result["ocr_caution"] = capture_meta["warning"]

    return text, urls, result


def analyze_with_backend(api_base: str, urls: List[str], text: str):
    risky_urls: List[str] = []
    url_results: List[dict] = []
    headers = {"Content-Type": "application/json", "X-Fast-Scan": "1"}
    for url in urls[:MAX_URLS_TO_ANALYZE]:
        try:
            resp = requests.post(
                f"{api_base.rstrip('/')}/analyze/url",
                json={"url": url},
                headers=headers,
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            url_results.append(
                {"url": url, "prediction": data["prediction"], "confidence": data["confidence"]}
            )
            if _url_result_is_risky(data) and url not in risky_urls:
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

    email_phish = email_result.get("prediction") == "phishing"
    try:
        if float(email_result.get("p_phishing", 0)) >= DESKTOP_UNCERTAIN_PHISH:
            email_phish = True
    except (TypeError, ValueError):
        pass

    risk_level = "LOW"
    if len(risky_urls) > 5 or email_phish:
        risk_level = "HIGH"
    elif risky_urls:
        risk_level = "MEDIUM"
    elif email_phish and float(email_result.get("confidence", 0)) >= 0.4:
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
    print(
        "Email/Text Signal:",
        result["email_result"].get("prediction"),
        f"({result['email_result'].get('confidence', 0):.2f})",
    )
    meta = result.get("ocr_meta") or {}
    if meta:
        mode = meta.get("capture_mode", "?")
        if meta.get("browser_windows"):
            print("Browser windows:", "; ".join(meta["browser_windows"][:3]))
            if len(meta["browser_windows"]) > 3:
                print(f"  ... +{len(meta['browser_windows']) - 3} more")
        elif meta.get("monitors_scanned"):
            print(f"Monitors scanned: {meta.get('monitors_scanned')}")
        print(f"Capture: {mode} | {meta.get('url_count', 0)} URL(s) | {meta.get('text_length', 0)} OCR chars")
        if meta.get("warning"):
            print("Note:", meta["warning"])
        if meta.get("uncertain"):
            print("Note: OCR uncertain — few URLs read; zoom the browser or use the web analyzer.")
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
        "--capture-mode",
        choices=CAPTURE_MODES,
        default=CAPTURE_MODE_BROWSER,
        help="browser=all browser windows (default), foreground=active browser only, all=full monitors",
    )
    parser.add_argument(
        "--no-fallback-all",
        action="store_true",
        help="When no browser is found, do not fall back to scanning all monitors",
    )
    parser.add_argument(
        "--monitor",
        type=int,
        default=0,
        help="mss monitor index for --capture-mode all (or fallback): 0=all, 1=primary, 2+=other",
    )
    parser.add_argument("--debug", action="store_true", help="Print OCR text preview to stdout")
    args = parser.parse_args()

    print(f"Desktop agent: capture-mode={args.capture_mode} (browser OCR for phishing in web pages).")
    if sys.platform != "win32" and args.capture_mode != CAPTURE_MODE_ALL:
        print("Note: browser window capture needs Windows; will use all monitors.")
    print("Press Ctrl+C to stop.\n")

    while True:
        try:
            _, urls, result = capture_and_analyze(
                args.api_base,
                monitor_index=args.monitor,
                capture_mode=args.capture_mode,
                fallback_all=not args.no_fallback_all,
                debug=args.debug,
            )
            print("URLs detected:", len(urls))
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
