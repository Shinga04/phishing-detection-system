"""
Local GUI for the desktop phishing scanner (OCR + FastAPI).
Extension-style status orb on the bottom-left (opposite the browser extension FAB).

Run: python gui_agent.py
Orb only (no main window): python gui_agent.py --orb-only
"""

import argparse
import threading
from typing import Any, Callable, Optional, Tuple

import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from urllib.parse import urljoin

import requests

from screen_agent import (
    CAPTURE_MODE_ALL,
    CAPTURE_MODE_BROWSER,
    CAPTURE_MODE_FOREGROUND,
    capture_and_analyze,
)

# Match extension FAB (content.js) — shared palette
ORB_SIZE = 46
ORB_MARGIN_X = 22
ORB_MARGIN_BOTTOM = 22
ORB_ICONS = {
    "idle": "•",
    "scanning": "…",
    "safe": "✓",
    "warn": "!",
    "unsafe": "!",
    "offline": "?",
}
ORB_COLORS = {
    "idle": "#64748b",
    "scanning": "#ca8a04",
    "safe": "#16a34a",
    "warn": "#ea580c",
    "unsafe": "#dc2626",
    "offline": "#d97706",
    "error": "#7c3aed",
}
TOAST_VARIANTS = {
    "ok": {"bg": "#f0fdf4", "fg": "#166534"},
    "warn": {"bg": "#fef2f2", "fg": "#991b1b"},
    "offline": {"bg": "#fffbeb", "fg": "#92400e"},
}


class OrbToast(tk.Toplevel):
    """Small message above the desktop orb (mirrors extension toast placement)."""

    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        self.overrideredirect(True)
        try:
            self.attributes("-topmost", True)
        except tk.TclError:
            pass

        self._label = tk.Label(
            self,
            text="",
            font=("Segoe UI", 10),
            wraplength=280,
            justify=tk.LEFT,
            padx=12,
            pady=10,
        )
        self._label.pack()
        self._hide_after: Optional[str] = None
        self.withdraw()

    def show(self, text: str, variant: str = "ok", ms: int = 4500) -> None:
        style = TOAST_VARIANTS.get(variant, TOAST_VARIANTS["ok"])
        self._label.configure(
            text=text,
            bg=style["bg"],
            fg=style["fg"],
        )
        self.configure(bg=style["bg"])
        self.update_idletasks()

        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        tw = max(self._label.winfo_reqwidth() + 24, 200)
        th = self._label.winfo_reqheight() + 20
        x = ORB_MARGIN_X
        y = sh - ORB_MARGIN_BOTTOM - ORB_SIZE - 12 - th
        self.geometry(f"{min(tw, 300)}x{th}+{x}+{max(8, y)}")
        self.deiconify()
        self.lift()

        if self._hide_after:
            try:
                self.after_cancel(self._hide_after)
            except tk.TclError:
                pass
        self._hide_after = self.after(ms, self.hide)

    def hide(self) -> None:
        self.withdraw()


class PhishGuardOrb(tk.Toplevel):
    """
    Extension-style floating FAB on the bottom-left of the screen.
    Chrome extension FAB sits bottom-right; this balances the layout in browser windows.
    """

    def __init__(self, master: tk.Misc, on_scan: Optional[Callable[[], None]] = None) -> None:
        super().__init__(master)
        self._on_scan = on_scan
        self._state = "idle"
        self._pulse_after: Optional[str] = None
        self._pulse_on = True

        self.overrideredirect(True)
        try:
            self.attributes("-topmost", True)
        except tk.TclError:
            pass
        try:
            self.attributes("-alpha", 0.96)
        except tk.TclError:
            pass

        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = ORB_MARGIN_X
        y = max(8, sh - ORB_SIZE - ORB_MARGIN_BOTTOM)
        self.geometry(f"{ORB_SIZE}x{ORB_SIZE}+{x}+{y}")

        self._canvas = tk.Canvas(
            self,
            width=ORB_SIZE,
            height=ORB_SIZE,
            highlightthickness=0,
            bg="#0f172a",
            cursor="hand2",
        )
        self._canvas.pack(fill=tk.BOTH, expand=True)

        pad = 5
        self._circle = self._canvas.create_oval(
            pad,
            pad,
            ORB_SIZE - pad,
            ORB_SIZE - pad,
            fill=ORB_COLORS["idle"],
            outline="#f8fafc",
            width=2,
        )
        self._icon = self._canvas.create_text(
            ORB_SIZE // 2,
            ORB_SIZE // 2,
            text=ORB_ICONS["idle"],
            fill="#ffffff",
            font=("Segoe UI", 11, "bold"),
        )

        self._canvas.bind("<Button-1>", self._handle_click)
        self._canvas.bind("<Button-3>", self._handle_right_click)

        self._toast = OrbToast(master)
        self.set_state("idle", show_message=False)

    def _handle_click(self, _event=None) -> None:
        if self._on_scan:
            self._on_scan()

    def _handle_right_click(self, _event=None) -> None:
        master = self.master
        if isinstance(master, tk.Tk):
            try:
                master.deiconify()
                master.lift()
                master.focus_force()
            except tk.TclError:
                pass

    def _stop_pulse(self) -> None:
        if self._pulse_after:
            try:
                self.after_cancel(self._pulse_after)
            except tk.TclError:
                pass
            self._pulse_after = None

    def _tick_pulse(self) -> None:
        if not self.winfo_exists():
            return
        fill = "#fbbf24" if self._pulse_on else ORB_COLORS["scanning"]
        self._pulse_on = not self._pulse_on
        self._canvas.itemconfigure(self._circle, fill=fill)
        self._pulse_after = self.after(450, self._tick_pulse)

    def set_state(self, state: str, message: Optional[str] = None, show_message: bool = True) -> None:
        self._state = state
        self._stop_pulse()
        fill = ORB_COLORS.get(state, ORB_COLORS["idle"])
        icon = ORB_ICONS.get(state, ORB_ICONS["idle"])
        self._canvas.itemconfigure(self._circle, fill=fill)
        self._canvas.itemconfigure(self._icon, text=icon)

        if state == "scanning":
            self._pulse_on = True
            self._tick_pulse()
        elif message and show_message:
            variant = "ok"
            if state in ("unsafe", "warn"):
                variant = "warn"
            elif state in ("offline", "error"):
                variant = "offline"
            self.show_toast(message, variant)

    def show_toast(self, text: str, variant: str = "ok", ms: int = 4500) -> None:
        self._toast.show(text, variant=variant, ms=ms)

    def destroy(self) -> None:
        self._stop_pulse()
        try:
            self._toast.destroy()
        except tk.TclError:
            pass
        super().destroy()


def check_backend(api_base: str) -> Tuple[bool, str]:
    base = api_base.rstrip("/") + "/"
    try:
        r = requests.get(urljoin(base, "health"), timeout=3)
        if r.status_code == 200:
            return True, "OK"
        return False, f"HTTP {r.status_code}"
    except requests.RequestException as exc:
        return False, str(exc)


def friendly_toast_for_result(result: dict, err: Optional[str] = None) -> Tuple[str, str, str]:
    """
    Returns (orb_state, toast_variant, message).
    orb_state: idle|scanning|safe|warn|unsafe|offline
    """
    if err:
        low = err.lower()
        if "connection" in low or "refused" in low or "timeout" in low or "127.0.0.1" in low:
            return (
                "offline",
                "offline",
                "Scanner offline — start the backend on port 8000.",
            )
        return ("error", "offline", f"Scan error: {err[:120]}")

    risk = (result.get("risk_level") or "LOW").upper()
    risky = result.get("risky_urls") or []
    email = result.get("email_result") or {}
    pred = email.get("prediction", "safe")
    n_risky = len(risky)

    caution = result.get("ocr_caution")
    if caution:
        if risk in ("HIGH", "MEDIUM") or n_risky:
            return "warn", "warn", caution[:200]
        return "warn", "warn", caution[:200]

    email_bad = pred == "phishing"
    if risk == "HIGH" or n_risky > 5:
        if email_bad and n_risky:
            return (
                "unsafe",
                "warn",
                f"High risk: suspicious text and {n_risky} risky link(s) in browser.",
            )
        if n_risky:
            return (
                "unsafe",
                "warn",
                f"High risk: {n_risky} suspicious link(s) found on screen.",
            )
        return "unsafe", "warn", "High risk: possible phishing detected."

    if risk == "MEDIUM" or n_risky > 0 or email_bad:
        if n_risky:
            return (
                "warn",
                "warn",
                f"Caution: {n_risky} link(s) may be phishing. Check before clicking.",
            )
        if email_bad:
            return "warn", "warn", "Caution: message text looks suspicious."
        return "warn", "warn", "Caution: possible phishing signals detected."

    meta = result.get("ocr_meta") or {}
    if meta.get("warning") and not meta.get("browser_windows"):
        return "offline", "offline", meta["warning"][:200]

    return "safe", "ok", "No strong phishing signals in scanned browser windows."


class DesktopAgentGUI(tk.Tk):
    def __init__(self, orb_only: bool = False) -> None:
        super().__init__()
        self._orb_only = orb_only
        self.title("Phishing Desktop Scanner")
        self.geometry("560x540")
        self.minsize(480, 400)

        self._stop = threading.Event()
        self._worker: Optional[threading.Thread] = None
        self._scan_lock = threading.Lock()

        self._orb = PhishGuardOrb(self, on_scan=self.on_scan_once)
        self._orb.set_state("idle", "Click to scan browser windows.", show_message=not orb_only)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

        frm = ttk.Frame(self, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text="API base URL").grid(row=0, column=0, sticky=tk.W)
        self.api_var = tk.StringVar(value="http://127.0.0.1:8000")
        ttk.Entry(frm, textvariable=self.api_var, width=48).grid(row=0, column=1, columnspan=2, sticky=tk.EW)

        ttk.Label(frm, text="Interval (seconds)").grid(row=1, column=0, sticky=tk.W, pady=(8, 0))
        self.interval_var = tk.StringVar(value="15")
        ttk.Spinbox(frm, from_=5, to=3600, textvariable=self.interval_var, width=10).grid(
            row=1, column=1, sticky=tk.W, pady=(8, 0)
        )
        ttk.Label(frm, text="(0 = scan once when you click Start)").grid(row=1, column=2, sticky=tk.W, pady=(8, 0))

        ttk.Label(frm, text="Capture").grid(row=2, column=0, sticky=tk.W, pady=(8, 0))
        self.capture_mode_var = tk.StringVar(value=CAPTURE_MODE_BROWSER)
        capture_combo = ttk.Combobox(
            frm,
            textvariable=self.capture_mode_var,
            values=(
                CAPTURE_MODE_BROWSER,
                CAPTURE_MODE_FOREGROUND,
                CAPTURE_MODE_ALL,
            ),
            state="readonly",
            width=18,
        )
        capture_combo.grid(row=2, column=1, sticky=tk.W, pady=(8, 0))
        ttk.Label(
            frm,
            text="browser = Chrome/Edge/Firefox windows only",
            font=("", 8),
            foreground="#555",
        ).grid(row=2, column=2, sticky=tk.W, pady=(8, 0))

        btn_row = ttk.Frame(frm)
        btn_row.grid(row=3, column=0, columnspan=3, pady=12)
        ttk.Button(btn_row, text="Check backend", command=self.on_check_backend).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(btn_row, text="Scan once", command=self.on_scan_once).pack(side=tk.LEFT, padx=(0, 8))
        self.start_btn = ttk.Button(btn_row, text="Start", command=self.on_start)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.stop_btn = ttk.Button(btn_row, text="Stop", command=self.on_stop, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)

        status_frame = ttk.LabelFrame(frm, text="Last result", padding=8)
        status_frame.grid(row=4, column=0, columnspan=3, sticky=tk.EW, pady=(0, 8))
        self.backend_status = ttk.Label(status_frame, text="Backend: not checked")
        self.backend_status.pack(anchor=tk.W)
        self.risk_label = ttk.Label(status_frame, text="Risk: —", font=("", 12, "bold"))
        self.risk_label.pack(anchor=tk.W, pady=(4, 0))
        self.stats_label = ttk.Label(status_frame, text="URLs on screen: — | Risky URLs: —")
        self.stats_label.pack(anchor=tk.W)
        self.email_label = ttk.Label(status_frame, text="Text/email signal: —")
        self.email_label.pack(anchor=tk.W)

        log_frame = ttk.LabelFrame(frm, text="Log", padding=4)
        log_frame.grid(row=5, column=0, columnspan=3, sticky=tk.NSEW, pady=(0, 0))
        frm.rowconfigure(5, weight=1)
        frm.columnconfigure(1, weight=1)
        self.log = scrolledtext.ScrolledText(log_frame, height=14, wrap=tk.WORD, state=tk.DISABLED)
        self.log.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            frm,
            text="Tip: keep the FastAPI backend running. Default capture scans browser windows only (Windows).",
            font=("", 8),
            foreground="#555",
        ).grid(row=6, column=0, columnspan=3, pady=(8, 0))

        ttk.Label(
            frm,
            text="Bottom-left orb (opposite extension): click=scan, right-click=open this window.",
            font=("", 8),
            foreground="#555",
        ).grid(row=7, column=0, columnspan=3, pady=(4, 0))

        if orb_only:
            self.withdraw()

    def _on_close(self) -> None:
        self._stop.set()
        try:
            if getattr(self, "_orb", None):
                self._orb.destroy()
        except tk.TclError:
            pass
        self.destroy()

    def _log(self, line: str) -> None:
        self.log.configure(state=tk.NORMAL)
        self.log.insert(tk.END, line + "\n")
        self.log.see(tk.END)
        self.log.configure(state=tk.DISABLED)

    def _set_running(self, running: bool) -> None:
        self.start_btn.configure(state=tk.DISABLED if running else tk.NORMAL)
        self.stop_btn.configure(state=tk.NORMAL if running else tk.DISABLED)

    def _update_orb_from_result(self, result: dict, err: Optional[str] = None) -> None:
        if not getattr(self, "_orb", None):
            return
        state, variant, msg = friendly_toast_for_result(result, err)
        self._orb.set_state(state, message=msg, show_message=True)
        if variant != "ok" and state != variant:
            pass  # set_state already maps state -> variant

    def _apply_result(self, urls_count: int, result: dict, err: Optional[str] = None) -> None:
        self._update_orb_from_result(result, err)

        if err:
            self.risk_label.configure(text="Risk: ERROR", foreground="red")
            self.stats_label.configure(text=err)
            self._log(f"Error: {err}")
            return

        risk = result.get("risk_level", "—")
        risky = result.get("risky_urls", [])
        email = result.get("email_result", {})
        pred = email.get("prediction", "—")
        conf = email.get("confidence", 0.0)

        color = "#333"
        if risk == "HIGH":
            color = "red"
        elif risk == "MEDIUM":
            color = "darkorange"
        elif risk == "LOW":
            color = "green"

        self.risk_label.configure(text=f"Risk: {risk}", foreground=color)
        self.stats_label.configure(text=f"URLs on screen: {urls_count} | Risky URLs: {len(risky)}")
        self.email_label.configure(text=f"Text/email signal: {pred} ({float(conf):.0%})")

        self._log(f"Risk={risk} | URLs={urls_count} | Risky={len(risky)} | email={pred} ({float(conf):.2f})")
        meta = result.get("ocr_meta") or {}
        if meta.get("browser_windows"):
            titles = meta["browser_windows"]
            preview = "; ".join(titles[:2])
            if len(titles) > 2:
                preview += f" (+{len(titles) - 2} more)"
            self._log(f"Browser capture ({meta.get('capture_mode', 'browser')}): {preview}")
        elif meta.get("monitors_scanned"):
            self._log(
                f"Screen capture: {meta.get('monitors_scanned')} display(s), "
                f"{meta.get('text_length', 0)} OCR chars."
            )
        if meta.get("warning"):
            self._log(meta["warning"])
        if meta.get("uncertain") and risk == "LOW":
            self._log("Tip: Few URLs read by OCR — zoom the browser or use the web analyzer.")
        if result.get("ocr_caution"):
            self._log(result["ocr_caution"])
        for u in risky[:15]:
            self._log(f"  risky: {u}")
        if len(risky) > 15:
            self._log(f"  ... +{len(risky) - 15} more")

    def on_check_backend(self) -> None:
        api = self.api_var.get().strip()
        ok, msg = check_backend(api)
        if ok:
            self.backend_status.configure(text="Backend: connected", foreground="green")
            if getattr(self, "_orb", None):
                self._orb.show_toast("Backend connected.", "ok", ms=2500)
        else:
            self.backend_status.configure(text=f"Backend: failed ({msg})", foreground="red")
            if getattr(self, "_orb", None):
                self._orb.set_state("offline", "Scanner offline — start backend on port 8000.")

    def _get_interval_sec(self) -> int:
        try:
            v = int(self.interval_var.get().strip())
            return max(0, v)
        except ValueError:
            return 15

    def _get_capture_mode(self) -> str:
        mode = (self.capture_mode_var.get() or CAPTURE_MODE_BROWSER).strip().lower()
        if mode in (CAPTURE_MODE_BROWSER, CAPTURE_MODE_FOREGROUND, CAPTURE_MODE_ALL):
            return mode
        return CAPTURE_MODE_BROWSER

    def _run_capture(self, api: str):
        return capture_and_analyze(api, capture_mode=self._get_capture_mode(), fallback_all=True)

    def _begin_scan_ui(self) -> None:
        if getattr(self, "_orb", None):
            self._orb.set_state("scanning", "Scanning browser windows…", show_message=True)

    def _run_scan_async(self, from_worker: bool = False) -> None:
        if not self._scan_lock.acquire(blocking=False):
            if getattr(self, "_orb", None):
                self._orb.show_toast("Scan already in progress.", "offline", ms=2000)
            return

        api = self.api_var.get().strip()

        def job():
            self.after(0, self._begin_scan_ui)
            try:
                _, urls, result = self._run_capture(api)
                self.after(0, lambda: self._apply_result(len(urls), result))
            except Exception as exc:
                self.after(0, lambda e=str(exc): self._apply_result(0, {}, err=e))
            finally:
                self._scan_lock.release()
                if from_worker:
                    pass
                elif self._get_interval_sec() <= 0:
                    self.after(0, lambda: self._set_running(False))

        threading.Thread(target=job, daemon=True).start()

    def _worker_loop(self) -> None:
        api = self.api_var.get().strip()
        interval = self._get_interval_sec()

        def run_scan():
            if not self._scan_lock.acquire(blocking=False):
                return
            self.after(0, self._begin_scan_ui)
            try:
                _, urls, result = self._run_capture(api)
                self.after(0, lambda: self._apply_result(len(urls), result))
            except Exception as exc:
                self.after(0, lambda e=str(exc): self._apply_result(0, {}, err=e))
            finally:
                self._scan_lock.release()

        run_scan()
        if interval <= 0:
            self.after(0, lambda: self._set_running(False))
            return

        while not self._stop.is_set():
            if self._stop.wait(timeout=interval):
                break
            if self._stop.is_set():
                break
            run_scan()

        self.after(0, lambda: self._set_running(False))
        self.after(0, lambda: self._log("Stopped."))
        if getattr(self, "_orb", None):
            self.after(0, lambda: self._orb.set_state("idle", show_message=False))

    def on_start(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        self._stop.clear()
        self._set_running(True)
        self._log("Starting...")
        self._worker = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker.start()

    def on_stop(self) -> None:
        self._stop.set()
        self._log("Stop requested...")

    def on_scan_once(self) -> None:
        if self._worker and self._worker.is_alive():
            if not self._orb_only:
                messagebox.showinfo("Busy", "Stop the continuous scan first, or wait for it to finish.")
            else:
                if getattr(self, "_orb", None):
                    self._orb.show_toast("Continuous scan running — stop it from settings.", "offline", ms=3000)
            return

        self._log(f"Scan once (capture={self._get_capture_mode()})...")
        self._run_scan_async()


def main() -> None:
    parser = argparse.ArgumentParser(description="Phishing desktop scanner GUI with extension-style orb.")
    parser.add_argument(
        "--orb-only",
        action="store_true",
        help="Show only the bottom-left orb (right-click orb to open settings window)",
    )
    args = parser.parse_args()

    app = DesktopAgentGUI(orb_only=args.orb_only)
    app.mainloop()


if __name__ == "__main__":
    main()
