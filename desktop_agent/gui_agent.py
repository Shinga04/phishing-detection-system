"""
Local GUI for the desktop phishing scanner (OCR + FastAPI).
Uses tkinter (stdlib). Run: python gui_agent.py
"""

import threading
from typing import Any, Optional, Tuple
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from urllib.parse import urljoin

import requests

from screen_agent import capture_and_analyze


class StatusOrb(tk.Toplevel):
    """Small always-on-top circle (Grammarly-style) for quick safe / unsafe glance."""

    COLORS = {
        "idle": "#64748b",
        "scanning": "#ca8a04",
        "safe": "#16a34a",
        "warn": "#ea580c",
        "unsafe": "#dc2626",
        "error": "#7c3aed",
    }

    def __init__(self, master: tk.Tk) -> None:
        super().__init__(master)
        self._master = master
        self.overrideredirect(True)
        try:
            self.attributes("-topmost", True)
        except tk.TclError:
            pass
        try:
            self.attributes("-alpha", 0.94)
        except tk.TclError:
            pass

        w, h = 54, 54
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = max(8, sw - w - 28)
        y = max(8, sh - h - 96)
        self.geometry(f"{w}x{h}+{x}+{y}")

        self._canvas = tk.Canvas(self, width=w, height=h, highlightthickness=0, bg="#0f172a")
        self._canvas.pack(fill=tk.BOTH, expand=True)
        pad = 7
        self._circle = self._canvas.create_oval(
            pad, pad, w - pad, h - pad, fill=self.COLORS["idle"], outline="#f8fafc", width=2
        )
        self._pulse_after: Optional[Any] = None
        self._pulse_on = True

    def _stop_pulse(self) -> None:
        if self._pulse_after is not None:
            try:
                self.after_cancel(self._pulse_after)
            except tk.TclError:
                pass
            self._pulse_after = None

    def _tick_pulse(self) -> None:
        if not self.winfo_exists():
            return
        c = "#fbbf24" if self._pulse_on else self.COLORS["scanning"]
        self._pulse_on = not self._pulse_on
        self._canvas.itemconfigure(self._circle, fill=c)
        self._pulse_after = self.after(450, self._tick_pulse)

    def set_state(self, state: str) -> None:
        self._stop_pulse()
        fill = self.COLORS.get(state, self.COLORS["idle"])
        self._canvas.itemconfigure(self._circle, fill=fill)
        if state == "scanning":
            self._pulse_on = True
            self._tick_pulse()


def check_backend(api_base: str) -> Tuple[bool, str]:
    base = api_base.rstrip("/") + "/"
    try:
        r = requests.get(urljoin(base, "health"), timeout=3)
        if r.status_code == 200:
            return True, "OK"
        return False, f"HTTP {r.status_code}"
    except requests.RequestException as exc:
        return False, str(exc)


class DesktopAgentGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Phishing Desktop Scanner")
        self.geometry("560x520")
        self.minsize(480, 400)

        self._stop = threading.Event()
        self._worker: Optional[threading.Thread] = None

        self._orb = StatusOrb(self)
        self._orb.set_state("idle")

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

        btn_row = ttk.Frame(frm)
        btn_row.grid(row=2, column=0, columnspan=3, pady=12)
        ttk.Button(btn_row, text="Check backend", command=self.on_check_backend).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(btn_row, text="Scan once", command=self.on_scan_once).pack(side=tk.LEFT, padx=(0, 8))
        self.start_btn = ttk.Button(btn_row, text="Start", command=self.on_start)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.stop_btn = ttk.Button(btn_row, text="Stop", command=self.on_stop, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)

        status_frame = ttk.LabelFrame(frm, text="Last result", padding=8)
        status_frame.grid(row=3, column=0, columnspan=3, sticky=tk.EW, pady=(0, 8))
        self.backend_status = ttk.Label(status_frame, text="Backend: not checked")
        self.backend_status.pack(anchor=tk.W)
        self.risk_label = ttk.Label(status_frame, text="Risk: —", font=("", 12, "bold"))
        self.risk_label.pack(anchor=tk.W, pady=(4, 0))
        self.stats_label = ttk.Label(status_frame, text="URLs on screen: — | Risky URLs: —")
        self.stats_label.pack(anchor=tk.W)
        self.email_label = ttk.Label(status_frame, text="Text/email signal: —")
        self.email_label.pack(anchor=tk.W)

        log_frame = ttk.LabelFrame(frm, text="Log", padding=4)
        log_frame.grid(row=4, column=0, columnspan=3, sticky=tk.NSEW, pady=(0, 0))
        frm.rowconfigure(4, weight=1)
        frm.columnconfigure(1, weight=1)
        self.log = scrolledtext.ScrolledText(log_frame, height=14, wrap=tk.WORD, state=tk.DISABLED)
        self.log.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            frm,
            text="Tip: keep the FastAPI backend running. This tool captures visible screen text via OCR only.",
            font=("", 8),
            foreground="#555",
        ).grid(row=5, column=0, columnspan=3, pady=(8, 0))

        ttk.Label(
            frm,
            text="Bottom-right orb: gray=idle, pulsing=scanning, green=safer, orange/red=risk.",
            font=("", 8),
            foreground="#555",
        ).grid(row=6, column=0, columnspan=3, pady=(4, 0))

    def _on_close(self) -> None:
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

    def _apply_result(self, urls_count: int, result: dict, err: Optional[str] = None) -> None:
        if err:
            self.risk_label.configure(text="Risk: ERROR", foreground="red")
            self.stats_label.configure(text=err)
            self._log(f"Error: {err}")
            if getattr(self, "_orb", None):
                self._orb.set_state("error")
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
        self.email_label.configure(
            text=f"Text/email signal: {pred} ({float(conf):.0%})"
        )

        self._log(f"Risk={risk} | URLs={urls_count} | Risky={len(risky)} | email={pred} ({float(conf):.2f})")
        meta = result.get("ocr_meta") or {}
        if meta.get("monitors_scanned"):
            self._log(
                f"Screen capture: {meta.get('monitors_scanned')} display(s), "
                f"{meta.get('text_length', 0)} OCR chars."
            )
        if meta.get("uncertain") and risk == "LOW":
            self._log("Tip: Few URLs read by OCR — zoom the app or use the web analyzer with a pasted link.")
        if result.get("ocr_caution"):
            self._log(result["ocr_caution"])
        for u in risky[:15]:
            self._log(f"  risky: {u}")
        if len(risky) > 15:
            self._log(f"  ... +{len(risky) - 15} more")

        if getattr(self, "_orb", None):
            # Grammary-style status orb:
            # - grey/idle = not scanned yet
            # - green  = safe
            # - red    = unsafe (phishing or any risky URL detected)
            email_bad = pred == "phishing"
            any_url_bad = len(risky) > 0
            unsafe = email_bad or any_url_bad or risk in ("MEDIUM", "HIGH")

            if unsafe:
                self._orb.set_state("unsafe")
            else:
                self._orb.set_state("safe")

    def on_check_backend(self) -> None:
        api = self.api_var.get().strip()
        ok, msg = check_backend(api)
        if ok:
            self.backend_status.configure(text="Backend: connected", foreground="green")
        else:
            self.backend_status.configure(text=f"Backend: failed ({msg})", foreground="red")

    def _get_interval_sec(self) -> int:
        try:
            v = int(self.interval_var.get().strip())
            return max(0, v)
        except ValueError:
            return 15

    def _worker_loop(self) -> None:
        api = self.api_var.get().strip()
        interval = self._get_interval_sec()

        def run_scan():
            self.after(0, lambda: self._orb.set_state("scanning") if getattr(self, "_orb", None) else None)
            try:
                _, urls, result = capture_and_analyze(api)
                self.after(0, lambda: self._apply_result(len(urls), result))
            except Exception as exc:
                self.after(0, lambda e=str(exc): self._apply_result(0, {}, err=e))

        run_scan()
        if interval <= 0:
            self.after(0, lambda: self._set_running(False))
            return

        while not self._stop.is_set():
            if self._stop.wait(timeout=interval):
                break
            if self._stop.is_set():
                break
            try:
                self.after(0, lambda: self._orb.set_state("scanning") if getattr(self, "_orb", None) else None)
                _, urls, result = capture_and_analyze(api)
                self.after(0, lambda u=len(urls), r=result: self._apply_result(u, r))
            except Exception as exc:
                self.after(0, lambda e=str(exc): self._apply_result(0, {}, err=e))

        self.after(0, lambda: self._set_running(False))
        self.after(0, lambda: self._log("Stopped."))

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
            messagebox.showinfo("Busy", "Stop the current run first, or wait for it to finish.")
            return

        api = self.api_var.get().strip()

        def job():
            self.after(0, lambda: self._orb.set_state("scanning") if getattr(self, "_orb", None) else None)
            try:
                _, urls, result = capture_and_analyze(api)
                self.after(0, lambda: self._apply_result(len(urls), result))
            except Exception as exc:
                self.after(0, lambda e=str(exc): self._apply_result(0, {}, err=e))

        self._log("Scan once...")
        threading.Thread(target=job, daemon=True).start()


def main():
    app = DesktopAgentGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
