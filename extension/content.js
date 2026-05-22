(() => {
  const FAB_ID = "phish-guard-fab-ext";
  const TOAST_ID = "phish-guard-toast-ext";
  const HL_MARK = "data-phish-guard-risk";
  const AUTO_MIN_MS = 45000;
  const DEBOUNCE_MS = 2200;
  const INITIAL_DELAY_MS = 2800;
  const EMAIL_CONFIDENCE_THRESHOLD = 0.6;
  const MIN_RISKY_URLS_FOR_UNSAFE = 1;

  let lastAutoAt = 0;
  let debounceTimer = null;
  let scanInFlight = false;
  /** @type {boolean} */
  let lastScanMailContext = false;

  function isWebmailHost() {
    const h = location.hostname.toLowerCase();
    return (
      h === "mail.google.com" ||
      h === "mail.yahoo.com" ||
      h.endsWith(".mail.yahoo.com") ||
      h === "outlook.live.com" ||
      h.endsWith(".outlook.live.com") ||
      h === "outlook.office.com" ||
      h.endsWith(".outlook.office.com") ||
      h === "outlook.office365.com" ||
      h.endsWith(".outlook.office365.com")
    );
  }

  function findGmailMessagePane() {
    return (
      document.querySelector("div.a3s") ||
      document.querySelector("div.a3s.aiL") ||
      document.querySelector("div.adn.ads") ||
      document.querySelector("div.adn") ||
      document.querySelector("div.gs") ||
      null
    );
  }

  function getGenericScanRoot() {
    return (
      document.querySelector("main") ||
      document.querySelector('[role="main"]') ||
      document.querySelector("#primary") ||
      document.querySelector("#contents") ||
      document.getElementById("content") ||
      document.querySelector("article") ||
      document.body
    );
  }

  /**
   * Mail context: treat visible text as email body (Gmail pane or full webmail host fallback).
   * Generic sites: only scan links in main content; do not send page text as email (avoids false phishing).
   */
  function getScanContext() {
    const pane = findGmailMessagePane();
    if (isWebmailHost()) {
      const root = pane || getGenericScanRoot();
      const useEmail = Boolean(pane);
      return { root, useEmailContext: useEmail, mailHost: true };
    }
    return { root: getGenericScanRoot(), useEmailContext: false, mailHost: false };
  }

  const unwrapGoogleRedirect = (href) => {
    try {
      const u = new URL(href);
      if (u.hostname === "www.google.com" && u.pathname === "/url") {
        return u.searchParams.get("q") || href;
      }
    } catch {
      // ignore invalid URLs
    }
    return href;
  };

  const extractUrlsFromText = (text, limit = 50) => {
    const t = String(text || "");
    const raw = t.match(/https?:\/\/[^\s<>"')\]]+|www\.[^\s<>"')\]]+/gi) || [];
    const normalized = raw
      .map((u) => (u.toLowerCase().startsWith("www.") ? `https://${u}` : u))
      .map((u) => u.replace(/[.,;:!?]+$/g, ""));
    return [...new Set(normalized)].slice(0, limit);
  };

  const collectEmailBodyData = (opts = {}) => {
    const { maxUrls = 25, maxTextChars = 7000 } = opts;
    const { root, useEmailContext } = getScanContext();

    const anchorUrls = [...root.querySelectorAll("a[href]")]
      .map((a) => unwrapGoogleRedirect(a.href))
      .filter(Boolean);

    const bodyText = useEmailContext ? (root?.innerText || "").slice(0, maxTextChars) : "";
    const textUrls = extractUrlsFromText(bodyText, maxUrls);

    const urls = [...new Set([...anchorUrls, ...textUrls])].slice(0, maxUrls);
    return { urls, emailText: bodyText, root, useEmailContext };
  };

  const collectPageData = () => {
    const { urls, emailText, root, useEmailContext } = collectEmailBodyData({
      maxUrls: 75,
      maxTextChars: 7000,
    });
    return { urls, emailText, useEmailContext };
  };

  const collectForAutoScan = () => {
    return collectEmailBodyData({ maxUrls: 25, maxTextChars: 7000 });
  };

  function clearExtensionHighlights() {
    document.querySelectorAll(`a[${HL_MARK}]`).forEach((a) => {
      a.style.backgroundColor = "";
      a.style.color = "";
      a.removeAttribute(HL_MARK);
    });
  }

  /** Only mark risky links; do not paint unscanned links green. */
  const applyHighlights = (riskLinks = [], domRoot = null) => {
    clearExtensionHighlights();
    const riskySet = new Set(riskLinks);
    if (riskySet.size === 0) return;

    const root = domRoot || getScanContext().root;
    [...root.querySelectorAll("a[href]")].forEach((link) => {
      const href = unwrapGoogleRedirect(link.href);
      if (riskySet.has(link.href) || riskySet.has(href)) {
        link.setAttribute(HL_MARK, "1");
        link.style.backgroundColor = "rgba(239,68,68,0.2)";
        link.style.color = "#b91c1c";
      }
    });
  };

  function injectFabStyles() {
    if (document.getElementById("phish-guard-fab-styles")) return;
    const style = document.createElement("style");
    style.id = "phish-guard-fab-styles";
    style.textContent = `
      #${FAB_ID} {
        position: fixed;
        bottom: 22px;
        right: 22px;
        width: 46px;
        height: 46px;
        border-radius: 50%;
        z-index: 2147483646;
        box-shadow: 0 4px 14px rgba(0,0,0,0.35);
        border: 2px solid rgba(255,255,255,0.9);
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 11px;
        font-weight: 800;
        font-family: system-ui, Segoe UI, sans-serif;
        color: #fff;
        text-shadow: 0 1px 2px rgba(0,0,0,0.4);
        transition: transform 0.2s ease, background 0.35s ease;
        user-select: none;
      }
      #${FAB_ID}:hover { transform: scale(1.06); }
      #${FAB_ID}.idle { background: #64748b; }
      #${FAB_ID}.scanning { background: #ca8a04; animation: phish-guard-pulse 1.1s ease-in-out infinite; }
      #${FAB_ID}.safe { background: #16a34a; }
      #${FAB_ID}.unsafe { background: #dc2626; animation: phish-guard-shake 0.5s ease; }
      @keyframes phish-guard-pulse {
        0%, 100% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.85; transform: scale(0.95); }
      }
      @keyframes phish-guard-shake {
        0%, 100% { transform: translateX(0); }
        25% { transform: translateX(-3px); }
        75% { transform: translateX(3px); }
      }
      #${TOAST_ID} {
        position: fixed;
        bottom: 78px;
        right: 22px;
        max-width: 280px;
        padding: 10px 12px;
        border-radius: 10px;
        z-index: 2147483647;
        font-size: 13px;
        font-family: system-ui, Segoe UI, sans-serif;
        line-height: 1.35;
        box-shadow: 0 6px 20px rgba(0,0,0,0.25);
        opacity: 0;
        transform: translateY(8px);
        transition: opacity 0.35s ease, transform 0.35s ease;
        pointer-events: none;
      }
      #${TOAST_ID}.show { opacity: 1; transform: translateY(0); }
      #${TOAST_ID}.warn { background: #fef2f2; color: #991b1b; border: 1px solid #fecaca; }
      #${TOAST_ID}.ok { background: #f0fdf4; color: #166534; border: 1px solid #bbf7d0; }
    `;
    (document.head || document.documentElement).appendChild(style);
  }

  function ensureFab() {
    injectFabStyles();
    let el = document.getElementById(FAB_ID);
    if (el) return el;
    el = document.createElement("button");
    el.id = FAB_ID;
    el.type = "button";
    el.className = "idle";
    el.textContent = "•";
    el.title = "Phishing guard — click to scan now";
    el.setAttribute("aria-label", "Phishing scan status");
    el.addEventListener("click", () => {
      lastAutoAt = 0;
      runAutoScan(true);
    });
    document.documentElement.appendChild(el);
    return el;
  }

  function ensureToast() {
    let t = document.getElementById(TOAST_ID);
    if (t) return t;
    t = document.createElement("div");
    t.id = TOAST_ID;
    document.documentElement.appendChild(t);
    return t;
  }

  let toastHideTimer = null;
  function showToast(text, variant, ms = 5000) {
    const t = ensureToast();
    clearTimeout(toastHideTimer);
    t.className = variant === "warn" ? "warn" : "ok";
    t.textContent = text;
    requestAnimationFrame(() => {
      t.classList.add("show");
    });
    toastHideTimer = setTimeout(() => {
      t.classList.remove("show");
    }, ms);
  }

  function setFabState(state) {
    const el = ensureFab();
    el.classList.remove("idle", "scanning", "safe", "unsafe");
    el.classList.add(state);
    const labels = {
      idle: "Phishing guard: idle",
      scanning: "Phishing guard: checking…",
      safe: "Phishing guard: looks safer",
      unsafe: "Phishing guard: possible unsafe links",
    };
    el.setAttribute("aria-label", labels[state] || "Phishing guard");
    if (state === "safe") el.textContent = "✓";
    else if (state === "unsafe") el.textContent = "!";
    else if (state === "scanning") el.textContent = "…";
    else el.textContent = "•";
  }

  function applyAutoResult(payload) {
    if (payload?.error) {
      setFabState("idle");
      showToast("Could not reach scanner. Is the backend running?", "warn", 4000);
      return;
    }
    const { riskyUrlCount, riskyUrls, emailResult } = payload;
    const safeRiskyUrlCount = Number.isFinite(riskyUrlCount) ? riskyUrlCount : 0;
    const safeRiskyUrls = riskyUrls || [];
    applyHighlights(safeRiskyUrls, payload._scanRoot || null);

    const emailBad =
      lastScanMailContext &&
      emailResult?.prediction === "phishing" &&
      (emailResult?.confidence ?? 0) >= EMAIL_CONFIDENCE_THRESHOLD;
    const urlBad = safeRiskyUrlCount >= MIN_RISKY_URLS_FOR_UNSAFE;
    const unsafe = emailBad || urlBad;

    if (unsafe) {
      setFabState("unsafe");
      if (urlBad && emailBad) {
        showToast("Warning: risky links and suspicious message text. Be careful before clicking.", "warn", 6500);
      } else if (urlBad) {
        showToast("Warning: one or more sampled links look like phishing. Be careful before clicking.", "warn", 6500);
      } else {
        showToast("Warning: message text matches common phishing patterns. Verify the sender before acting.", "warn", 6500);
      }
    } else {
      setFabState("safe");
      if (lastScanMailContext) {
        showToast("No strong phishing signals in this message sample. Still stay careful online.", "ok", 4200);
      } else {
        showToast("No risky links in the sampled page links. General browsing is not a full safety check.", "ok", 4200);
      }
    }
  }

  function runAutoScan(force = false) {
    const now = Date.now();
    if (scanInFlight) return;
    if (!force && now - lastAutoAt < AUTO_MIN_MS) return;

    const { urls, emailText, root, useEmailContext } = collectForAutoScan();
    lastScanMailContext = useEmailContext;

    if (urls.length === 0 && !emailText.trim()) {
      clearExtensionHighlights();
      setFabState("idle");
      return;
    }

    scanInFlight = true;
    setFabState("scanning");

    chrome.runtime.sendMessage(
      { type: "AUTO_SCAN", urls, emailText, analyzeEmail: useEmailContext },
      (res) => {
        scanInFlight = false;
        if (chrome.runtime.lastError) {
          setFabState("idle");
          showToast("Extension could not scan. Try reloading the page.", "warn", 4000);
          return;
        }
        if (res?.ok) {
          lastAutoAt = Date.now();
          applyAutoResult({ ...res, _scanRoot: root });
        } else applyAutoResult({ error: res?.error || "unknown" });
      }
    );
  }

  function scheduleAutoScan() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => runAutoScan(false), DEBOUNCE_MS);
  }

  chrome.runtime.onMessage.addListener((msg, _, sendResponse) => {
    if (msg?.type === "COLLECT_PAGE_DATA") {
      sendResponse(collectPageData());
      return true;
    }
    if (msg?.type === "HIGHLIGHT_RISK") {
      applyHighlights(msg.riskyUrls || [], getScanContext().root);
      sendResponse({ ok: true });
      return true;
    }
    if (msg?.type === "AUTO_SCAN_RESULT") {
      lastScanMailContext = Boolean(msg.emailAnalysisIncluded);
      applyAutoResult({ ...msg, _scanRoot: getScanContext().root });
      sendResponse({ ok: true });
      return true;
    }
    return false;
  });

  function initAutoWatch() {
    ensureFab();
    setFabState("idle");
    setTimeout(() => runAutoScan(false), INITIAL_DELAY_MS);

    const obs = new MutationObserver(() => scheduleAutoScan());
    if (document.body) {
      obs.observe(document.body, { childList: true, subtree: true });
    } else {
      document.addEventListener("DOMContentLoaded", () => {
        obs.observe(document.body, { childList: true, subtree: true });
      });
    }
  }

  initAutoWatch();
})();
