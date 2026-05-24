/**
 * Content script (Option B): webmail email + link phishing only.
 * - Gmail/Outlook/Yahoo: floating badge, scan links in open message + email ML.
 * - Other sites: no badge (use extension popup to scan).
 */
(() => {
  const FAB_ID = "phish-guard-fab-ext";
  const TOAST_ID = "phish-guard-toast-ext";
  const HL_MARK = "data-phish-guard-risk";
  const AUTO_MIN_MS = 60000;
  const DEBOUNCE_MS = 3000;
  const MAX_URLS = 10;
  const EMAIL_CONFIDENCE_THRESHOLD = 0.6;

  let lastAutoAt = 0;
  let debounceTimer = null;
  let scanInFlight = false;
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
      document.querySelector("motion.div.a3s") ||
      document.querySelector("motion.div.a3s.aiL") ||
      document.querySelector("motion.div.adn.ads") ||
      document.querySelector("motion.div.adn") ||
      document.querySelector("motion.div.gs") ||
      document.querySelector("motion.div[role='listitem'] div.a3s") ||
      document.querySelector("div.a3s") ||
      document.querySelector("div.a3s.aiL") ||
      document.querySelector("div.adn.ads") ||
      document.querySelector("div.adn") ||
      document.querySelector("div.gs") ||
      null
    );
  }

  function collectGmailHeaders() {
    if (!location.hostname.includes("google.com")) return "";

    const lines = [];
    const subject =
      document.querySelector("h2.hP")?.innerText?.trim() ||
      document.querySelector(".ha h2")?.innerText?.trim();
    if (subject) lines.push(`Subject: ${subject}`);

    const fromEl =
      document.querySelector(".gD[email]") ||
      document.querySelector("span.gD[email]") ||
      document.querySelector("[email][name]");
    if (fromEl) {
      const email = fromEl.getAttribute("email")?.trim();
      const name = fromEl.getAttribute("name")?.trim() || fromEl.innerText?.trim();
      if (email) {
        lines.push(name ? `From: ${name} <${email}>` : `From: ${email}`);
      }
    }

    document.querySelectorAll(".go, .gQ, .g2").forEach((el) => {
      const t = el.innerText?.trim();
      if (t && t.includes("@")) {
        const label = t.toLowerCase().includes("via") ? "Via" : "Reply-To";
        if (!lines.some((line) => line.includes(t))) {
          lines.push(`${label}: ${t.replace(/^via\s+/i, "")}`);
        }
      }
    });

    return lines.join("\n");
  }

  function buildEmailText(root, useEmailContext) {
    if (!useEmailContext) return "";
    const parts = [];
    const headers = collectGmailHeaders();
    if (headers) parts.push(headers);
    if (root) parts.push((root.innerText || "").slice(0, 7000));
    return parts.filter(Boolean).join("\n\n").slice(0, 7000);
  }

  function isEmailResultRisky(emailResult) {
    if (!emailResult) return false;
    if (
      emailResult.prediction === "phishing" &&
      (emailResult.confidence ?? 0) >= EMAIL_CONFIDENCE_THRESHOLD
    ) {
      return true;
    }
    const p = Number(emailResult.p_phishing);
    return !Number.isNaN(p) && p >= 0.55;
  }

  function getScanContext() {
    if (!isWebmailHost()) return null;
    const pane = findGmailMessagePane();
    const headers = collectGmailHeaders();
    const root = pane || document.querySelector('[role="main"]') || document.body;
    return { root, useEmailContext: Boolean(pane) || Boolean(headers) };
  }

  function unwrapGoogleRedirect(href) {
    try {
      const u = new URL(href);
      if (u.hostname === "www.google.com" && u.pathname === "/url") {
        return u.searchParams.get("q") || href;
      }
    } catch {
      /* ignore */
    }
    return href;
  }

  function extractUrlsFromText(text, limit) {
    const raw = String(text || "").match(/https?:\/\/[^\s<>"')\]]+|www\.[^\s<>"')\]]+/gi) || [];
    return [
      ...new Set(
        raw
          .map((u) => (u.toLowerCase().startsWith("www.") ? `https://${u}` : u))
          .map((u) => u.replace(/[.,;:!?]+$/g, ""))
      ),
    ].slice(0, limit);
  }

  function collectLinkData() {
    const ctx = getScanContext();
    if (!ctx) return { urls: [], emailText: "", root: null, useEmailContext: false };

    const { root, useEmailContext } = ctx;
    const anchorUrls = [...root.querySelectorAll("a[href]")]
      .map((a) => unwrapGoogleRedirect(a.href))
      .filter((h) => h && /^https?:\/\//i.test(h));

    const bodyText = buildEmailText(root, useEmailContext);
    const textUrls = extractUrlsFromText(bodyText, MAX_URLS);
    const urls = [...new Set([...anchorUrls, ...textUrls])].slice(0, MAX_URLS);

    return { urls, emailText: bodyText, root, useEmailContext };
  }

  function clearExtensionHighlights() {
    document.querySelectorAll(`a[${HL_MARK}]`).forEach((a) => {
      a.style.backgroundColor = "";
      a.style.color = "";
      a.removeAttribute(HL_MARK);
    });
  }

  function applyHighlights(riskLinks, domRoot) {
    clearExtensionHighlights();
    if (!domRoot || !riskLinks?.length) return;
    const riskySet = new Set(riskLinks);
    domRoot.querySelectorAll("a[href]").forEach((link) => {
      const href = unwrapGoogleRedirect(link.href);
      if (riskySet.has(link.href) || riskySet.has(href)) {
        link.setAttribute(HL_MARK, "1");
        link.style.backgroundColor = "rgba(239,68,68,0.2)";
        link.style.color = "#b91c1c";
      }
    });
  }

  function injectFabStyles() {
    if (document.getElementById("phish-guard-fab-styles")) return;
    const style = document.createElement("style");
    style.id = "phish-guard-fab-styles";
    style.textContent = `
      #${FAB_ID} {
        position: fixed; bottom: 22px; right: 22px; width: 46px; height: 46px;
        border-radius: 50%; z-index: 2147483646;
        box-shadow: 0 4px 14px rgba(0,0,0,0.35);
        border: 2px solid rgba(255,255,255,0.9);
        cursor: pointer; display: flex; align-items: center; justify-content: center;
        font-size: 11px; font-weight: 800; font-family: system-ui, Segoe UI, sans-serif;
        color: #fff; user-select: none;
      }
      #${FAB_ID}.idle { background: #64748b; }
      #${FAB_ID}.scanning { background: #ca8a04; }
      #${FAB_ID}.safe { background: #16a34a; }
      #${FAB_ID}.unsafe { background: #dc2626; }
      #${FAB_ID}.offline { background: #d97706; }
      #${TOAST_ID} {
        position: fixed; bottom: 78px; right: 22px; max-width: 280px;
        padding: 10px 12px; border-radius: 10px; z-index: 2147483647;
        font-size: 13px; font-family: system-ui, Segoe UI, sans-serif;
        line-height: 1.35; box-shadow: 0 6px 20px rgba(0,0,0,0.25);
        opacity: 0; pointer-events: none;
        transition: opacity 0.3s ease;
      }
      #${TOAST_ID}.show { opacity: 1; }
      #${TOAST_ID}.warn { background: #fef2f2; color: #991b1b; border: 1px solid #fecaca; }
      #${TOAST_ID}.ok { background: #f0fdf4; color: #166534; border: 1px solid #bbf7d0; }
      #${TOAST_ID}.offline { background: #fffbeb; color: #92400e; border: 1px solid #fde68a; }
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
    el.title = "Scan email links (phishing guard)";
    el.addEventListener("click", () => runScan(true));
    document.documentElement.appendChild(el);
    return el;
  }

  function ensureToast() {
    let t = document.getElementById(TOAST_ID);
    if (!t) {
      t = document.createElement("div");
      t.id = TOAST_ID;
      document.documentElement.appendChild(t);
    }
    return t;
  }

  let toastTimer = null;
  function showToast(text, variant, ms = 4500) {
    const t = ensureToast();
    clearTimeout(toastTimer);
    t.className = variant === "warn" ? "warn" : variant === "offline" ? "offline" : "ok";
    t.textContent = text;
    requestAnimationFrame(() => t.classList.add("show"));
    toastTimer = setTimeout(() => t.classList.remove("show"), ms);
  }

  function setFabState(state) {
    const el = ensureFab();
    el.className = state;
    const icon = { idle: "•", scanning: "…", safe: "✓", unsafe: "!", offline: "?" };
    el.textContent = icon[state] || "•";
  }

  function applyResult(payload) {
    if (payload?.error) {
      setFabState("offline");
      showToast("Cannot reach API. Start backend and set http://127.0.0.1:8000 in extension popup.", "offline");
      return;
    }

    const { riskyUrls, riskyUrlCount, emailResult, backendUnavailable, scanIncomplete, _scanRoot } =
      payload;
    applyHighlights(riskyUrls || [], _scanRoot);

    const emailBad = lastScanMailContext && isEmailResultRisky(emailResult);
    const urlBad = (riskyUrlCount || 0) >= 1;
    const unsafe = emailBad || urlBad;

    if (backendUnavailable) {
      setFabState("offline");
      showToast("Scanner offline — start uvicorn on port 8000.", "offline");
      return;
    }

    if (scanIncomplete && !unsafe) {
      setFabState("offline");
      showToast("API is up but link scans failed. Check backend logs and retry.", "offline");
      return;
    }

    if (unsafe) {
      setFabState("unsafe");
      showToast(
        urlBad && emailBad
          ? "Warning: suspicious email and risky links detected."
          : urlBad
            ? "Warning: one or more links in this message look like phishing."
            : "Warning: this message looks like phishing.",
        "warn"
      );
      return;
    }

    setFabState("safe");
    showToast("No strong phishing signals in sampled links and text.", "ok");
  }

  function runScan(force) {
    if (!isWebmailHost()) return;
    if (scanInFlight) return;
    if (!force && Date.now() - lastAutoAt < AUTO_MIN_MS) return;

    const { urls, emailText, root, useEmailContext } = collectLinkData();
    lastScanMailContext = useEmailContext;

    if (urls.length === 0 && !emailText.trim()) {
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
          setFabState("offline");
          showToast("Extension error — reload this tab.", "offline");
          return;
        }
        if (res?.ok) {
          lastAutoAt = Date.now();
          applyResult({ ...res, _scanRoot: root });
        } else {
          applyResult({ error: res?.error });
        }
      }
    );
  }

  function scheduleScan() {
    if (scanInFlight) return;
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => runScan(false), DEBOUNCE_MS);
  }

  chrome.runtime.onMessage.addListener((msg, _, sendResponse) => {
    if (msg?.type === "COLLECT_PAGE_DATA") {
      const data = collectLinkData();
      sendResponse({
        urls: data.urls,
        emailText: data.emailText,
        useEmailContext: data.useEmailContext,
      });
      return true;
    }
    if (msg?.type === "SCAN_RESULT") {
      applyResult({ ...msg, _scanRoot: getScanContext()?.root });
      sendResponse({ ok: true });
      return true;
    }
    return false;
  });

  function init() {
    if (!isWebmailHost()) return;
    ensureFab();
    setFabState("idle");
    setTimeout(() => runScan(false), 3500);

    const pane = findGmailMessagePane();
    const target = pane || document.querySelector('[role="main"]');
    if (target) {
      const obs = new MutationObserver(scheduleScan);
      obs.observe(target, { childList: true, subtree: true });
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
