/**
 * Extension background (Option B): email + hyperlink phishing via backend API only.
 * No malvertising / iframe / client heuristics.
 */

const DEFAULT_API_BASE = "http://127.0.0.1:8000";
const URL_CONFIDENCE_THRESHOLD = 0.5;
const EXTENSION_UNCERTAIN_PHISH = 0.55;
const MAX_URLS = 10;
const FETCH_CONCURRENCY = 3;
const FETCH_TIMEOUT_MS = 15000;
const HEALTH_TIMEOUT_MS = 5000;

let cachedApiBase = DEFAULT_API_BASE;

async function getApiBase() {
  try {
    const stored = await chrome.storage.sync.get(["apiBase"]);
    const base = (stored.apiBase || DEFAULT_API_BASE).trim().replace(/\/$/, "");
    cachedApiBase = base || DEFAULT_API_BASE;
  } catch {
    cachedApiBase = DEFAULT_API_BASE;
  }
  return cachedApiBase;
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "sync" && changes.apiBase) {
    cachedApiBase = (changes.apiBase.newValue || DEFAULT_API_BASE).trim().replace(/\/$/, "");
  }
});

function fetchWithTimeout(url, options, timeoutMs = FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, { ...options, signal: controller.signal }).finally(() => clearTimeout(timer));
}

function unwrapGoogleRedirect(href) {
  try {
    const u = new URL(href);
    if (u.hostname === "www.google.com" && u.pathname === "/url") {
      const q = u.searchParams.get("q");
      return q || href;
    }
  } catch {
    /* ignore */
  }
  return href;
}

function normalizeUrlList(urls) {
  const out = [];
  const seen = new Set();
  for (const raw of urls || []) {
    let u = unwrapGoogleRedirect(String(raw || "").trim());
    if (!u || seen.has(u)) continue;
    if (!/^https?:\/\//i.test(u)) {
      if (/^www\./i.test(u)) u = `https://${u}`;
      else continue;
    }
    seen.add(u);
    out.push(u);
  }
  return out;
}

async function checkBackendHealth() {
  const apiBase = await getApiBase();
  try {
    const res = await fetchWithTimeout(`${apiBase}/health`, { method: "GET" }, HEALTH_TIMEOUT_MS);
    return res.ok;
  } catch (err) {
    console.warn("[phish-ext] health failed:", apiBase, err);
    return false;
  }
}

async function analyzeUrl(url) {
  const apiBase = await getApiBase();
  const res = await fetchWithTimeout(`${apiBase}/analyze/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Fast-Scan": "1" },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function analyzeEmail(emailText) {
  const apiBase = await getApiBase();
  const res = await fetchWithTimeout(`${apiBase}/analyze/email`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email_text: emailText }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function isBackendResultRisky(result) {
  if (result?.prediction === "phishing" && (result?.confidence ?? 0) >= URL_CONFIDENCE_THRESHOLD) {
    return true;
  }
  const p = Number(result?.p_phishing);
  return !Number.isNaN(p) && p >= EXTENSION_UNCERTAIN_PHISH;
}

async function scanUrls(urls) {
  const riskyUrls = [];
  let urlsScored = 0;
  let urlsFailed = 0;
  let index = 0;
  const list = urls.slice(0, MAX_URLS);

  async function worker() {
    while (index < list.length) {
      const i = index++;
      const url = list[i];
      try {
        const result = await analyzeUrl(url);
        urlsScored += 1;
        if (isBackendResultRisky(result) && !riskyUrls.includes(url)) riskyUrls.push(url);
      } catch (err) {
        urlsFailed += 1;
        console.error("[phish-ext] URL error:", url, err);
      }
    }
  }

  const n = Math.min(FETCH_CONCURRENCY, list.length);
  if (n > 0) await Promise.all(Array.from({ length: n }, () => worker()));
  return { riskyUrls, urlsScored, urlsFailed };
}

async function analyzePagePayload(urls, emailText, options = {}) {
  const analyzeEmail = options.analyzeEmail !== false;
  const sampleUrls = normalizeUrlList(urls);

  const healthy = await checkBackendHealth();
  if (!healthy) {
    return {
      riskyUrls: [],
      riskLevel: "LOW",
      emailResult: { prediction: "safe", confidence: 0 },
      emailAnalysisIncluded: analyzeEmail && String(emailText || "").trim().length > 0,
      scannedUrlCount: sampleUrls.length,
      riskyUrlCount: 0,
      urlsScored: 0,
      backendOnline: false,
      backendUnavailable: true,
    };
  }

  let riskyUrls = [];
  let urlsScored = 0;
  let urlsFailed = 0;

  if (sampleUrls.length > 0) {
    const r = await scanUrls(sampleUrls);
    riskyUrls = r.riskyUrls;
    urlsScored = r.urlsScored;
    urlsFailed = r.urlsFailed;
  }

  let emailResult = { prediction: "safe", confidence: 0 };
  if (analyzeEmail && String(emailText || "").trim()) {
    try {
      emailResult = await analyzeEmail(emailText);
    } catch (err) {
      console.error("[phish-ext] email error:", err);
    }
  }

  const emailPhish = analyzeEmail && isBackendResultRisky(emailResult);
  const riskLevel =
    riskyUrls.length > 3 || emailPhish ? "HIGH" : riskyUrls.length ? "MEDIUM" : "LOW";

  return {
    riskyUrls,
    riskLevel,
    emailResult,
    emailAnalysisIncluded: analyzeEmail && String(emailText || "").trim().length > 0,
    scannedUrlCount: sampleUrls.length,
    riskyUrlCount: riskyUrls.length,
    urlsScored,
    urlsFailed,
    backendOnline: true,
    backendUnavailable: false,
    scanIncomplete: sampleUrls.length > 0 && urlsScored === 0 && urlsFailed > 0,
  };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "GET_API_BASE") {
    getApiBase().then((base) => sendResponse({ apiBase: base }));
    return true;
  }

  if (message?.type === "SET_API_BASE") {
    const base = String(message.apiBase || DEFAULT_API_BASE)
      .trim()
      .replace(/\/$/, "");
    chrome.storage.sync.set({ apiBase: base }, () => {
      cachedApiBase = base;
      sendResponse({ ok: true, apiBase: base });
    });
    return true;
  }

  if (message?.type === "PING_HEALTH") {
    checkBackendHealth().then((ok) => sendResponse({ ok, apiBase: cachedApiBase }));
    return true;
  }

  if (message?.type === "AUTO_SCAN") {
    (async () => {
      try {
        const { urls = [], emailText = "", analyzeEmail: doEmail = true } = message;
        const out = await analyzePagePayload(urls, emailText, { analyzeEmail: doEmail });
        sendResponse({ ok: true, ...out });
      } catch (error) {
        sendResponse({ ok: false, error: error.message || "Scan failed" });
      }
    })();
    return true;
  }

  if (message?.type !== "RUN_SCAN") return false;

  (async () => {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const pageData = await chrome.tabs.sendMessage(tab.id, { type: "COLLECT_PAGE_DATA" });
      const doEmail = Boolean(pageData?.useEmailContext);
      const out = await analyzePagePayload(pageData?.urls || [], pageData?.emailText || "", {
        analyzeEmail: doEmail,
      });
      try {
        await chrome.tabs.sendMessage(tab.id, { type: "SCAN_RESULT", ...out });
      } catch {
        /* tab may not have content script */
      }
      sendResponse({
        ok: true,
        riskLevel: out.riskLevel,
        scannedUrlCount: out.scannedUrlCount,
        riskyUrlCount: out.riskyUrlCount,
        emailPrediction: out.emailResult.prediction,
        emailConfidence: out.emailResult.confidence,
        backendUnavailable: out.backendUnavailable,
        backendOnline: out.backendOnline,
        urlsScored: out.urlsScored,
      });
    } catch (error) {
      sendResponse({ ok: false, error: error.message || "Scan failed" });
    }
  })();

  return true;
});

getApiBase();
