importScripts("heuristics.js");

const DEFAULT_API_BASE = "http://127.0.0.1:8000";
const URL_CONFIDENCE_THRESHOLD = 0.5;
const MAX_URLS_PER_SCAN = 30;

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

async function analyzeUrl(url) {
  const apiBase = await getApiBase();
  const res = await fetch(`${apiBase}/analyze/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) throw new Error(`URL analysis failed (${res.status})`);
  return res.json();
}

async function analyzeEmail(emailText) {
  const apiBase = await getApiBase();
  const res = await fetch(`${apiBase}/analyze/email`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email_text: emailText }),
  });
  if (!res.ok) throw new Error(`Email analysis failed (${res.status})`);
  return res.json();
}

function isBackendResultRisky(result) {
  return result?.prediction === "phishing" && (result?.confidence ?? 0) >= URL_CONFIDENCE_THRESHOLD;
}

async function analyzePagePayload(urls, emailText, options = {}) {
  const analyzeEmailFlag = options.analyzeEmail !== false;
  const sampleUrls = [...new Set((urls || []).map((u) => PhishHeuristics.unwrapGoogleRedirect(u)).filter(Boolean))].slice(
    0,
    MAX_URLS_PER_SCAN
  );

  const riskyUrls = [];
  const heuristicRiskyUrls = PhishHeuristics.filterRiskyHeuristic(sampleUrls);
  let urlsScored = 0;
  let urlsFailed = 0;

  for (const url of sampleUrls) {
    try {
      const result = await analyzeUrl(url);
      urlsScored += 1;
      if (isBackendResultRisky(result)) riskyUrls.push(url);
    } catch (err) {
      urlsFailed += 1;
      console.error("URL scan error:", url, err);
    }
  }

  const backendReachable = sampleUrls.length === 0 ? true : urlsScored > 0;
  const backendUnavailable = sampleUrls.length > 0 && urlsScored === 0;

  // Offline / API down: apply client heuristics so malvertising URLs are not marked "safe"
  if (backendUnavailable && heuristicRiskyUrls.length) {
    for (const u of heuristicRiskyUrls) {
      if (!riskyUrls.includes(u)) riskyUrls.push(u);
    }
  }

  let emailResult = { prediction: "safe", confidence: 0 };
  let emailScored = false;
  if (analyzeEmailFlag && String(emailText || "").trim()) {
    try {
      emailResult = await analyzeEmail(emailText);
      emailScored = true;
    } catch (err) {
      console.error("Email scan error:", err);
      if (backendUnavailable) {
        const low = emailText.toLowerCase();
        const scam =
          low.includes("western union") ||
          low.includes("mtcn") ||
          low.includes("verify your account") ||
          low.includes("click here") ||
          low.includes("urgent");
        if (scam) {
          emailResult = { prediction: "phishing", confidence: 0.7, heuristic: true };
        }
      }
    }
  }

  const emailPhish = analyzeEmailFlag && emailResult.prediction === "phishing";
  const riskLevel =
    riskyUrls.length > 5 || emailPhish ? "HIGH" : riskyUrls.length ? "MEDIUM" : "LOW";

  return {
    riskyUrls,
    heuristicRiskyUrls,
    riskLevel,
    emailResult,
    emailAnalysisIncluded: analyzeEmailFlag && String(emailText || "").trim().length > 0,
    scannedUrlCount: sampleUrls.length,
    riskyUrlCount: riskyUrls.length,
    urlsScored,
    urlsFailed,
    backendReachable,
    backendUnavailable,
    heuristicOnly: backendUnavailable && heuristicRiskyUrls.length > 0,
    emailScored,
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
      await chrome.tabs.sendMessage(tab.id, { type: "HIGHLIGHT_RISK", riskyUrls: out.riskyUrls });
      await chrome.tabs.sendMessage(tab.id, {
        type: "AUTO_SCAN_RESULT",
        ...out,
        emailAnalysisIncluded: out.emailAnalysisIncluded,
      });

      sendResponse({
        ok: true,
        riskLevel: out.riskLevel,
        scannedUrlCount: out.scannedUrlCount,
        riskyUrlCount: out.riskyUrlCount,
        emailPrediction: out.emailResult.prediction,
        emailConfidence: out.emailResult.confidence,
        emailAnalysisIncluded: out.emailAnalysisIncluded,
        backendUnavailable: out.backendUnavailable,
        heuristicOnly: out.heuristicOnly,
        urlsScored: out.urlsScored,
      });
    } catch (error) {
      sendResponse({ ok: false, error: error.message || "Scan failed" });
    }
  })();

  return true;
});

getApiBase();
