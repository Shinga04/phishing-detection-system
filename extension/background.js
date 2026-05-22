const API_BASE = "http://127.0.0.1:8000";

async function analyzeUrl(url) {
  const res = await fetch(`${API_BASE}/analyze/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) throw new Error("URL analysis failed");
  return res.json();
}

async function analyzeEmail(emailText) {
  const res = await fetch(`${API_BASE}/analyze/email`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email_text: emailText }),
  });
  if (!res.ok) throw new Error("Email analysis failed");
  return res.json();
}

async function analyzePagePayload(urls, emailText, options = {}) {
  const analyzeEmailFlag = options.analyzeEmail !== false;
  const sampleUrls = (urls || []).slice(0, 20);
  const riskyUrls = [];

  for (const url of sampleUrls) {
    try {
      const result = await analyzeUrl(url);
      if (result.prediction === "phishing" && result.confidence >= 0.5) riskyUrls.push(url);
    } catch (err) {
      console.error("URL scan error:", err);
    }
  }

  let emailResult = { prediction: "safe", confidence: 0 };
  if (analyzeEmailFlag && String(emailText || "").trim()) {
    try {
      emailResult = await analyzeEmail(emailText);
    } catch (err) {
      console.error("Email scan error:", err);
    }
  }

  const emailPhish = analyzeEmailFlag && emailResult.prediction === "phishing";
  const riskLevel =
    riskyUrls.length > 5 || emailPhish ? "HIGH" : riskyUrls.length ? "MEDIUM" : "LOW";

  return {
    riskyUrls,
    riskLevel,
    emailResult,
    emailAnalysisIncluded: analyzeEmailFlag && String(emailText || "").trim().length > 0,
    scannedUrlCount: sampleUrls.length,
    riskyUrlCount: riskyUrls.length,
  };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
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
      });
    } catch (error) {
      sendResponse({ ok: false, error: error.message || "Scan failed" });
    }
  })();

  return true;
});
