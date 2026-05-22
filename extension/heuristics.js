/**
 * Lightweight client-side URL signals for malvertising / phishing when the API is down.
 * Not a replacement for the ML backend — used as fallback with clear UI labeling.
 */
(function (root) {
  const SUSPICIOUS_TLDS = new Set([
    "zip",
    "mov",
    "top",
    "xyz",
    "cam",
    "work",
    "click",
    "link",
    "gq",
    "tk",
    "ml",
    "cf",
    "ga",
    "loan",
    "download",
    "racing",
    "win",
    "bid",
  ]);

  const SHORTENER_HOSTS = new Set([
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "cutt.ly",
    "rb.gy",
  ]);

  const LOGIN_PATH_HINTS = ["login", "signin", "verify", "account", "password", "secure", "update", "banking"];

  function normalizeCandidate(raw) {
    if (!raw || typeof raw !== "string") return "";
    let s = raw.trim();
    if (!s || s.startsWith("#") || s.toLowerCase().startsWith("javascript:")) return "";
    if (s.toLowerCase().startsWith("data:")) return "";
    if (s.toLowerCase().startsWith("mailto:") || s.toLowerCase().startsWith("tel:")) return "";
    if (s.toLowerCase().startsWith("www.")) s = `https://${s}`;
    try {
      const u = new URL(s);
      if (u.protocol !== "http:" && u.protocol !== "https:") return "";
      return u.href;
    } catch {
      return "";
    }
  }

  function unwrapGoogleRedirect(href) {
    try {
      const u = new URL(href);
      if (u.hostname === "www.google.com" && u.pathname === "/url") {
        return normalizeCandidate(u.searchParams.get("q") || "");
      }
    } catch {
      /* ignore */
    }
    return normalizeCandidate(href);
  }

  function scoreUrlHeuristic(url) {
    const normalized = unwrapGoogleRedirect(url);
    if (!normalized) return { risky: false, score: 0, url: "", reasons: [] };

    let score = 0;
    const reasons = [];

    try {
      const u = new URL(normalized);
      const host = u.hostname.toLowerCase();
      const path = (u.pathname + u.search).toLowerCase();

      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
        score += 2;
        reasons.push("IP-based host");
      }

      const labels = host.split(".");
      const tld = labels[labels.length - 1] || "";
      if (SUSPICIOUS_TLDS.has(tld)) {
        score += 2;
        reasons.push(`Suspicious TLD (.${tld})`);
      }

      if (labels.length >= 4) {
        score += 1;
        reasons.push("Many subdomains");
      }

      if (host.includes("xn--") || /[^\x00-\x7F]/.test(host)) {
        score += 2;
        reasons.push("Internationalized / homoglyph domain");
      }

      for (const sh of SHORTENER_HOSTS) {
        if (host === sh || host.endsWith(`.${sh}`)) {
          score += 1;
          reasons.push("URL shortener");
          break;
        }
      }

      if (path.includes("@")) {
        score += 2;
        reasons.push("@ in URL path");
      }

      if (u.protocol === "http:" && LOGIN_PATH_HINTS.some((k) => path.includes(k))) {
        score += 2;
        reasons.push("HTTP with login-like path");
      }

      if (LOGIN_PATH_HINTS.some((k) => path.includes(k))) {
        score += 1;
        reasons.push("Login/verify keyword in path");
      }

      if (path.includes("redirect") || path.includes("url=") || path.includes("goto=")) {
        score += 1;
        reasons.push("Redirect parameter");
      }
    } catch {
      return { risky: false, score: 0, url: normalized, reasons: [] };
    }

    return {
      risky: score >= 3,
      score,
      url: normalized,
      reasons,
    };
  }

  function filterRiskyHeuristic(urls) {
    const risky = [];
    const seen = new Set();
    for (const raw of urls || []) {
      const h = scoreUrlHeuristic(raw);
      if (!h.url || seen.has(h.url)) continue;
      seen.add(h.url);
      if (h.risky) risky.push(h.url);
    }
    return risky;
  }

  const api = {
    normalizeCandidate,
    unwrapGoogleRedirect,
    scoreUrlHeuristic,
    filterRiskyHeuristic,
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else if (typeof root !== "undefined") {
    root.PhishHeuristics = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : self);
