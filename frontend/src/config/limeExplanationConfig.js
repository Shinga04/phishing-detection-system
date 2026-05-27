/**
 * Maps raw LIME / model feature keys to plain-English copy and UI categories.
 * Supports context-aware labels for URL vs email scans.
 */

export const CATEGORY_SECTIONS = [
  { id: "content", label: "Content Analysis" },
  { id: "link", label: "Link Analysis" },
  { id: "sender", label: "Sender Reputation" },
  { id: "other", label: "Additional Signals" },
];

/** Email-only features — hidden on URL scans when feature value is zero. */
export const EMAIL_ONLY_FEATURES = new Set([
  "email_text_length",
  "email_num_links",
  "email_suspicious_keywords",
  "email_has_spoofed_tld",
]);

/**
 * Per scan type: { title, explanation, category } or null to hide on that scan type.
 * @type {Record<string, { url?: object|null, email?: object|null, default?: object }>}
 */
export const FEATURE_DISPLAY_MAP = {
  adv_domain_ngram_entropy: {
    url: {
      title: "Suspicious Domain Name",
      explanation: "The website's domain name appears randomized or unnatural.",
      category: "sender",
    },
    email: {
      title: "Suspicious Sender Domain",
      explanation: "The sender's domain name appears randomized or unnatural.",
      category: "sender",
    },
  },
  email_suspicious_keywords: {
    url: null,
    email: {
      title: "Urgency & Social Engineering",
      explanation:
        "The email uses language commonly designed to create panic or force immediate action.",
      category: "content",
    },
  },
  phish_hyphen_count: {
    default: {
      title: "Excessive Hyphens",
      explanation:
        "The link contains multiple hyphens, a tactic often used to mimic legitimate websites.",
      category: "link",
    },
  },
  email_num_links: {
    url: null,
    email: {
      title: "Unusually High Link Count",
      explanation: "This email contains more links than typical correspondence.",
      category: "link",
    },
  },
  count_dslash: {
    default: {
      title: "Hidden Redirects",
      explanation:
        "The URL structure suggests it may redirect you to a different, hidden destination.",
      category: "link",
    },
  },
  url_length: {
    default: {
      title: "Overly Long URL",
      explanation:
        "The web address is unusually long, which is often used to hide the true destination.",
      category: "link",
    },
  },
  has_login_keyword: {
    url: {
      title: "Login-Related URL Path",
      explanation:
        "The link path mentions login, password, or verification — common in credential phishing pages.",
      category: "link",
    },
    email: {
      title: "Credential-Harvesting Language",
      explanation:
        "The message mentions login, password, or account verification in a pressuring way.",
      category: "content",
    },
  },
  phish_keyword_count: {
    url: {
      title: "Suspicious Terms in URL",
      explanation:
        "The link contains wording often associated with scams or credential theft.",
      category: "link",
    },
    email: {
      title: "Phishing-Oriented Wording",
      explanation:
        "Several terms associated with scams or credential theft appear in the message.",
      category: "content",
    },
  },
  email_text_length: {
    url: null,
    email: {
      title: "Unusual Message Length",
      explanation: "The message length differs from typical email patterns the model has learned.",
      category: "content",
    },
  },
  shortening_services: {
    default: {
      title: "URL Shortener Detected",
      explanation: "A shortened link can hide the real destination until you click.",
      category: "link",
    },
  },
  phish_has_redirect: {
    default: {
      title: "Redirect Pattern",
      explanation: "The link structure resembles known redirect or relay techniques.",
      category: "link",
    },
  },
  phish_many_subdomains: {
    default: {
      title: "Complex Subdomain Chain",
      explanation: "Multiple subdomains can be used to disguise the true host.",
      category: "link",
    },
  },
  phish_long_domain: {
    default: {
      title: "Abnormally Long Domain",
      explanation: "An unusually long hostname can obscure the brand being impersonated.",
      category: "link",
    },
  },
  num_dots: {
    default: {
      title: "Complex Domain Structure",
      explanation: "Many dots in the address often indicate nested or misleading domains.",
      category: "link",
    },
  },
  email_has_spoofed_tld: {
    url: null,
    email: {
      title: "Suspicious Sender Domain",
      explanation: "The sender uses a top-level domain or pattern often seen in spoofing.",
      category: "sender",
    },
  },
  phish_suspicious_tld: {
    default: {
      title: "Risky Top-Level Domain",
      explanation: "The link uses a domain ending frequently abused in phishing campaigns.",
      category: "sender",
    },
  },
  domain_age: {
    default: {
      title: "New or Young Domain",
      explanation: "Recently registered domains are commonly used for short-lived scams.",
      category: "sender",
    },
  },
  adv_subdomain_count: {
    default: {
      title: "Unusual Subdomain Count",
      explanation: "The hostname structure is more complex than typical legitimate sites.",
      category: "sender",
    },
  },
  has_ip: {
    default: {
      title: "IP-Based Link",
      explanation: "The URL points to a numeric IP address instead of a normal domain name.",
      category: "link",
    },
  },
  ssl_valid: {
    default: {
      title: "TLS Certificate Status",
      explanation: "Certificate validity influences how trustworthy the destination appears.",
      category: "other",
    },
  },
  ssl_self_signed: {
    default: {
      title: "Self-Signed Certificate",
      explanation: "Self-signed certificates are uncommon on major legitimate services.",
      category: "other",
    },
  },
  web_has_login: {
    url: {
      title: "Login Surface in URL",
      explanation: "The address suggests a login or sign-in page, which phishers often mimic.",
      category: "link",
    },
  },
};

const SIMPLE_LIME_RE = /^([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*([-+]?(?:\d*\.\d+|\d+)(?:[eE][-+]?\d+)?)\s*$/;
const CONDITION_WEIGHT_RE = /:\s*([-+]?(?:\d*\.\d+|\d+)(?:[eE][-+]?\d+)?)\s*$/;

const FEATURE_KEY_IN_CONDITION = [
  "adv_domain_ngram_entropy",
  "email_suspicious_keywords",
  "phish_hyphen_count",
  "email_num_links",
  "count_dslash",
  "url_length",
  "email_has_spoofed_tld",
  "email_text_length",
  "shortening_services",
  "phish_suspicious_tld",
  "phish_many_subdomains",
  "phish_long_domain",
  "phish_keyword_count",
  "has_login_keyword",
  "phish_has_redirect",
  "num_dots",
  "has_ip",
  "domain_age",
  "adv_subdomain_count",
  "ssl_valid",
  "ssl_self_signed",
  "web_has_login",
  "uses_https",
  "num_special_chars",
];

function humanizeFeatureKey(key) {
  if (!key) return "Security signal";
  return key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export function resolveScanType(result, scanTypeProp) {
  const fromApi = (result?.analysis_type || scanTypeProp || "").toLowerCase();
  return fromApi === "url" || fromApi === "email" ? fromApi : "email";
}

export function resolveFeatureKey(item) {
  if (item?.feature_key) return item.feature_key;
  const raw = String(item?.raw || item?.condition || "").trim();
  const simple = raw.match(SIMPLE_LIME_RE);
  if (simple) return simple[1];

  const condition = String(item?.condition || "").trim();
  for (const name of FEATURE_KEY_IN_CONDITION.sort((a, b) => b.length - a.length)) {
    if (new RegExp(`\\b${name}\\b`).test(condition) || new RegExp(`\\b${name}\\b`).test(raw)) {
      return name;
    }
  }
  const lead = condition.match(/^([a-zA-Z_][a-zA-Z0-9_]*)\s*[<>]=?/);
  if (lead) return lead[1];
  return null;
}

export function parseWeight(item) {
  if (typeof item?.weight === "number" && !Number.isNaN(item.weight)) return item.weight;
  const raw = String(item?.raw || "").trim();
  const m = raw.match(CONDITION_WEIGHT_RE);
  if (m) return parseFloat(m[1]);
  const simple = raw.match(SIMPLE_LIME_RE);
  if (simple) return parseFloat(simple[2]);
  return null;
}

export function getFeatureValue(result, featureKey) {
  const features = result?.features;
  if (!features || featureKey == null) return null;
  const val = features[featureKey];
  if (val == null) return null;
  const num = Number(val);
  return Number.isNaN(num) ? val : num;
}

export function shouldHideFeature(featureKey, scanType, result) {
  if (scanType !== "url" || !featureKey) return false;
  if (!EMAIL_ONLY_FEATURES.has(featureKey)) return false;
  const val = getFeatureValue(result, featureKey);
  return val == null || Number(val) === 0;
}

export function getImpactLevel(absWeight, allWeights) {
  const abs = absWeight ?? 0;
  const max = Math.max(...allWeights.filter((w) => w != null).map(Math.abs), 0.001);
  const ratio = abs / max;
  if (ratio >= 0.66 || abs >= 0.15) return "High";
  if (ratio >= 0.33 || abs >= 0.06) return "Medium";
  return "Low";
}

export function getDisplayForFeature(featureKey, scanType, fallbackTitle, fallbackBody) {
  const entry = featureKey ? FEATURE_DISPLAY_MAP[featureKey] : null;
  if (entry) {
    const mapped = entry[scanType] ?? entry.default ?? entry.email ?? entry.url;
    if (mapped === null) return null;
    if (mapped) {
      return mapped;
    }
  }
  if (scanType === "url" && featureKey && EMAIL_ONLY_FEATURES.has(featureKey)) {
    return null;
  }
  return {
    title: fallbackTitle || humanizeFeatureKey(featureKey),
    explanation: fallbackBody || "This factor influenced the risk assessment.",
    category: scanType === "url" ? "link" : "content",
  };
}

/**
 * Normalize backend explanation_friendly rows or raw LIME strings for the UI.
 */
export function normalizeExplanationItems(result, scanTypeProp) {
  const scanType = resolveScanType(result, scanTypeProp);
  const friendly = Array.isArray(result?.explanation_friendly) ? result.explanation_friendly : [];
  const rawList = Array.isArray(result?.explanation) ? result.explanation : [];
  const source = friendly.length > 0 ? friendly : rawList.map((line) => ({ raw: line }));

  const parsed = [];
  for (const item of source) {
    const featureKey = resolveFeatureKey(item);
    if (shouldHideFeature(featureKey, scanType, result)) continue;

    const weight = parseWeight(item);
    const polarity =
      item?.impact_polarity ||
      (weight == null
        ? "informational"
        : weight > 0
          ? "elevated_risk"
          : weight < 0
            ? "legitimacy_support"
            : "neutral");

    const display = getDisplayForFeature(
      featureKey,
      scanType,
      item?.title,
      item?.security_impact
    );
    if (!display) continue;

    parsed.push({
      featureKey,
      title: display.title,
      explanation: display.explanation,
      category: display.category,
      weight,
      polarity,
      raw: item?.raw,
    });
  }

  const weights = parsed.map((p) => p.weight).filter((w) => w != null);
  return parsed.map((p) => ({
    ...p,
    impactLevel: getImpactLevel(p.weight != null ? Math.abs(p.weight) : 0, weights),
  }));
}

export function groupByCategory(items) {
  const groups = {};
  for (const section of CATEGORY_SECTIONS) {
    groups[section.id] = [];
  }
  for (const item of items) {
    const cat = item.category && groups[item.category] ? item.category : "other";
    groups[cat].push(item);
  }
  return CATEGORY_SECTIONS.filter((s) => groups[s.id].length > 0).map((s) => ({
    ...s,
    items: groups[s.id],
  }));
}

export function getExplanationIntro(scanType) {
  if (scanType === "url") {
    return "Key factors from this URL analysis. Green supports a legitimate site; red supports phishing.";
  }
  return "Key factors from this email analysis. Green supports a legitimate message; red supports phishing.";
}
