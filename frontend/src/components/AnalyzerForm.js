import { useState } from "react";

/** Single-line http(s)/www URL → URL scan; otherwise email scan. */
export function detectInputKind(text) {
  const t = (text || "").trim();
  if (!t) return null;

  const lines = t.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (lines.length > 1) return "email";

  const one = lines[0];
  if (/^mailto:/i.test(one)) return "email";
  if (/^https?:\/\//i.test(one)) return "url";
  if (/^www\./i.test(one)) return "url";
  if (
    one.includes("@") &&
    (one.includes(" ") || /^[^\s]+@[^\s]+\.[^\s]+/.test(one))
  ) {
    return "email";
  }
  if (/^(from|to|subject|date):/im.test(t)) return "email";

  try {
    const withProto = /^https?:\/\//i.test(one) ? one : `https://${one}`;
    const u = new URL(withProto);
    if (u.hostname && u.hostname.includes(".") && one.length < 2048 && !one.includes(" ")) {
      return "url";
    }
  } catch {
    /* not a URL */
  }

  return "email";
}

export function normalizeUrlInput(text) {
  const t = text.trim();
  if (/^https?:\/\//i.test(t)) return t;
  if (/^www\./i.test(t)) return `https://${t}`;
  return `https://${t}`;
}

function AnalyzerForm({ onAnalyze, loading }) {
  const [input, setInput] = useState("");

  const submit = (event) => {
    event.preventDefault();
    const trimmed = input.trim();
    if (!trimmed) return;
    onAnalyze(trimmed);
  };

  return (
    <form className="card analyzer-unified" onSubmit={submit}>
      <h2>Analyze URL or email</h2>
      <p className="analyzer-hint">
        Paste one link (e.g. https://example.com) or full email text. The system picks the right scan automatically.
      </p>
      <textarea
        className="textarea textarea--unified"
        placeholder={"URL: https://example.com\nOr paste email headers and body..."}
        value={input}
        onChange={(e) => setInput(e.target.value)}
        rows={6}
      />
      <button className="button" type="submit" disabled={loading || !input.trim()}>
        {loading ? "Analyzing..." : "Analyze"}
      </button>
    </form>
  );
}

export default AnalyzerForm;
