import { useState } from "react";

function AnalyzerForm({ onAnalyzeUrl, onAnalyzeEmail, loading }) {
  const [url, setUrl] = useState("");
  const [emailText, setEmailText] = useState("");

  const submitUrl = (event) => {
    event.preventDefault();
    if (url.trim()) onAnalyzeUrl(url.trim());
  };

  const submitEmail = (event) => {
    event.preventDefault();
    if (emailText.trim()) onAnalyzeEmail(emailText.trim());
  };

  return (
    <div className="form-grid">
      <form className="card" onSubmit={submitUrl}>
        <h2>URL Analysis</h2>
        <input
          type="text"
          className="input"
          placeholder="https://example.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <button className="button" type="submit" disabled={loading}>
          {loading ? "Analyzing..." : "Analyze URL"}
        </button>
      </form>

      <form className="card" onSubmit={submitEmail}>
        <h2>Email Analysis</h2>
        <textarea
          className="textarea"
          placeholder="Paste raw email content..."
          value={emailText}
          onChange={(e) => setEmailText(e.target.value)}
        />
        <button className="button" type="submit" disabled={loading}>
          {loading ? "Analyzing..." : "Analyze Email"}
        </button>
      </form>
    </div>
  );
}

export default AnalyzerForm;
