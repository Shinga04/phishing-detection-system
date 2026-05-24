import { useState } from "react";
import axios from "axios";
import AnalyzerForm, { detectInputKind, normalizeUrlInput } from "../components/AnalyzerForm";
import ResultCard from "../components/ResultCard";

const API_BASE = "http://127.0.0.1:8000";

function Dashboard() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const handleApi = async (path, payload) => {
    setLoading(true);
    setError("");
    try {
      const { data } = await axios.post(`${API_BASE}${path}`, payload);
      setResult(data);
    } catch (err) {
      setResult(null);
      setError(err?.response?.data?.detail || "Unable to analyze input. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleAnalyze = (text) => {
    const kind = detectInputKind(text);
    if (kind === "url") {
      handleApi("/analyze/url", { url: normalizeUrlInput(text) });
    } else {
      handleApi("/analyze/email", { email_text: text.trim() });
    }
  };

  return (
    <main className="container">
      <header className="header card">
        <h1>Phishing Detection System</h1>
      </header>

      <AnalyzerForm loading={loading} onAnalyze={handleAnalyze} />

      {loading && <div className="card spinner">Scanning with AI model...</div>}
      {error && <div className="card error">{error}</div>}
      <ResultCard result={result} />
    </main>
  );
}

export default Dashboard;
