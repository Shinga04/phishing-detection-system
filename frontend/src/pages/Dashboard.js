import { useCallback, useEffect, useState } from "react";
import axios from "axios";
import AnalyzerForm from "../components/AnalyzerForm";
import LearningStats from "../components/LearningStats";
import ResultCard from "../components/ResultCard";

const API_BASE = "http://127.0.0.1:8000";

function Dashboard() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [lastInput, setLastInput] = useState(null);
  const [learningStats, setLearningStats] = useState(null);
  const [feedbackStatus, setFeedbackStatus] = useState("");
  const [retrainLoading, setRetrainLoading] = useState(false);

  const fetchStats = useCallback(async () => {
    try {
      const { data } = await axios.get(`${API_BASE}/learning/stats`);
      setLearningStats(data);
    } catch {
      setLearningStats(null);
    }
  }, []);

  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  const handleApi = async (path, payload, meta) => {
    setLoading(true);
    setError("");
    setFeedbackStatus("");
    try {
      const { data } = await axios.post(`${API_BASE}${path}`, payload);
      setResult(data);
      setLastInput(meta);
    } catch (err) {
      setResult(null);
      setLastInput(null);
      setError(err?.response?.data?.detail || "Unable to analyze input. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleFeedback = async (label) => {
    if (!lastInput || !result) return;
    setFeedbackStatus("loading");
    try {
      const pPhish = result._meta?.p_phishing ?? (result.prediction === "phishing" ? result.confidence : 1 - result.confidence);
      await axios.post(`${API_BASE}/feedback`, {
        sample_type: lastInput.sample_type,
        input_text: lastInput.input_text,
        label,
        features: result.features || {},
        prediction: result.prediction,
        confidence: result.confidence,
        p_phishing: pPhish,
      });
      setFeedbackStatus("ok");
      fetchStats();
    } catch {
      setFeedbackStatus("error");
    }
  };

  const handleRetrain = async () => {
    setRetrainLoading(true);
    setError("");
    try {
      const { data } = await axios.post(`${API_BASE}/learning/retrain`);
      setLearningStats(data);
    } catch (err) {
      setError(err?.response?.data?.detail || "Retrain failed.");
    } finally {
      setRetrainLoading(false);
    }
  };

  return (
    <main className="container">
      <header className="header card">
        <h1>Phishing Detection System</h1>
      </header>

      <LearningStats
        stats={learningStats}
        onRetrain={handleRetrain}
        retrainLoading={retrainLoading}
      />

      <AnalyzerForm
        loading={loading}
        onAnalyzeUrl={(url) =>
          handleApi("/analyze/url", { url }, { sample_type: "url", input_text: url })
        }
        onAnalyzeEmail={(email_text) =>
          handleApi("/analyze/email", { email_text }, { sample_type: "email", input_text: email_text })
        }
      />

      {loading && <div className="card spinner">Scanning with AI model...</div>}
      {error && <div className="card error">{error}</div>}
      <ResultCard
        result={result}
        onFeedback={lastInput ? handleFeedback : null}
        feedbackStatus={feedbackStatus}
      />
    </main>
  );
}

export default Dashboard;
