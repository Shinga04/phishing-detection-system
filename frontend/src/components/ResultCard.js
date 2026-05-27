import LimeExplanationPanel from "./LimeExplanationPanel";
import PhishingRecommendation from "./PhishingRecommendation";
import { resolveScanType } from "../config/limeExplanationConfig";

function ResultCard({ result, scanType }) {
  if (!result) return null;

  const confidence = Math.round((result.confidence || 0) * 100);
  const isPhishing = result.prediction === "phishing";
  const resolvedScanType = resolveScanType(result, scanType);

  const hasExplanations =
    (Array.isArray(result.explanation_friendly) && result.explanation_friendly.length > 0) ||
    (Array.isArray(result.explanation) && result.explanation.length > 0);

  return (
    <div className="card result-card">
      <h2>Analysis Result</h2>
      <p className="result-scan-type">
        Scan type: {resolvedScanType === "url" ? "URL" : "Email"}
      </p>
      <p className={`tag ${isPhishing ? "danger" : "safe"}`}>
        {isPhishing ? "Phishing" : "Safe"}
      </p>

      <div className="progress-wrap">
        <div className="progress-label">Confidence: {confidence}%</div>
        <div className="progress-bg">
          <div className="progress-fill" style={{ width: `${confidence}%` }} />
        </div>
      </div>

      <PhishingRecommendation isPhishing={isPhishing} scanType={resolvedScanType} />

      {hasExplanations ? (
        <LimeExplanationPanel result={result} scanType={resolvedScanType} />
      ) : (
        <p className="lime-explanations__empty">No detailed explanation available for this scan.</p>
      )}
    </div>
  );
}

export default ResultCard;
