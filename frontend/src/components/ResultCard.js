function polarityClass(polarity) {
  if (polarity === "elevated_risk") return "explain-impact explain-impact--risk";
  if (polarity === "legitimacy_support") return "explain-impact explain-impact--safe";
  if (polarity === "neutral") return "explain-impact explain-impact--neutral";
  return "explain-impact explain-impact--info";
}

function ResultCard({ result, onFeedback, feedbackStatus }) {
  if (!result) return null;

  const confidence = Math.round((result.confidence || 0) * 100);
  const isPhishing = result.prediction === "phishing";

  const friendly = Array.isArray(result.explanation_friendly) ? result.explanation_friendly : [];
  const useFriendly = friendly.length > 0;

  return (
    <div className="card">
      <h2>Analysis Result</h2>
      <p className={`tag ${isPhishing ? "danger" : "safe"}`}>
        {isPhishing ? "Phishing" : "Safe"}
      </p>

      <div className="progress-wrap">
        <div className="progress-label">Confidence: {confidence}%</div>
        <div className="progress-bg">
          <div className="progress-fill" style={{ width: `${confidence}%` }} />
        </div>
      </div>

      <h3>Top Feature Explanations</h3>
      {useFriendly ? (
        <ul className="explain-list">
          {friendly.map((item, idx) => (
            <li key={`${item.raw || idx}-${idx}`} className={polarityClass(item.impact_polarity)}>
              <div className="explain-title">{item.title || "Signal"}</div>
              <p className="explain-body">{item.security_impact || item.raw}</p>
              {item.condition != null && item.weight != null && (
                <div className="explain-meta">
                  <span className="explain-condition">{item.condition}</span>
                  <span className="explain-weight">weight: {item.weight}</span>
                </div>
              )}
            </li>
          ))}
        </ul>
      ) : (
        <ul className="explain-list explain-list--raw">
          {(result.explanation || []).map((item, idx) => (
            <li key={`${item}-${idx}`} className="explain-impact explain-impact--info">
              {item}
            </li>
          ))}
        </ul>
      )}

      {onFeedback && (
        <div className="feedback-row">
          <p className="feedback-label">Help improve the model:</p>
          <div className="feedback-actions">
            <button
              type="button"
              className="btn danger-outline"
              disabled={feedbackStatus === "loading"}
              onClick={() => onFeedback(1)}
            >
              Report as Phishing
            </button>
            <button
              type="button"
              className="btn safe-outline"
              disabled={feedbackStatus === "loading"}
              onClick={() => onFeedback(0)}
            >
              Mark as Safe
            </button>
          </div>
          {feedbackStatus === "ok" && (
            <p className="feedback-msg">Thanks — sample saved for next retrain.</p>
          )}
          {feedbackStatus === "error" && (
            <p className="feedback-msg feedback-msg--error">Could not save feedback.</p>
          )}
        </div>
      )}
    </div>
  );
}

export default ResultCard;
