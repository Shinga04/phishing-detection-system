function PhishingRecommendation({ isPhishing, scanType }) {
  if (!isPhishing) return null;

  const isUrl = scanType === "url";
  const message = isUrl
    ? "High risk detected. Do not visit this link or enter credentials on this page."
    : "High risk detected. Do not click any links or download attachments. Quarantine this email.";

  return (
    <div className="recommendation-banner" role="alert">
      <strong>Recommendation:</strong> {message}
    </div>
  );
}

export default PhishingRecommendation;
