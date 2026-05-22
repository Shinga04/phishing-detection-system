const scanBtn = document.getElementById("scanBtn");
const result = document.getElementById("result");

function riskClass(risk) {
  if (risk === "HIGH") return "danger";
  if (risk === "MEDIUM") return "warn";
  return "safe";
}

scanBtn.addEventListener("click", async () => {
  result.textContent = "Scanning...";
  try {
    const response = await chrome.runtime.sendMessage({ type: "RUN_SCAN" });
    if (!response?.ok) throw new Error(response?.error || "Unknown error");

    result.innerHTML = `
      <div class="${riskClass(response.riskLevel)}"><strong>Risk Level:</strong> ${response.riskLevel}</div>
      <div><strong>URLs Scanned:</strong> ${response.scannedUrlCount}</div>
      <div><strong>Phishing URLs:</strong> ${response.riskyUrlCount}</div>
      <div><strong>Email Signal:</strong> ${response.emailPrediction} (${Math.round((response.emailConfidence || 0) * 100)}%)</div>
    `;
  } catch (error) {
    result.innerHTML = `<span class="danger">Scan failed: ${error.message}</span>`;
  }
});
