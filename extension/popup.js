const scanBtn = document.getElementById("scanBtn");
const result = document.getElementById("result");
const apiBaseInput = document.getElementById("apiBase");
const saveApiBtn = document.getElementById("saveApiBtn");

function riskClass(risk) {
  if (risk === "HIGH") return "danger";
  if (risk === "MEDIUM") return "warn";
  return "safe";
}

chrome.runtime.sendMessage({ type: "GET_API_BASE" }, (res) => {
  if (res?.apiBase) apiBaseInput.value = res.apiBase;
});

saveApiBtn.addEventListener("click", () => {
  const apiBase = apiBaseInput.value.trim();
  chrome.runtime.sendMessage({ type: "SET_API_BASE", apiBase }, (res) => {
    if (res?.ok) {
      result.innerHTML = `<span class="safe">API URL saved: ${res.apiBase}</span>`;
    } else {
      result.innerHTML = `<span class="danger">Could not save API URL.</span>`;
    }
  });
});

scanBtn.addEventListener("click", async () => {
  result.textContent = "Scanning...";
  try {
    const response = await chrome.runtime.sendMessage({ type: "RUN_SCAN" });
    if (!response?.ok) throw new Error(response?.error || "Unknown error");

    let statusLine = "";
    if (response.backendUnavailable) {
      statusLine = `<div class="unknown"><strong>Backend:</strong> offline (heuristic only if risks found)</div>`;
    } else {
      statusLine = `<div class="safe"><strong>Backend:</strong> scored ${response.urlsScored || 0} URL(s)</div>`;
    }

    result.innerHTML = `
      ${statusLine}
      <div class="${riskClass(response.riskLevel)}"><strong>Risk Level:</strong> ${response.riskLevel}</div>
      <div><strong>URLs Scanned:</strong> ${response.scannedUrlCount}</div>
      <div><strong>Risky URLs:</strong> ${response.riskyUrlCount}</div>
      <div><strong>Email Signal:</strong> ${response.emailPrediction} (${Math.round((response.emailConfidence || 0) * 100)}%)</div>
    `;
  } catch (error) {
    result.innerHTML = `<span class="danger">Scan failed: ${error.message}</span>`;
  }
});
