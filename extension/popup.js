const scanBtn = document.getElementById("scanBtn");
const result = document.getElementById("result");
const apiBaseInput = document.getElementById("apiBase");
const saveApiBtn = document.getElementById("saveApiBtn");

function riskClass(risk) {
  if (risk === "HIGH") return "danger";
  if (risk === "MEDIUM") return "warn";
  return "safe";
}

function loadApiBase() {
  chrome.runtime.sendMessage({ type: "GET_API_BASE" }, (res) => {
    if (res?.apiBase) apiBaseInput.value = res.apiBase;
  });
}
loadApiBase();

document.getElementById("testApiBtn")?.addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "PING_HEALTH" }, (res) => {
    if (res?.ok) {
      result.innerHTML = `<span class="safe">Backend OK — ${res.apiBase || apiBaseInput.value}</span>`;
    } else {
      result.innerHTML = `<span class="danger">Cannot reach backend. Run uvicorn on port 8000.</span>`;
    }
  });
});

saveApiBtn.addEventListener("click", () => {
  const apiBase = apiBaseInput.value.trim();
  chrome.runtime.sendMessage({ type: "SET_API_BASE", apiBase }, (res) => {
    if (res?.ok) {
      result.innerHTML = `<span class="safe">Saved: ${res.apiBase}</span>`;
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
      statusLine = `<div class="offline"><strong>API:</strong> offline</div>`;
    } else {
      statusLine = `<div class="safe"><strong>API:</strong> online (${response.urlsScored || 0} links scored)</div>`;
    }

    result.innerHTML = `
      ${statusLine}
      <div class="${riskClass(response.riskLevel)}"><strong>Risk:</strong> ${response.riskLevel}</div>
      <div><strong>Links scanned:</strong> ${response.scannedUrlCount}</div>
      <div><strong>Risky links:</strong> ${response.riskyUrlCount}</div>
      <div><strong>Email:</strong> ${response.emailPrediction} (${Math.round((response.emailConfidence || 0) * 100)}%)</div>
    `;
  } catch (error) {
    result.innerHTML = `<span class="danger">Scan failed: ${error.message}</span>`;
  }
});
