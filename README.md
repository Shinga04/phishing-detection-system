# Multi-Vector Phishing Detection System

Production-style phishing detection pipeline using:
- React dashboard (Axios)
- FastAPI backend
- Scikit-learn ensemble model (RandomForest + GradientBoosting via VotingClassifier)
- LIME explainability
- Chrome Extension (Manifest v3)

## Project Structure

```text
backend/
  main.py
  model.py
  feature_engineering.py
  explain.py
  requirements.txt
frontend/
  package.json
  public/index.html
  src/
    App.js
    styles.css
    components/
    pages/
extension/
  manifest.json
  content.js
  background.js
  popup.html
  popup.js
desktop_agent/
  screen_agent.py
  gui_agent.py
  requirements.txt
data/
models/
```

## Backend Setup (FastAPI + ML)

1. Create a virtual environment and install dependencies:

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

2. Ensure a CSV dataset exists in `/data` with a `label` column:
- `label`: `0` for safe, `1` for phishing
- If not present, fallback synthetic data is generated automatically.

3. Run API:

```bash
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

4. Test endpoints:
- `POST /analyze/url`
  ```json
  { "url": "http://example.com" }
  ```
- `POST /analyze/email`
  ```json
  { "email_text": "Urgent: verify your password now." }
  ```

Response format:
```json
{
  "prediction": "phishing",
  "confidence": 0.91,
  "features": {},
  "explanation": []
}
```

## Frontend Setup (React)

```bash
cd frontend
npm install
npm start
```

App runs at `http://localhost:3000` and calls backend at `http://127.0.0.1:8000`.

## Chrome Extension Setup

1. Open Chrome -> `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the `extension` folder
5. Open any webpage and click extension button -> **Scan for Phishing**

Behavior (v2 — email & links only):
- **Webmail** (Gmail, Outlook, Yahoo): floating badge scans **links in the open message** + **email text** via the API.
- **Other websites:** no badge; use popup **Scan this tab** (links in page + email text on webmail only).
- **States:** green = safe, red = risky, orange ? = API offline, yellow = scanning.
- **Popup:** set `http://127.0.0.1:8000`, **Test backend connection**, then scan.
- Display-ad / malvertising detection is **out of scope** for the extension.

## Desktop Agent Setup (Browser OCR + optional full screen)

**Default:** captures **Chrome, Edge, and Firefox windows only** (Windows) so phishing pages and visible links are scanned without reading your whole desktop.

Use `--capture-mode all` for WhatsApp Desktop, Outlook Desktop, or other non-browser apps.

1. Install Tesseract OCR (Windows):
- Download installer: [Tesseract OCR (UB Mannheim)](https://github.com/UB-Mannheim/tesseract/wiki)
- Install and ensure `tesseract.exe` is available in PATH.

2. Install Python dependencies:

```bash
cd desktop_agent
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

3. Run one-time scan:

```bash
python screen_agent.py
```

4. Run continuous scan (every 10s):

```bash
python screen_agent.py --interval 10
```

- **Browser capture (default):** `--capture-mode browser` OCRs up to 3 visible browser windows (Chrome/Edge/Firefox on Windows).
- **Foreground browser:** `--capture-mode foreground` scans only the active window if it is a browser.
- **All monitors:** `--capture-mode all` captures each physical display (`--monitor 0` = all, `1` = primary only).
- **Fallback:** if no browser is open, the agent falls back to all monitors unless you pass `--no-fallback-all`.
- **Multi-pass OCR:** Tesseract runs with multiple page-segmentation modes per capture.
- **URL repair:** Fixes common OCR glitches (`https: / /`, spaces in `www.`, `hxxp://`, etc.) before extraction.
- **Desktop scoring:** Uses fast-scan API + `p_phishing >= 0.55` (aligned with the extension).
- **Debug OCR:** `python screen_agent.py --debug` prints capture metadata, OCR preview, and URLs.

5. Optional — GUI with extension-style orb (bottom-**left**, opposite the Chrome FAB):

```bash
python gui_agent.py
```

Orb only (minimal UI — click orb to scan, right-click for settings):

```bash
python gui_agent.py --orb-only
```

Behavior:
- Captures browser windows (or full screen when configured) locally
- Extracts text + URLs via OCR
- Sends URL/text to FastAPI backend
- **Always-on-top orb** (bottom-**left**): same colors as the extension — gray idle, amber scanning, green safe, orange caution, red high risk, orange `?` offline
- **Toast** above the orb with a short plain-English summary (like the extension)
- **Click orb** = scan once; **right-click orb** = open settings window
- Logs risk level and risky URLs in the settings window

## Notes

- Model artifact is saved to `models/phishing_model.pkl`
- Scaler and training features are saved in `models/` for consistent inference + LIME
- API includes CORS enabled for local frontend and extension communication
- Desktop agent does not upload screenshots by default; it sends extracted text/URLs only
