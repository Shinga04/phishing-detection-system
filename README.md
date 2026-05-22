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

Behavior:
- **Floating badge** (bottom-right on each page): gray = idle, pulsing yellow = scanning, green = safer sample, red = possible phishing; **toast** explains the result.
- **Auto-scan:** after load and when the page changes (debounced), samples links + page text and calls the backend (at most about once every 45s per tab unless you **click the badge** to force a scan).
- Popup **Scan for Phishing** still works; results also update the badge and highlights.
- Sends URL/email-like page text to FastAPI backend; highlights risky links in **red** and others in **green**

## Desktop Agent Setup (Scan Non-Browser Screens)

Use this for desktop apps like WhatsApp Desktop, Outlook Desktop, etc.

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

- **All monitors (default `--monitor 0`):** captures **each physical display** separately, runs OCR on all of them, and merges text (not only the primary screen).
- **Multi-pass OCR:** Tesseract runs with multiple page-segmentation modes (block + sparse + auto) per capture so chat-style UIs (e.g. WhatsApp Desktop) are less likely to miss links.
- **URL repair:** Fixes common OCR glitches (`https: / /`, spaces in `www.`, `hxxp://`, etc.) before extraction.
- **Desktop scoring:** URL phishing uses a slightly lower confidence cutoff than the browser (OCR often garbles characters); ambiguous OCR + link-like fragments can raise **MEDIUM** with a caution message.
- **Short links & bare domains:** `bit.ly`, `t.co`, `wa.me`, `chat.whatsapp.com`, bare `domain.tld/path`, etc.
- **Debug OCR:** `python screen_agent.py --debug` prints OCR preview and extracted URLs. Use `--monitor 1` to scan **primary display only**.

5. Optional — small GUI (start/stop, interval, log):

```bash
python gui_agent.py
```

Behavior:
- Captures visible screen content locally
- Extracts text + URLs via OCR
- Sends URL/text to FastAPI backend
- **Always-on-top status orb** (bottom-right of the screen): gray idle, pulsing amber while scanning, green = low risk, orange = medium, red = high / phishing email signal, purple = error
- Logs risk level and risky URLs in the window

## Notes

- Model artifact is saved to `models/phishing_model.pkl`
- Scaler and training features are saved in `models/` for consistent inference + LIME
- API includes CORS enabled for local frontend and extension communication
- Desktop agent does not upload screenshots by default; it sends extracted text/URLs only
