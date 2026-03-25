# PhishGuard — Chrome Extension

> Real-time, multi-signal phishing detection with Explainable AI

## 🛡️ Features

| Signal | Weight | Description |
|---|---|---|
| PhishTank API | 1.00 | Verified phishing database lookup |
| Password over HTTP | 0.90 | Credential exposure on insecure pages |
| Unicode Homograph | 0.85 | Cyrillic/IDN domain spoofing detection |
| BitB Detection | 0.85 | Browser-in-the-Browser overlay attacks |
| SSL Certificate | 0.80 | Invalid/self-signed/expired cert check |
| Title↔Domain Mismatch | 0.75 | Brand impersonation via page title |
| Redirect Chain | 0.70 | Multi-hop and cross-TLD redirects |
| CSRF Token Absence | 0.65 | Login forms without CSRF protection |
| Hidden IFrames | 0.60 | Concealed cross-origin iframes |
| External Exfiltration | 0.55 | Pixel trackers, external XHR |
| DOM Signatures | 0.55 | Anti-debug JS, obfuscation, meta-refresh |
| Link/Image Mismatch | 0.45 | Deceptive anchor text vs. href |

## 📁 Project Structure

```
PhishGuard/
├── manifest.json              — Manifest V3
├── background/
│   └── service_worker.js      — PhishTank API, redirects, SSL, caching
├── content/
│   └── content_script.js      — DOM analysis, all 12 signals, auto-block
├── popup/
│   ├── popup.html             — Security dashboard UI
│   ├── popup.css              — Dark-themed styles
│   └── popup.js               — UI logic, settings, history
├── blocker/
│   └── blocker.html           — Full-screen phishing block page
├── utils/
│   ├── signals.js             — All 12 detection modules (tree-shakeable exports)
│   ├── xai.js                 — SHAP+LIME-inspired explainability
│   └── scoring.js             — Weighted risk scoring engine (pure functions)
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

## 🚀 Installation

### Load as Unpacked Extension (Developer Mode)

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **"Load unpacked"**
4. Select the `PhishGuard/` directory
5. The extension is now active — click the 🛡️ icon to view analysis

### Icon Setup
Copy your `icons/phishguard_icon.png` and save three sizes:
- `icons/icon16.png` (16×16)
- `icons/icon48.png` (48×48)  
- `icons/icon128.png` (128×128)

You can use any image editor or the online tool at [favicon.io](https://favicon.io) to resize.

## 🔐 Scoring Engine

```
Final Risk Score = Σ(signal_score × weight) / Σ(weights)

0.00–0.30 → ✅ SAFE       (green badge)
0.31–0.60 → ⚠️ SUSPICIOUS  (amber badge)
0.61–0.79 → 🔶 HIGH RISK  (orange badge)
0.80–1.00 → 🚨 PHISHING   (AUTO-BLOCK)
```

## ⚙️ Configuration

Click the ⚙️ Settings button in the popup to:
- Enable/disable auto-blocking
- Enable/disable PhishTank API checks
- Toggle XAI (Explainable AI) explanations
- Enter a PhishTank API key (optional, increases rate limits)
- View and clear blocked URL history

## 🔬 Explainable AI

The XAI module provides:
- **SHAP-inspired**: Marginal contribution of each signal to the final risk score
- **LIME-inspired**: Which DOM element or URL part triggered each signal
- **Natural language**: Human-readable explanations per signal in the popup

## 🔑 PhishTank API Key

1. Register at [phishtank.org](https://www.phishtank.com/register.php)
2. Get your API key from account settings
3. Enter it in PhishGuard's Settings → PhishTank API Key
4. Paste the key into `background/service_worker.js` line 9:
   ```js
   const PHISHTANK_APP_KEY = 'your_key_here';
   ```

## 🛡️ Privacy

- **No page content is sent to external servers** — only the URL is sent to PhishTank
- All DOM analysis runs locally in your browser
- Session cache expires automatically
- Blocked URL history is stored locally in `chrome.storage.local`

## 📋 Permissions Used

| Permission | Purpose |
|---|---|
| `activeTab` | Read current tab URL and inject content script |
| `scripting` | Inject analysis into pages |
| `webRequest` | Intercept headers for SSL info |
| `webNavigation` | Track redirect chains |
| `storage` | Cache results, settings, blocked history |
| `tabs` | Get current tab metadata |
| `declarativeNetRequest` | URL-level block rules |
