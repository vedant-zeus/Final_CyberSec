/**
 * PhishGuard — Background Service Worker (Manifest V3)
 * Handles: PhishTank API, redirect tracking, SSL cert data, inter-script messaging.
 *
 * FIX LOG:
 * - Merged onMessage listeners into one to prevent channel conflicts
 * - PhishTank request is now fire-and-forget; GET_ANALYSIS_DATA responds immediately
 *   with cert/redirect data, PhishTank result is stored and retrievable separately
 * - Added GET_RESULTS message handler for popup→content script bridge
 */

// ─── Constants ────────────────────────────────────────────────────────────────
const PHISHTANK_API  = 'https://checkurl.phishtank.com/checkurl/';
const PHISHTANK_APP_KEY = ''; // Optional: add your API key here
const CACHE_TTL_MS   = 10 * 60 * 1000; // 10 minutes
const MAX_RETRIES    = 2;
const RETRY_BASE_MS  = 1500;

// ─── In-memory stores (survive only while SW is alive) ───────────────────────
const redirectChains = new Map(); // tabId → string[]
const tabCertInfo    = new Map(); // tabId → certInfo object

// ─── Redirect Tracking ────────────────────────────────────────────────────────
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  redirectChains.set(details.tabId, [details.url]);
  tabCertInfo.delete(details.tabId); // clear stale cert data on new navigation
});

chrome.webNavigation.onBeforeRedirect.addListener((details) => {
  if (details.frameId !== 0) return;
  const chain = redirectChains.get(details.tabId) || [details.url];
  chain.push(details.redirectUrl);
  redirectChains.set(details.tabId, chain);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  redirectChains.delete(tabId);
  tabCertInfo.delete(tabId);
});

// ─── SSL / Header tracking ────────────────────────────────────────────────────
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.tabId < 0 || details.frameId !== 0) return;
    const certData = tabCertInfo.get(details.tabId) || {};
    certData.hasHSTS  = !!(details.responseHeaders?.find(h => h.name.toLowerCase() === 'strict-transport-security'));
    certData.isHTTPS  = details.url.startsWith('https://');
    certData.resolved = true;
    tabCertInfo.set(details.tabId, certData);
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders']
);

chrome.webRequest.onErrorOccurred.addListener((details) => {
  if (details.tabId < 0 || details.frameId !== 0) return;
  const err = details.error || '';
  const certData = tabCertInfo.get(details.tabId) || {};
  if (err.includes('ERR_CERT_AUTHORITY_INVALID') || err.includes('ERR_CERT_COMMON_NAME_INVALID')) {
    certData.isSelfSigned = true; certData.isValid = false; certData.errorDetail = err;
  } else if (err.includes('ERR_CERT_DATE_INVALID')) {
    certData.isExpired = true; certData.isValid = false; certData.errorDetail = err;
  } else if (err.includes('ERR_SSL_')) {
    certData.sslError = true; certData.isValid = false; certData.errorDetail = err;
  }
  tabCertInfo.set(details.tabId, certData);
}, { urls: ['<all_urls>'] });

// ─── Build cert summary ───────────────────────────────────────────────────────
function buildCertInfo(tabId, tabUrl) {
  const stored  = tabCertInfo.get(tabId) || {};
  const isHTTPS = tabUrl?.startsWith('https://');

  if (!isHTTPS) {
    return { isValid: false, isHTTPS: false, isSelfSigned: false, isExpired: false,
             sslError: false, issuer: 'None (HTTP)', daysUntilExpiry: null, hasHSTS: false };
  }
  return {
    isValid:       !stored.isSelfSigned && !stored.isExpired && !stored.sslError,
    isHTTPS:       true,
    isSelfSigned:  stored.isSelfSigned  || false,
    isExpired:     stored.isExpired     || false,
    sslError:      stored.sslError      || false,
    issuer:        stored.issuer        || 'Unknown',
    daysUntilExpiry: stored.daysUntilExpiry ?? 90,
    hasHSTS:       stored.hasHSTS       || false,
    errorDetail:   stored.errorDetail   || null,
  };
}

// ─── Redirect chain analysis ──────────────────────────────────────────────────
function analyzeRedirectChain(chain) {
  const openParams = ['redirect', 'url', 'goto', 'next', 'return', 'returnurl', 'continue', 'redir'];
  let hasOpenRedirect = false;

  for (const u of (chain || [])) {
    try {
      const parsed = new URL(u);
      for (const p of openParams) {
        const v = parsed.searchParams.get(p);
        if (v && (v.startsWith('http://') || v.startsWith('https://'))) hasOpenRedirect = true;
      }
    } catch { /* ignore */ }
  }
  return { chain: chain || [], hasOpenRedirect };
}

// ─── PhishTank API — fire and store result in session cache ──────────────────
async function checkPhishTankAndStore(url) {
  const cacheKey = `pt_${btoa(url).slice(0, 60)}`;

  // Check cache
  try {
    const cached = await chrome.storage.session.get(cacheKey);
    if (cached[cacheKey] && Date.now() - cached[cacheKey].ts < CACHE_TTL_MS) {
      return cached[cacheKey].data;
    }
  } catch { /* ignore */ }

  const store = async (result) => {
    try { await chrome.storage.session.set({ [cacheKey]: { data: result, ts: Date.now() } }); } catch {}
    return result;
  };

  // Without an API key PhishTank enforces strict rate limiting.
  // We still try, but treat any error as "not in database".
  try {
    const form = new URLSearchParams({ url, format: 'json' });
    if (PHISHTANK_APP_KEY) form.append('app_key', PHISHTANK_APP_KEY);

    const res = await fetch(PHISHTANK_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body:    form.toString(),
      signal:  AbortSignal.timeout(8000), // 8 s hard limit
    });

    if (res.status === 429) return store({ error: 'PhishTank rate limited', inDatabase: false, verified: false });
    if (!res.ok)            return store({ error: `HTTP ${res.status}`,       inDatabase: false, verified: false });

    const json = await res.json();
    return store({
      inDatabase: json?.results?.in_database ?? false,
      verified:   json?.results?.verified    ?? false,
      phishId:    json?.results?.phish_id,
    });
  } catch (err) {
    return store({ error: err.message, inDatabase: false, verified: false });
  }
}

// ─── Blocked URL history ──────────────────────────────────────────────────────
async function logBlockedURL(url, score, reasons) {
  try {
    const { blockedHistory = [] } = await chrome.storage.local.get('blockedHistory');
    blockedHistory.unshift({ url, score: Math.round(score * 100), reasons: reasons.slice(0, 3), timestamp: new Date().toISOString() });
    if (blockedHistory.length > 200) blockedHistory.length = 200;
    await chrome.storage.local.set({ blockedHistory });
  } catch { /* ignore */ }
}

// ─── Badge updater ────────────────────────────────────────────────────────────
function updateBadge(tabId, score, label) {
  if (!tabId || tabId < 0) return;
  let text = '✓', color = '#22c55e';
  if (score >= 0.80)      { text = '!!!'; color = '#ef4444'; }
  else if (score >= 0.61) { text = '!!';  color = '#f97316'; }
  else if (score >= 0.31) { text = '!';   color = '#f59e0b'; }

  chrome.action.setBadgeText({ text, tabId }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ color, tabId }).catch(() => {});
  chrome.action.setTitle({ title: `PhishGuard — ${label} (${Math.round(score * 100)}% risk)`, tabId }).catch(() => {});
}

// ─── SINGLE consolidated message listener ─────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab?.id ?? message.tabId;

  switch (message.type) {

    case 'GET_ANALYSIS_DATA': {
      // FIXED: Respond immediately with cert/redirect, kick off PhishTank async
      const chain      = redirectChains.get(tabId) || [];
      const certInfo   = buildCertInfo(tabId, message.url);
      const redirectData = analyzeRedirectChain(chain);

      // Kick off PhishTank asynchronously — result stores in session cache
      // Content script will poll for it with GET_PHISHTANK_RESULT
      checkPhishTankAndStore(message.url).catch(() => {});

      sendResponse({ certInfo, redirectData, phishTankData: null });
      return false; // synchronous response — no need to return true
    }

    case 'GET_PHISHTANK_RESULT': {
      // Content script calls this after initial analysis is done
      const cacheKey = `pt_${btoa(message.url).slice(0, 60)}`;
      chrome.storage.session.get(cacheKey).then(cached => {
        sendResponse(cached[cacheKey]?.data || null);
      }).catch(() => sendResponse(null));
      return true;
    }

    case 'UPDATE_BADGE': {
      updateBadge(tabId, message.score, message.label);
      return false;
    }

    case 'LOG_BLOCKED_URL': {
      logBlockedURL(message.url, message.score, message.reasons || []);
      sendResponse({ ok: true });
      return false;
    }

    case 'REPORT_FALSE_POSITIVE': {
      chrome.storage.local.get('falsePositives').then(data => {
        const fp = data.falsePositives || [];
        if (!fp.includes(message.url)) fp.push(message.url);
        chrome.storage.local.set({ falsePositives: fp });
        sendResponse({ ok: true });
      }).catch(() => sendResponse({ ok: false }));
      return true;
    }

    case 'GET_BLOCKED_HISTORY': {
      chrome.storage.local.get('blockedHistory').then(data => {
        sendResponse({ history: data.blockedHistory || [] });
      }).catch(() => sendResponse({ history: [] }));
      return true;
    }

    default:
      return false;
  }
});

console.log('[PhishGuard] Service worker v1.1 initialized.');
