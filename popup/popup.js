/**
 * PhishGuard — Popup Script
 * Reads analysis data from session storage, renders risk score, signals, XAI.
 */

'use strict';

// ─── Signal Display Metadata ──────────────────────────────────────────────────
const SIGNAL_META = {
  titleDomainMismatch:  { label: 'Title Match',    safe: '✅', warn: '⚠️', danger: '❌' },
  csrfTokenAbsence:     { label: 'CSRF Token',     safe: '✅', warn: '⚠️', danger: '❌' },
  passwordOverHTTP:     { label: 'HTTPS Pass',      safe: '✅', warn: '⚠️', danger: '❌' },
  iframeSuspicion:      { label: 'Iframes',         safe: '✅', warn: '⚠️', danger: '❌' },
  externalResources:    { label: 'Ext Resources',   safe: '✅', warn: '⚠️', danger: '❌' },
  linkImageMismatch:    { label: 'Link Integrity',  safe: '✅', warn: '⚠️', danger: '❌' },
  domPhishingSignature: { label: 'DOM Signature',   safe: '✅', warn: '⚠️', danger: '❌' },
  sslCertificate:       { label: 'SSL Valid',       safe: '✅', warn: '⚠️', danger: '❌' },
  redirectChain:        { label: 'Redirect Chain',  safe: '✅', warn: '⚠️', danger: '❌' },
  unicodeHomograph:     { label: 'URL Integrity',   safe: '✅', warn: '⚠️', danger: '❌' },
  bitbAttack:           { label: 'BitB Attack',     safe: '✅', warn: '⚠️', danger: '❌' },
  phishTank:            { label: 'PhishTank',       safe: '✅', warn: '⚠️', danger: '❌' },
};

const THRESHOLDS = {
  SAFE:       { min: 0.00, max: 0.30, label: 'SAFE',       class: '',                color: '#22c55e' },
  SUSPICIOUS: { min: 0.31, max: 0.60, label: 'SUSPICIOUS', class: 'state-suspicious', color: '#f59e0b' },
  HIGH_RISK:  { min: 0.61, max: 0.79, label: 'HIGH RISK',  class: 'state-high-risk',  color: '#f97316' },
  PHISHING:   { min: 0.80, max: 1.00, label: 'PHISHING',   class: 'state-phishing',   color: '#ef4444' },
};

function getThreatInfo(score) {
  if (score >= 0.80) return THRESHOLDS.PHISHING;
  if (score >= 0.61) return THRESHOLDS.HIGH_RISK;
  if (score >= 0.31) return THRESHOLDS.SUSPICIOUS;
  return THRESHOLDS.SAFE;
}

function getSeverityInfo(score) {
  if (score >= 0.8)  return { label: 'CRITICAL', bg: '#ef4444', color: '#fff' };
  if (score >= 0.6)  return { label: 'HIGH',     bg: '#f97316', color: '#fff' };
  if (score >= 0.3)  return { label: 'MEDIUM',   bg: '#f59e0b', color: '#000' };
  if (score > 0)     return { label: 'LOW',       bg: '#3b82f6', color: '#fff' };
  return               { label: 'OK',            bg: '#22c55e', color: '#000' };
}

function getSignalChipClass(score) {
  if (score >= 0.6)  return 'danger';
  if (score >= 0.3)  return 'warn';
  return 'safe';
}

function getSignalIcon(meta, score) {
  if (score >= 0.6)  return meta.danger;
  if (score >= 0.3)  return meta.warn;
  return meta.safe;
}

// ─── XAI Summary Texts ───────────────────────────────────────────────────────
const XAI_TEMPLATES = {
  phishTank:           (sig) => sig.score >= 0.9 ? '🚨 CONFIRMED in PhishTank phishing database.' : sig.detail,
  passwordOverHTTP:    (sig) => sig.score > 0 ? '🔓 Password field on insecure HTTP — credentials unencrypted.' : '🔒 Passwords served securely over HTTPS.',
  unicodeHomograph:    (sig) => sig.score > 0 ? `🔤 ${sig.detail}` : '✓ No homograph/Unicode attacks in URL.',
  bitbAttack:          (sig) => sig.score > 0 ? `🖥️ ${sig.detail}` : '✓ No Browser-in-the-Browser indicators.',
  sslCertificate:      (sig) => sig.score > 0 ? `🔐 SSL issue: ${sig.detail}` : '✓ SSL certificate is valid.',
  titleDomainMismatch: (sig) => sig.score > 0 ? `🏷️ ${sig.detail}` : '✓ Page title matches domain.',
  redirectChain:       (sig) => sig.score > 0 ? `↪️ ${sig.detail}` : '✓ No suspicious redirects.',
  csrfTokenAbsence:    (sig) => sig.score > 0 ? `🛡️ ${sig.detail}` : '✓ Forms have CSRF protection.',
  iframeSuspicion:     (sig) => sig.score > 0 ? `📦 ${sig.detail}` : '✓ No suspicious iframes.',
  externalResources:   (sig) => sig.score > 0 ? `📡 ${sig.detail}` : '✓ No suspicious external resources.',
  domPhishingSignature:(sig) => sig.score > 0 ? `🧬 ${sig.detail}` : '✓ No DOM phishing signatures.',
  linkImageMismatch:   (sig) => sig.score > 0 ? `🔗 ${sig.detail}` : '✓ Links and images are consistent.',
};

// ─── DOM References ───────────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);

const loadingState  = $('loadingState');
const mainContent   = $('mainContent');
const mainFooter    = $('mainFooter');
const siteDomain    = $('siteDomain');
const riskBarFill   = $('riskBarFill');
const riskPct       = $('riskPct');
const riskBadge     = $('riskBadge');
const summaryText   = $('summaryText');
const reasonsSection= $('reasonsSection');
const reasonsList   = $('reasonsList');
const signalGrid    = $('signalGrid');
const xaiSection    = $('xaiSection');
const xaiList       = $('xaiList');
const settingsPanel = $('settingsPanel');

// ─── Render Functions ─────────────────────────────────────────────────────────
function renderRiskScore(score, domain) {
  const threat = getThreatInfo(score);
  const pct    = Math.round(score * 100);

  // Apply state class
  document.body.className = threat.class || '';

  // Populate fields
  siteDomain.textContent   = domain || '—';
  riskPct.textContent      = `${pct}%`;
  riskBadge.textContent    = threat.label;

  // Animate bar
  requestAnimationFrame(() => {
    riskBarFill.style.width = `${pct}%`;
  });
}

function renderSummary(score) {
  const pct = Math.round(score * 100);
  if (score >= 0.80) {
    summaryText.textContent = `🚨 Strong phishing indicators detected (${pct}% risk). This site may be attempting to steal your credentials.`;
    summaryText.style.color = '#ef4444';
  } else if (score >= 0.61) {
    summaryText.textContent = `🔶 Multiple suspicious signals found (${pct}% risk). Exercise extreme caution on this page.`;
    summaryText.style.color = '#f97316';
  } else if (score >= 0.31) {
    summaryText.textContent = `⚠️ Some suspicious patterns detected (${pct}% risk). Verify this site before entering sensitive data.`;
    summaryText.style.color = '#f59e0b';
  } else {
    summaryText.textContent = `✅ This page appears safe (${pct}% risk). No significant phishing indicators detected.`;
    summaryText.style.color = '#22c55e';
  }
}

function renderReasons(signals) {
  const activeSignals = signals.filter(s => s.score >= 0.3)
    .sort((a, b) => b.score * b.weight - a.score * a.weight)
    .slice(0, 5);

  if (activeSignals.length === 0) {
    reasonsSection.hidden = true;
    return;
  }

  reasonsSection.hidden = false;
  reasonsList.innerHTML = '';

  for (const sig of activeSignals) {
    const sev = getSeverityInfo(sig.score);
    const tmpl = XAI_TEMPLATES[sig.signal];
    const text = tmpl ? tmpl(sig) : sig.detail;

    const li = document.createElement('li');
    li.className = 'reason-item';
    li.innerHTML = `
      <span class="reason-icon">⚠️</span>
      <div class="reason-body">
        <div class="reason-text">${escapeHtml(text)}</div>
        <div class="reason-meta">
          <span class="severity-badge" style="background:${sev.bg};color:${sev.color}">${sev.label}</span>
          <span class="reason-score">[${sig.weight.toFixed(2)}×${sig.score.toFixed(2)}]</span>
        </div>
      </div>
    `;
    reasonsList.appendChild(li);
  }
}

function renderSignalGrid(signals) {
  signalGrid.innerHTML = '';
  for (const sig of signals) {
    const meta = SIGNAL_META[sig.signal] || { label: sig.signal, safe: '✅', warn: '⚠️', danger: '❌' };
    const chipClass = getSignalChipClass(sig.score);
    const icon = getSignalIcon(meta, sig.score);

    const chip = document.createElement('div');
    chip.className = `signal-chip ${chipClass}`;
    chip.title = sig.detail;
    chip.innerHTML = `
      <span class="signal-status">${icon}</span>
      <span class="signal-name">${meta.label}</span>
    `;
    signalGrid.appendChild(chip);
  }
}

function renderXAI(signals) {
  const totalWeight = signals.reduce((acc, s) => acc + s.weight, 0);
  const withContrib = signals.map(s => ({
    ...s,
    contribution: totalWeight > 0 ? (s.score * s.weight / totalWeight) : 0,
  })).sort((a, b) => b.contribution - a.contribution).filter(s => s.score > 0).slice(0, 5);

  if (withContrib.length === 0) {
    xaiSection.hidden = true;
    return;
  }

  xaiSection.hidden = false;
  xaiList.innerHTML = '';
  const maxContrib = withContrib[0]?.contribution || 1;

  for (const sig of withContrib) {
    const sev = getSeverityInfo(sig.score);
    const tmpl = XAI_TEMPLATES[sig.signal];
    const explanation = tmpl ? tmpl(sig) : sig.detail;
    const pct = Math.round((sig.contribution / maxContrib) * 100);
    const meta = SIGNAL_META[sig.signal] || { label: sig.signal };

    const item = document.createElement('div');
    item.className = 'xai-item';
    item.innerHTML = `
      <div class="xai-header">
        <span class="xai-signal-name">${meta.label}</span>
        <span class="xai-contribution">+${(sig.contribution * 100).toFixed(1)}% risk</span>
      </div>
      <div class="xai-bar-track">
        <div class="xai-bar-fill" style="width:${pct}%;background:${sev.bg}"></div>
      </div>
      <div class="xai-explanation">${escapeHtml(explanation)}</div>
      <div class="xai-lime">📍 Triggered by: ${sig.element || 'URL/Page analysis'}</div>
    `;
    xaiList.appendChild(item);
  }
}

function escapeHtml(text) {
  const d = document.createElement('div');
  d.textContent = text;
  return d.innerHTML;
}

// ─── Settings ─────────────────────────────────────────────────────────────────
async function loadSettings() {
  const data = await chrome.storage.local.get(['settings']).catch(() => ({}));
  const settings = data.settings || {};
  $('autoBlockToggle').checked  = settings.autoBlock  !== false;
  $('phishTankToggle').checked  = settings.phishTank  !== false;
  $('xaiToggle').checked        = settings.showXAI    !== false;
  $('apiKeyInput').value        = settings.apiKey     || '';
}

async function saveSettings() {
  const settings = {
    autoBlock: $('autoBlockToggle').checked,
    phishTank: $('phishTankToggle').checked,
    showXAI:   $('xaiToggle').checked,
    apiKey:    $('apiKeyInput').value.trim(),
  };
  await chrome.storage.local.set({ settings }).catch(() => {});
  settingsPanel.hidden = true;
}

async function loadHistory() {
  const data = await chrome.storage.local.get('blockedHistory').catch(() => ({}));
  const history = data.blockedHistory || [];
  const historyList = $('historyList');
  if (history.length === 0) {
    historyList.innerHTML = '<em>No blocked sites yet.</em>';
    return;
  }
  historyList.innerHTML = history.slice(0, 10).map(h => `
    <div class="history-entry" title="${escapeHtml(h.url)}">
      🚫 ${escapeHtml(new URL(h.url).hostname)} — ${h.score}% — ${new Date(h.timestamp).toLocaleDateString()}
    </div>
  `).join('');
}

// ─── Main Init ────────────────────────────────────────────────────────────────
async function init() {
  try {
    // Get active tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) {
      loadingState.innerHTML = '<p style="color:#6e7681;padding:20px">No active tab found.</p>';
      return;
    }

    const url = tab.url;
    // Skip non-web pages
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      loadingState.innerHTML = '<p style="color:#6e7681;padding:20px;text-align:center">PhishGuard only analyzes http/https pages.</p>';
      return;
    }

    let hostname = 'unknown';
    try { hostname = new URL(url).hostname; } catch {}

    // ── Tier 1: Ask content script directly (fastest, most accurate) ──────────
    let data = await new Promise((resolve) => {
      const t = setTimeout(() => resolve(null), 1500);
      chrome.tabs.sendMessage(tab.id, { type: 'GET_RESULTS' }, (response) => {
        clearTimeout(t);
        if (chrome.runtime.lastError || !response) resolve(null);
        else resolve(response);
      });
    });

    // ── Tier 2: Try session storage ───────────────────────────────────────────
    if (!data || data.hostname !== hostname) {
      const cacheKey = `phishguard_${hostname}`;
      const cached = await chrome.storage.session.get([cacheKey, 'phishguard_latest']).catch(() => ({}));
      const candidate = cached[cacheKey] || cached['phishguard_latest'];
      if (candidate && candidate.hostname === hostname) data = candidate;
    }

    // ── Tier 3: Inject & wait if content script not yet run ──────────────────
    if (!data) {
      loadingState.querySelector('p').textContent = 'Injecting analyzer...';
      try {
        await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          files: ['content/content_script.js'],
        });
      } catch (injErr) {
        // Already injected or restricted page — that's OK
        console.warn('[PhishGuard Popup] Injection skipped:', injErr.message);
      }
      // Wait for analysis to complete
      loadingState.querySelector('p').textContent = 'Analyzing page...';
      await new Promise(r => setTimeout(r, 2500));

      // Re-query content script
      data = await new Promise((resolve) => {
        const t = setTimeout(() => resolve(null), 1500);
        chrome.tabs.sendMessage(tab.id, { type: 'GET_RESULTS' }, (response) => {
          clearTimeout(t);
          if (chrome.runtime.lastError || !response) resolve(null);
          else resolve(response);
        });
      });

      // Final fallback: session storage after injection
      if (!data) {
        const cacheKey = `phishguard_${hostname}`;
        const retried = await chrome.storage.session.get([cacheKey, 'phishguard_latest']).catch(() => ({}));
        data = retried[cacheKey] || retried['phishguard_latest'];
      }
    }

    // ── No data found ─────────────────────────────────────────────────────────
    if (!data || !data.signals) {
      loadingState.innerHTML = `
        <div style="text-align:center;padding:20px;color:#8b949e">
          <div style="font-size:24px;margin-bottom:8px">🔍</div>
          <p style="margin-bottom:6px">Cannot analyze this page.</p>
          <p style="font-size:11px">Try reloading and clicking the icon again.</p>
        </div>`;
      return;
    }

    // ── Render all UI ─────────────────────────────────────────────────────────
    loadingState.hidden = true;
    mainContent.hidden  = false;
    mainFooter.hidden   = false;

    const { score, signals } = data;
    renderRiskScore(score, hostname);
    renderSummary(score);
    renderReasons(signals);
    renderSignalGrid(signals);

    const settings = await chrome.storage.local.get('settings').catch(() => ({}));
    if (settings.settings?.showXAI !== false) renderXAI(signals);

    loadSettings();

    // ── Auto-refresh popup every 5s to catch PhishTank updates ───────────────
    setTimeout(async () => {
      const fresh = await new Promise((resolve) => {
        const t = setTimeout(() => resolve(null), 1500);
        chrome.tabs.sendMessage(tab.id, { type: 'GET_RESULTS' }, (r) => { clearTimeout(t); resolve(r || null); });
      });
      if (fresh && fresh.signals && Math.abs(fresh.score - score) > 0.01) {
        renderRiskScore(fresh.score, hostname);
        renderSummary(fresh.score);
        renderReasons(fresh.signals);
        renderSignalGrid(fresh.signals);
        if (settings.settings?.showXAI !== false) renderXAI(fresh.signals);
      }
    }, 5000);

  } catch (err) {
    console.error('[PhishGuard Popup] Error:', err);
    loadingState.innerHTML = `<p style="color:#ef4444;padding:20px">Error loading analysis: ${escapeHtml(err.message)}</p>`;
  }
}

// ─── Event Listeners ──────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  init();

  $('settingsBtn').addEventListener('click', () => {
    settingsPanel.hidden = false;
    loadSettings();
    loadHistory();
  });

  $('closeSettingsBtn').addEventListener('click', () => { settingsPanel.hidden = true; });

  $('saveSettingsBtn').addEventListener('click', saveSettings);

  $('clearHistoryBtn').addEventListener('click', async () => {
    await chrome.storage.local.remove('blockedHistory').catch(() => {});
    loadHistory();
  });

  $('reportFPBtn').addEventListener('click', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) return;
    chrome.runtime.sendMessage({ type: 'REPORT_FALSE_POSITIVE', url: tab.url }, () => {
      $('reportFPBtn').textContent = '✅ Reported!';
      $('reportFPBtn').disabled = true;
    });
  });

  $('detailsBtn').addEventListener('click', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) return;
    // Toggle XAI section visibility
    xaiSection.hidden = !xaiSection.hidden;
    $('detailsBtn').textContent = xaiSection.hidden ? '🔍 Full Details' : '🔼 Hide Details';
  });
});
