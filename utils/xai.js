/**
 * PhishGuard — Explainable AI (XAI) Module
 * SHAP-inspired marginal contribution + LIME-inspired element highlighting.
 * Pure JS — no external ML dependencies.
 */

import { computeRiskScore, rankSignalsByContribution } from './scoring.js';

// ─── Natural Language Templates ───────────────────────────────────────────────
const EXPLANATION_TEMPLATES = {
  phishTank: {
    high: () => 'This URL is confirmed in PhishTank\'s verified phishing database — this is a known malicious site.',
    low:  () => 'This URL was not found in the PhishTank phishing database.',
  },
  passwordOverHTTP: {
    high: () => 'A password field was found on an unencrypted HTTP page, exposing your credentials to interception by anyone on the network.',
    low:  () => 'Password fields are served over HTTPS — connection is encrypted.',
  },
  unicodeHomograph: {
    high: (sig) => `The domain uses Unicode or homoglyph characters to visually impersonate a legitimate brand. Detail: ${sig.detail}`,
    low:  () => 'No homograph or Unicode spoofing detected in the domain.',
  },
  bitbAttack: {
    high: (sig) => `A Browser-in-the-Browser (BitB) overlay was detected — a fake browser window designed to steal credentials. Detail: ${sig.detail}`,
    low:  () => 'No Browser-in-the-Browser attack patterns detected.',
  },
  sslCertificate: {
    high: (sig) => `SSL certificate issue detected: ${sig.detail}`,
    low:  (sig) => `SSL certificate appears valid. ${sig.detail}`,
  },
  titleDomainMismatch: {
    high: (sig) => `The page title claims to represent a known brand, but the domain does not match. ${sig.detail}`,
    low:  () => 'Page title and domain are consistent.',
  },
  redirectChain: {
    high: (sig) => `Suspicious redirect chain detected: ${sig.detail}`,
    low:  () => 'No suspicious redirect patterns detected.',
  },
  csrfTokenAbsence: {
    high: (sig) => `Login form(s) found without CSRF protection: ${sig.detail}`,
    low:  () => 'Form security tokens (CSRF) are present.',
  },
  iframeSuspicion: {
    high: (sig) => `Suspicious iframes detected: ${sig.detail}`,
    low:  (sig) => sig.detail,
  },
  externalResources: {
    high: (sig) => `Suspicious external resource loading detected: ${sig.detail}`,
    low:  () => 'No suspicious background resource loading.',
  },
  domPhishingSignature: {
    high: (sig) => `Known phishing DOM patterns detected: ${sig.detail}`,
    low:  () => 'No known phishing DOM signatures found.',
  },
  linkImageMismatch: {
    high: (sig) => `Deceptive links or images detected: ${sig.detail}`,
    low:  () => 'No deceptive link or image mismatches detected.',
  },
};

// ─── Severity Badge ───────────────────────────────────────────────────────────
function getSeverityBadge(score) {
  if (score >= 0.8)  return { label: 'CRITICAL', color: '#ef4444' };
  if (score >= 0.6)  return { label: 'HIGH',     color: '#f97316' };
  if (score >= 0.3)  return { label: 'MEDIUM',   color: '#f59e0b' };
  if (score > 0)     return { label: 'LOW',       color: '#3b82f6' };
  return               { label: 'OK',            color: '#22c55e' };
}

/**
 * SHAP-inspired: compute marginal contribution of each signal.
 * Approximation: contribution_i = score_i × weight_i / Σ(weights)
 */
function computeMarginalContributions(signals) {
  const totalWeight = signals.reduce((acc, s) => acc + (s.weight ?? 0.5), 0);
  return signals.map(s => ({
    ...s,
    marginalContribution: totalWeight > 0
      ? (s.score ?? 0) * (s.weight ?? 0.5) / totalWeight
      : 0,
  }));
}

/**
 * LIME-inspired: identify which DOM element or URL part triggered the signal.
 */
function getLimeHighlight(signal) {
  const elementMap = {
    titleDomainMismatch:  { selector: 'title', part: 'Page Title' },
    csrfTokenAbsence:     { selector: 'form[method="post"]', part: 'HTML Form' },
    passwordOverHTTP:     { selector: 'input[type="password"]', part: 'Password Input' },
    iframeSuspicion:      { selector: 'iframe', part: 'IFrame Element' },
    externalResources:    { selector: 'script[src], img[src]', part: 'External Resources' },
    linkImageMismatch:    { selector: 'a[href], img[src]', part: 'Links / Images' },
    domPhishingSignature: { selector: 'script, body', part: 'DOM / Script Content' },
    sslCertificate:       { selector: null, part: 'SSL Certificate (Network Layer)' },
    redirectChain:        { selector: null, part: 'URL Redirect Chain' },
    unicodeHomograph:     { selector: null, part: 'URL / Domain Name' },
    bitbAttack:           { selector: 'div[class*="browser"], iframe', part: 'Overlay Elements' },
    phishTank:            { selector: null, part: 'Full URL (PhishTank Check)' },
  };
  return elementMap[signal] || { selector: null, part: 'Unknown' };
}

/**
 * Generate full XAI explanation for a set of signals.
 * Returns top N reasons sorted by contribution, with severity badges and LIME hints.
 *
 * @param {Array} signals — Array of signal result objects
 * @param {number} topN — Number of top reasons to return
 * @returns {{ overallSummary: string, reasons: Array, allSignals: Array }}
 */
export function generateExplanation(signals, topN = 5) {
  const withContributions = computeMarginalContributions(signals);
  const ranked = [...withContributions].sort((a, b) => b.marginalContribution - a.marginalContribution);
  const totalScore = computeRiskScore(signals);

  const reasons = ranked
    .filter(s => s.score > 0)
    .slice(0, topN)
    .map(sig => {
      const template = EXPLANATION_TEMPLATES[sig.signal];
      const isHigh = sig.score >= 0.5;
      const explanation = template
        ? (isHigh ? template.high(sig) : template.low(sig))
        : sig.detail;

      const lime = getLimeHighlight(sig.signal);
      const badge = getSeverityBadge(sig.score);

      return {
        signal: sig.signal,
        score: sig.score,
        weight: sig.weight,
        contribution: sig.marginalContribution,
        explanation,
        badge,
        lime,
        detail: sig.detail,
      };
    });

  // Overall summary sentence
  let overallSummary = '';
  if (totalScore >= 0.80) {
    overallSummary = `🚨 This page shows strong indicators of a phishing attack (${Math.round(totalScore * 100)}% risk). ${reasons.length > 0 ? reasons[0].explanation : ''}`;
  } else if (totalScore >= 0.61) {
    overallSummary = `🔶 This page has multiple suspicious characteristics (${Math.round(totalScore * 100)}% risk). Exercise extreme caution.`;
  } else if (totalScore >= 0.31) {
    overallSummary = `⚠️ Some suspicious signals detected (${Math.round(totalScore * 100)}% risk). Proceed with caution.`;
  } else {
    overallSummary = `✅ This page appears safe (${Math.round(totalScore * 100)}% risk). No significant phishing indicators.`;
  }

  return {
    overallSummary,
    reasons,
    allSignals: withContributions,
    totalScore,
  };
}

/**
 * Quick explanation for the fullscreen blocker — returns top 3 reasons.
 * @param {Array} signals
 * @returns {Array<string>}
 */
export function getBlockerReasons(signals) {
  const { reasons } = generateExplanation(signals, 3);
  return reasons.map(r => r.explanation);
}
