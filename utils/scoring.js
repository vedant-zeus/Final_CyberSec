/**
 * PhishGuard — Risk Scoring Engine
 * Pure functions, no side effects — fully unit-testable.
 */

// ─── Signal Weights (must match signals.js) ───────────────────────────────────
export const SIGNAL_WEIGHTS = {
  phishTank:           1.00,
  passwordOverHTTP:    0.90,
  unicodeHomograph:    0.85,
  bitbAttack:          0.85,
  sslCertificate:      0.80,
  titleDomainMismatch: 0.75,
  redirectChain:       0.70,
  csrfTokenAbsence:    0.65,
  iframeSuspicion:     0.60,
  externalResources:   0.55,
  domPhishingSignature:0.55,
  linkImageMismatch:   0.45,
};

// ─── Thresholds ───────────────────────────────────────────────────────────────
export const THRESHOLDS = {
  SAFE:       { min: 0.00, max: 0.30, label: 'SAFE',      color: '#22c55e', emoji: '✅' },
  SUSPICIOUS: { min: 0.31, max: 0.60, label: 'SUSPICIOUS', color: '#f59e0b', emoji: '⚠️' },
  HIGH_RISK:  { min: 0.61, max: 0.79, label: 'HIGH RISK',  color: '#f97316', emoji: '🔶' },
  PHISHING:   { min: 0.80, max: 1.00, label: 'PHISHING',   color: '#ef4444', emoji: '🚨' },
};

/**
 * Compute the weighted risk score.
 * Formula: Σ(signal_score × weight) / Σ(weights)
 * @param {Array<{signal: string, score: number, weight: number}>} signals
 * @returns {number} — normalized score 0–1
 */
export function computeRiskScore(signals) {
  if (!signals || signals.length === 0) return 0;

  let weightedSum = 0;
  let totalWeight = 0;

  for (const sig of signals) {
    const weight = sig.weight ?? SIGNAL_WEIGHTS[sig.signal] ?? 0.5;
    weightedSum += (sig.score ?? 0) * weight;
    totalWeight += weight;
  }

  return totalWeight === 0 ? 0 : Math.min(1.0, weightedSum / totalWeight);
}

/**
 * Get threat level object for a given score.
 * @param {number} score
 * @returns {{ label: string, color: string, emoji: string, shouldBlock: boolean }}
 */
export function getThreatLevel(score) {
  if (score >= 0.80) return { ...THRESHOLDS.PHISHING, shouldBlock: true };
  if (score >= 0.61) return { ...THRESHOLDS.HIGH_RISK, shouldBlock: false };
  if (score >= 0.31) return { ...THRESHOLDS.SUSPICIOUS, shouldBlock: false };
  return { ...THRESHOLDS.SAFE, shouldBlock: false };
}

/**
 * Determine if the page should be immediately blocked.
 * Triggers on: score ≥ 0.80 OR PhishTank confirmed.
 * @param {number} score
 * @param {Array} signals
 * @returns {boolean}
 */
export function shouldAutoBlock(score, signals) {
  if (score >= 0.80) return true;
  const phishTankSignal = signals.find(s => s.signal === 'phishTank');
  if (phishTankSignal && phishTankSignal.score === 1.0) return true;
  return false;
}

/**
 * Sort signals by their weighted contribution (descending).
 * Used by the XAI module.
 * @param {Array} signals
 * @returns {Array} sorted signals
 */
export function rankSignalsByContribution(signals) {
  return [...signals]
    .map(s => ({
      ...s,
      contribution: (s.score ?? 0) * (s.weight ?? SIGNAL_WEIGHTS[s.signal] ?? 0.5),
    }))
    .sort((a, b) => b.contribution - a.contribution);
}
