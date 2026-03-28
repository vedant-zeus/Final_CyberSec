/**
 * PhishGuard — Detection Signals Module
 * Each signal returns: { signal, score (0–1), weight, detail, element? }
 * All functions are pure and independently callable.
 */

// ─── Known Brand → Domain Map ─────────────────────────────────────────────────
const BRAND_DOMAINS = {
  google:       ['google.com', 'google.co.uk', 'google.ca', 'googleapis.com', 'gstatic.com'],
  paypal:       ['paypal.com', 'paypalobjects.com'],
  amazon:       ['amazon.com', 'amazon.co.uk', 'amazonaws.com', 'amazon.in'],
  facebook:     ['facebook.com', 'fb.com', 'fbcdn.net', 'instagram.com'],
  apple:        ['apple.com', 'icloud.com', 'apple.co'],
  microsoft:    ['microsoft.com', 'live.com', 'outlook.com', 'hotmail.com', 'microsoftonline.com', 'office.com', 'azure.com'],
  bankofamerica:['bankofamerica.com', 'bofa.com'],
  chase:        ['chase.com', 'jpmorgan.com', 'jpmchase.com'],
  wellsfargo:   ['wellsfargo.com'],
  netflix:      ['netflix.com', 'nflximg.com'],
  twitter:      ['twitter.com', 'x.com', 't.co'],
  linkedin:     ['linkedin.com', 'licdn.com'],
  dropbox:      ['dropbox.com', 'dropboxapi.com'],
  github:       ['github.com', 'githubusercontent.com'],
  ebay:         ['ebay.com', 'ebaystatic.com'],
  yahoo:        ['yahoo.com', 'yimg.com', 'yahooapis.com'],
  citibank:     ['citibank.com', 'citi.com'],
  dhl:          ['dhl.com', 'dhl.de'],
  fedex:        ['fedex.com'],
  ups:          ['ups.com'],
  usps:         ['usps.com'],
  irs:          ['irs.gov'],
};

// ─── Homoglyph Mapping ─────────────────────────────────────────────────────────
const HOMOGLYPHS = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
  'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ɡ': 'g', 'ο': 'o', 'ν': 'v',
  'α': 'a', 'β': 'b', 'δ': 'd', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'μ': 'm',
  'η': 'n', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'ω': 'w', 'ζ': 'z',
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '6': 'g', '7': 't',
  '8': 'b', '@': 'a', '$': 's', '!': 'i',
};

function normalizeHomoglyphs(str) {
  return str.toLowerCase().split('').map(c => HOMOGLYPHS[c] || c).join('');
}

function getDomain(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch {
    return '';
  }
}

function getRootDomain(hostname) {
  const parts = hostname.split('.');
  return parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
}

// ─── Signal 1: Title ↔ Domain Mismatch ───────────────────────────────────────
export function checkTitleDomainMismatch() {
  const title = (document.title || '').toLowerCase();
  const hostname = window.location.hostname.replace(/^www\./, '').toLowerCase();
  const normalizedTitle = normalizeHomoglyphs(title);

  let maxScore = 0;
  let detail = 'No title/domain mismatch detected.';
  let detectedBrand = null;
  let detectedDomain = null;

  for (const [brand, domains] of Object.entries(BRAND_DOMAINS)) {
    const normalizedBrand = normalizeHomoglyphs(brand);
    const titleMentionsBrand = normalizedTitle.includes(normalizedBrand);

    if (titleMentionsBrand) {
      const domainMatchesBrand = domains.some(d => hostname.includes(d.replace(/^www\./, '')));
      if (!domainMatchesBrand) {
        // Title claims to be brand X but domain doesn't match
        const score = 0.85;
        if (score > maxScore) {
          maxScore = score;
          detectedBrand = brand;
          detectedDomain = hostname;
          detail = `Page title claims to be "${brand}" but the domain "${hostname}" does not match any known ${brand} domain.`;
        }
      }
    }

    // Check for homograph substitution in title
    const brandInTitle = title.match(new RegExp(brand.split('').join('[^a-z]*'), 'i'));
    if (brandInTitle && normalizedTitle.includes(normalizedBrand)) {
      const domainMatchesBrand = domains.some(d => hostname.includes(d.replace(/^www\./, '')));
      if (!domainMatchesBrand && title !== normalizeHomoglyphs(title)) {
        const score = 0.90;
        if (score > maxScore) {
          maxScore = score;
          detail = `Possible homograph substitution detected in title impersonating "${brand}". Domain "${hostname}" is not a legitimate ${brand} domain.`;
        }
      }
    }
  }

  return {
    signal: 'titleDomainMismatch',
    score: maxScore,
    weight: 0.75,
    detail,
    element: 'document.title',
  };
}

// ─── Signal 2: Form Security — CSRF Token Absence ────────────────────────────
export function checkCSRFTokenAbsence() {
  const csrfPatterns = [
    /csrf/i, /_token$/i, /authenticity_token/i, /csrfmiddlewaretoken/i,
    /__RequestVerificationToken/i, /xsrf/i, /nonce/i,
  ];

  const forms = Array.from(document.querySelectorAll('form'));
  if (forms.length === 0) {
    return { signal: 'csrfTokenAbsence', score: 0, weight: 0.65, detail: 'No forms found on page.', element: null };
  }

  const currentOrigin = window.location.origin;
  let riskyForms = 0;
  let detail = '';
  const findings = [];

  for (const form of forms) {
    const method = (form.method || 'get').toUpperCase();
    if (method !== 'POST') continue;

    const hasPasswordField = form.querySelector('input[type="password"]') !== null;
    if (!hasPasswordField) continue; // Only care about login/sensitive forms

    const hiddenInputs = Array.from(form.querySelectorAll('input[type="hidden"]'));
    const hasCSRF = hiddenInputs.some(input =>
      csrfPatterns.some(p => p.test(input.name || '') || p.test(input.id || ''))
    );

    const actionUrl = form.action;
    let crossOrigin = false;
    if (actionUrl) {
      try {
        const actionOrigin = new URL(actionUrl, window.location.href).origin;
        crossOrigin = actionOrigin !== currentOrigin;
      } catch { /* ignore */ }
    }

    if (!hasCSRF) riskyForms++;
    if (crossOrigin) findings.push(`Form POSTs to cross-origin endpoint: ${actionUrl}`);
    if (!hasCSRF) findings.push('Login form lacks CSRF token');
  }

  const score = riskyForms > 0 ? Math.min(0.9, 0.5 + riskyForms * 0.2) : 0;
  detail = findings.length > 0
    ? findings.join('; ')
    : riskyForms > 0
      ? `${riskyForms} login form(s) detected without CSRF protection`
      : 'All forms appear to have CSRF protection.';

  return { signal: 'csrfTokenAbsence', score, weight: 0.65, detail, element: 'form[method="post"]' };
}

// ─── Signal 3: Password Fields Over HTTP ─────────────────────────────────────
export function checkPasswordOverHTTP() {
  const isHTTPS = window.location.protocol === 'https:';
  const passwordFields = Array.from(document.querySelectorAll('input[type="password"]'));

  if (passwordFields.length === 0) {
    return { signal: 'passwordOverHTTP', score: 0, weight: 0.90, detail: 'No password fields found.', element: null };
  }

  if (!isHTTPS) {
    return {
      signal: 'passwordOverHTTP',
      score: 1.0,
      weight: 0.90,
      detail: `CRITICAL: ${passwordFields.length} password field(s) found on an unencrypted HTTP page. Credentials are transmitted in plaintext.`,
      element: 'input[type="password"]',
    };
  }

  // Even if page is HTTPS, check if form action sends to HTTP
  const insecureActions = [];
  for (const field of passwordFields) {
    const form = field.closest('form');
    if (form && form.action) {
      try {
        const actionUrl = new URL(form.action, window.location.href);
        if (actionUrl.protocol === 'http:') {
          insecureActions.push(form.action);
        }
      } catch { /* ignore */ }
    }
  }

  if (insecureActions.length > 0) {
    return {
      signal: 'passwordOverHTTP',
      score: 0.95,
      weight: 0.90,
      detail: `Password form submits to insecure HTTP endpoint: ${insecureActions[0]}`,
      element: 'form[action]',
    };
  }

  return {
    signal: 'passwordOverHTTP',
    score: 0,
    weight: 0.90,
    detail: `${passwordFields.length} password field(s) found on HTTPS page — OK.`,
    element: 'input[type="password"]',
  };
}

// ─── Signal 4: IFrame Suspicion Analysis ─────────────────────────────────────
export function checkIframeSuspicion() {
  const iframes = Array.from(document.querySelectorAll('iframe'));
  if (iframes.length === 0) {
    return { signal: 'iframeSuspicion', score: 0, weight: 0.60, detail: 'No iframes found.', element: null };
  }

  const currentOrigin = window.location.origin;
  let suspicionScore = 0;
  const findings = [];

  for (const iframe of iframes) {
    const style = window.getComputedStyle(iframe);
    const isHidden =
      style.display === 'none' ||
      style.visibility === 'hidden' ||
      parseInt(style.width) === 0 ||
      parseInt(style.height) === 0 ||
      parseFloat(style.opacity) === 0 ||
      iframe.width === '0' ||
      iframe.height === '0';

    if (isHidden) {
      suspicionScore += 0.3;
      findings.push('Hidden iframe detected');
    }

    const src = iframe.src || iframe.getAttribute('src') || '';
    if (src && src.startsWith('http')) {
      try {
        const iframeOrigin = new URL(src).origin;
        if (iframeOrigin !== currentOrigin) {
          suspicionScore += 0.2;
          findings.push(`Cross-origin iframe: ${iframeOrigin}`);
        }
      } catch { /* ignore */ }
    }

    // Detect sandbox escape: allow-scripts + allow-same-origin together
    const sandbox = iframe.getAttribute('sandbox') || '';
    if (sandbox.includes('allow-scripts') && sandbox.includes('allow-same-origin')) {
      suspicionScore += 0.4;
      findings.push('Sandbox escape vector: allow-scripts + allow-same-origin');
    }

    // BitB detection — iframes styled to look like browser chrome
    const rect = iframe.getBoundingClientRect();
    const viewportW = window.innerWidth;
    const viewportH = window.innerHeight;
    if (rect.width > viewportW * 0.5 && rect.height > viewportH * 0.5) {
      suspicionScore += 0.35;
      findings.push('Large viewport-covering iframe — possible Browser-in-the-Browser attack');
    }
  }

  const score = Math.min(1.0, suspicionScore);
  const detail = findings.length > 0
    ? findings.join('; ')
    : `${iframes.length} iframe(s) found — no immediate suspicion.`;

  return { signal: 'iframeSuspicion', score, weight: 0.60, detail, element: 'iframe' };
}

// ─── Signal 5: External Resource Loading ─────────────────────────────────────
export function checkExternalResources() {
  const currentHost = window.location.hostname;
  const currentRoot = getRootDomain(currentHost);
  const findings = [];
  let suspicionScore = 0;

  // Scripts
  document.querySelectorAll('script[src]').forEach(el => {
    const srcHost = getDomain(el.src);
    if (srcHost && getRootDomain(srcHost) !== currentRoot) {
      findings.push(`External script: ${srcHost}`);
      suspicionScore += 0.05;
    }
  });

  // Pixel trackers
  document.querySelectorAll('img').forEach(el => {
    const w = parseInt(el.width || el.getAttribute('width') || '100');
    const h = parseInt(el.height || el.getAttribute('height') || '100');
    if ((w <= 1 || h <= 1) && el.src) {
      const srcHost = getDomain(el.src);
      if (srcHost && getRootDomain(srcHost) !== currentRoot) {
        findings.push(`Pixel tracker from: ${srcHost}`);
        suspicionScore += 0.25;
      }
    }
  });

  // Performance resource timing for fetch/XHR
  if (window.performance && window.performance.getEntriesByType) {
    const resources = window.performance.getEntriesByType('resource');
    const externalXHR = resources.filter(r => {
      const rHost = getDomain(r.name);
      return (r.initiatorType === 'fetch' || r.initiatorType === 'xmlhttprequest')
        && rHost && getRootDomain(rHost) !== currentRoot;
    });
    if (externalXHR.length > 0) {
      findings.push(`${externalXHR.length} fetch/XHR call(s) to external origins`);
      suspicionScore += externalXHR.length * 0.1;
    }
  }

  const score = Math.min(1.0, suspicionScore);
  const detail = findings.length > 0
    ? findings.slice(0, 5).join('; ')
    : 'No suspicious external resource loading detected.';

  return { signal: 'externalResources', score, weight: 0.55, detail, element: 'script, img, link' };
}

// ─── Signal 6: Link & Image Domain Mismatch ───────────────────────────────────
export function checkLinkImageMismatch() {
  const currentRoot = getRootDomain(window.location.hostname);
  const findings = [];
  let suspicionScore = 0;

  // Check anchor text vs href mismatch
  document.querySelectorAll('a[href]').forEach(el => {
    const text = (el.textContent || '').trim().toLowerCase();
    const href = el.href || '';
    const domainInText = text.match(/([a-z0-9-]+\.(?:com|org|net|io|co|gov|edu))/i)?.[1];
    if (domainInText && href) {
      try {
        const hrefRoot = getRootDomain(new URL(href).hostname);
        const textRoot = getRootDomain(domainInText);
        if (textRoot && hrefRoot && textRoot !== hrefRoot) {
          findings.push(`Deceptive link: text shows "${textRoot}" but links to "${hrefRoot}"`);
          suspicionScore += 0.4;
        }
      } catch { /* ignore */ }
    }

    // Transparent overlay links
    const style = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    if (rect.width > 100 && rect.height > 100 && parseFloat(style.opacity) < 0.1) {
      findings.push('Transparent overlay link detected — possible clickjacking');
      suspicionScore += 0.5;
    }
  });

  // Image domain mismatch on apparent login pages
  const hasLoginForm = document.querySelector('input[type="password"]') !== null;
  if (hasLoginForm) {
    document.querySelectorAll('img[src]').forEach(el => {
      const imgHost = getDomain(el.src);
      if (imgHost && getRootDomain(imgHost) !== currentRoot) {
        const isLargeLogo = (parseInt(el.width) > 50 || parseInt(el.height) > 30);
        if (isLargeLogo) {
          findings.push(`Login page loads brand image from unrelated domain: ${imgHost}`);
          suspicionScore += 0.2;
        }
      }
    });
  }

  const score = Math.min(1.0, suspicionScore);
  const detail = findings.length > 0
    ? findings.slice(0, 4).join('; ')
    : 'No deceptive link or image domain mismatches detected.';

  return { signal: 'linkImageMismatch', score, weight: 0.45, detail, element: 'a, img' };
}

// ─── Signal 7: DOM Fingerprinting — Known Phishing Signatures ────────────────
export function checkDOMPhishingSignatures() {
  const findings = [];
  let suspicionScore = 0;

  // Anti-debugging
  const scriptContents = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent || '');
  const allScriptText = scriptContents.join('\n');

  if (/setInterval\s*\(.*debugger/.test(allScriptText)) {
    findings.push('Anti-debugging pattern detected: setInterval with debugger');
    suspicionScore += 0.4;
  }

  // Obfuscated JS
  const evalCount = (allScriptText.match(/\beval\s*\(/g) || []).length;
  const atobCount = (allScriptText.match(/\batob\s*\(/g) || []).length;
  const fromCharCount = (allScriptText.match(/String\.fromCharCode/g) || []).length;
  if (evalCount + atobCount + fromCharCount > 3) {
    findings.push(`Obfuscated JS detected: eval(${evalCount}), atob(${atobCount}), fromCharCode(${fromCharCount})`);
    suspicionScore += 0.35;
  }

  // Disabled right-click
  if (allScriptText.includes('contextmenu') && allScriptText.includes('preventDefault')) {
    findings.push('Right-click context menu is disabled — common phishing tactic');
    suspicionScore += 0.2;
  }

  // Text selection disabled
  const bodyStyle = window.getComputedStyle(document.body);
  if (bodyStyle.userSelect === 'none' || bodyStyle.webkitUserSelect === 'none') {
    findings.push('Text selection disabled on entire page');
    suspicionScore += 0.15;
  }

  // Meta refresh redirect
  const metaRefresh = document.querySelector('meta[http-equiv="refresh"]');
  if (metaRefresh) {
    findings.push(`Meta refresh redirect detected: ${metaRefresh.content}`);
    suspicionScore += 0.30;
  }

  // Original site copyright in source but domain mismatch (check via comments in scripts)
  const copyrightPattern = /(©|copyright)\s+\d{4}\s+(paypal|google|apple|microsoft|amazon|facebook|chase|wells fargo)/i;
  if (copyrightPattern.test(allScriptText) || copyrightPattern.test(document.documentElement.innerHTML.slice(0, 50000))) {
    const currentHost = window.location.hostname;
    const brand = allScriptText.match(copyrightPattern)?.[2]?.toLowerCase()
      || document.documentElement.innerHTML.match(copyrightPattern)?.[2]?.toLowerCase();
    if (brand) {
      const brandDomains = BRAND_DOMAINS[brand] || [];
      const matches = brandDomains.some(d => currentHost.includes(d));
      if (!matches) {
        findings.push(`Source code contains ${brand} copyright notice but domain is "${currentHost}"`);
        suspicionScore += 0.5;
      }
    }
  }

  // Suspicious class names / IDs (phishing kit signatures)
  const phishingClassPatterns = [
    'fake-browser', 'browser-window', 'oauth-window', 'popup-window',
    'overlay-browser', 'win-browser', 'chrome-window',
  ];
  for (const cls of phishingClassPatterns) {
    if (document.querySelector(`[class*="${cls}"], [id*="${cls}"]`)) {
      findings.push(`Suspicious element found with class/id: "${cls}"`);
      suspicionScore += 0.35;
    }
  }

  const score = Math.min(1.0, suspicionScore);
  const detail = findings.length > 0
    ? findings.slice(0, 5).join('; ')
    : 'No known phishing DOM signatures detected.';

  return { signal: 'domPhishingSignature', score, weight: 0.55, detail, element: 'document' };
}

// ─── Signal 8: SSL Certificate (via background response) ──────────────────────
export function checkSSLCertificate(certInfo) {
  // certInfo is passed from service worker via messaging
  if (!certInfo) {
    return {
      signal: 'sslCertificate',
      score: 0.1,
      weight: 0.80,
      detail: 'SSL certificate information unavailable.',
      element: null,
    };
  }

  const { isValid, issuer, daysUntilExpiry, isSelfSigned, isRecent, mismatch } = certInfo;
  const findings = [];
  let suspicionScore = 0;

  if (!isValid) { suspicionScore = 1.0; findings.push('Invalid SSL certificate'); }
  if (isSelfSigned) { suspicionScore += 0.5; findings.push('Self-signed certificate'); }
  if (isRecent) { suspicionScore += 0.2; findings.push('Certificate issued within last 30 days'); }
  if (mismatch) { suspicionScore += 0.6; findings.push('Certificate SAN does not match domain'); }
  if (daysUntilExpiry !== undefined && daysUntilExpiry < 0) {
    suspicionScore += 0.8; findings.push('SSL certificate has expired');
  }
  if (issuer && /let'?s encrypt/i.test(issuer)) {
    suspicionScore += 0.05; findings.push("Free TLS cert (Let's Encrypt) on apparent banking/financial page");
  }

  const score = Math.min(1.0, suspicionScore);
  const detail = findings.length > 0
    ? findings.join('; ')
    : `SSL valid. Issuer: ${issuer || 'Unknown'}. ${daysUntilExpiry} days until expiry.`;

  return { signal: 'sslCertificate', score, weight: 0.80, detail, element: null };
}

// ─── Signal 9: Redirect Chain Analysis (via background) ───────────────────────
export function checkRedirectChain(redirectData) {
  if (!redirectData) {
    return { signal: 'redirectChain', score: 0, weight: 0.70, detail: 'No redirect data available.', element: null };
  }

  const { chain, hasOpenRedirect } = redirectData;
  const findings = [];
  let suspicionScore = 0;

  if (chain && chain.length > 3) {
    suspicionScore += 0.3 + (chain.length - 3) * 0.1;
    findings.push(`Long redirect chain: ${chain.length} hops`);
  }

  if (chain && chain.length >= 2) {
    for (let i = 0; i < chain.length - 1; i++) {
      try {
        const fromTLD = chain[i].match(/\.([a-z]{2,})\//)?.[1];
        const toTLD = chain[i + 1].match(/\.([a-z]{2,})\//)?.[1];
        if (fromTLD && toTLD && fromTLD !== toTLD && fromTLD !== 'com' && toTLD !== 'com') {
          suspicionScore += 0.3;
          findings.push(`TLD boundary crossing: .${fromTLD} → .${toTLD}`);
        }
      } catch { /* ignore */ }
    }
  }

  if (hasOpenRedirect) {
    suspicionScore += 0.4;
    findings.push('Open redirect parameter detected in URL');
  }

  const score = Math.min(1.0, suspicionScore);
  const detail = findings.length > 0
    ? findings.join('; ')
    : 'No suspicious redirect chain patterns detected.';

  return { signal: 'redirectChain', score, weight: 0.70, detail, element: null };
}

// ─── Signal 10: Unicode / Homograph URL Attack ────────────────────────────────
export function checkUnicodeHomograph() {
  const href = window.location.href;
  const hostname = window.location.hostname;
  const findings = [];
  let suspicionScore = 0;

  // Detect Punycode / IDN domains
  if (hostname.startsWith('xn--') || hostname.includes('.xn--')) {
    suspicionScore += 0.5;
    findings.push(`Internationalized Domain Name (IDN) detected: ${hostname}`);
  }

  // Check for mixed scripts (Cyrillic mixed with Latin)
  const cyrillicChars = hostname.match(/[\u0400-\u04FF]/g);
  const greekChars = hostname.match(/[\u0370-\u03FF]/g);
  const armenianChars = hostname.match(/[\u0530-\u058F]/g);
  if (cyrillicChars) {
    suspicionScore += 0.7;
    findings.push(`Cyrillic characters in domain: ${cyrillicChars.join('')}`);
  }
  if (greekChars) {
    suspicionScore += 0.6;
    findings.push(`Greek characters in domain: ${greekChars.join('')}`);
  }
  if (armenianChars) {
    suspicionScore += 0.6;
    findings.push(`Armenian characters in domain: ${armenianChars.join('')}`);
  }

  // RTL override character
  if (href.includes('\u202E') || href.includes('%E2%80%AE')) {
    suspicionScore += 0.9;
    findings.push('RTL override character (U+202E) detected in URL — domain spoofing attempt');
  }

  // Normalized domain check against brand list
  const normalizedHostname = normalizeHomoglyphs(hostname.replace(/^www\./, ''));
  for (const [brand, domains] of Object.entries(BRAND_DOMAINS)) {
    const normalizedBrand = normalizeHomoglyphs(brand);
    const matchesBrand = domains.some(d => normalizeHomoglyphs(d.replace(/^www\./, '')) === normalizedHostname);
    const hostnameActuallyMatches = domains.some(d => hostname.includes(d));
    if (normalizedHostname.includes(normalizedBrand) && !hostnameActuallyMatches) {
      suspicionScore += 0.75;
      findings.push(`Homograph attack: domain "${hostname}" normalizes to "${normalizedHostname}" impersonating "${brand}"`);
    }
  }

  // Open redirect patterns
  const suspiciousParams = ['redirect', 'url', 'goto', 'next', 'return', 'returnUrl', 'continue'];
  const params = new URL(window.location.href).searchParams;
  for (const p of suspiciousParams) {
    const val = params.get(p);
    if (val && (val.startsWith('http://') || val.startsWith('https://'))) {
      suspicionScore += 0.3;
      findings.push(`Open redirect parameter: ?${p}=${val.slice(0, 50)}`);
    }
  }

  const score = Math.min(1.0, suspicionScore);
  const detail = findings.length > 0
    ? findings.join('; ')
    : 'No Unicode/homograph attack patterns detected.';

  return { signal: 'unicodeHomograph', score, weight: 0.85, detail, element: 'window.location' };
}

// ─── Signal 11: Browser-in-the-Browser (BitB) Detection ──────────────────────
export function checkBitBAttack() {
  const viewportW = window.innerWidth;
  const viewportH = window.innerHeight;
  const findings = [];
  let suspicionScore = 0;

  const bitbSelectors = [
    '[class*="browser-window"]', '[class*="fake-browser"]', '[class*="popup-window"]',
    '[class*="oauth-window"]', '[id*="browser-window"]', '[id*="fake-browser"]',
    '[class*="chrome-window"]', '[class*="safari-window"]',
  ];

  for (const sel of bitbSelectors) {
    const el = document.querySelector(sel);
    if (el) {
      findings.push(`BitB indicator element found: ${sel}`);
      suspicionScore += 0.5;
    }
  }

  // Check for fake URL bar inputs in non-iframe context
  document.querySelectorAll('input[type="text"], input[type="url"]').forEach(input => {
    const parent = input.closest('[style], [class]');
    if (!parent) return;
    const style = window.getComputedStyle(parent);
    const className = (parent.className || '').toLowerCase();
    const idName = (parent.id || '').toLowerCase();
    if (
      (style.position === 'fixed' || style.position === 'absolute') &&
      (className.includes('url') || idName.includes('url') || className.includes('address') || idName.includes('address'))
    ) {
      suspicionScore += 0.4;
      findings.push('Fake URL bar input field detected outside iframe');
    }
  });

  // Fixed/absolute positioned overlays near full viewport size
  document.querySelectorAll('div, section').forEach(el => {
    const style = window.getComputedStyle(el);
    if (style.position !== 'fixed' && style.position !== 'absolute') return;
    const rect = el.getBoundingClientRect();
    if (rect.width >= viewportW * 0.5 && rect.height >= viewportH * 0.5) {
      const hasInputs = el.querySelector('input') !== null;
      const hasPasswordInput = el.querySelector('input[type="password"]') !== null;
      if (hasInputs && hasPasswordInput) {
        findings.push('Large overlay with credential inputs — possible BitB attack');
        suspicionScore += 0.7;
      }
    }
  });

  const score = Math.min(1.0, suspicionScore);
  const detail = findings.length > 0
    ? findings.join('; ')
    : 'No Browser-in-the-Browser attack indicators detected.';

  return { signal: 'bitbAttack', score, weight: 0.85, detail, element: 'div, iframe' };
}

// ─── Signal 12: PhishTank Result (passed from background/cache) ──────────────
export function checkPhishTankResult(phishTankData) {
  if (!phishTankData) {
    return {
      signal: 'phishTank',
      score: 0,
      weight: 1.00,
      detail: 'PhishTank check pending or API unavailable.',
      element: null,
    };
  }

  const { inDatabase, verified, error } = phishTankData;

  if (error) {
    return {
      signal: 'phishTank',
      score: 0,
      weight: 1.00,
      detail: `PhishTank API error: ${error}. Relying on heuristic signals.`,
      element: null,
    };
  }

  if (inDatabase && verified) {
    return {
      signal: 'phishTank',
      score: 1.0,
      weight: 1.00,
      detail: 'URL is CONFIRMED in PhishTank\'s verified phishing database. This is a known phishing site.',
      element: null,
    };
  }

  if (inDatabase && !verified) {
    return {
      signal: 'phishTank',
      score: 0.5,
      weight: 1.00,
      detail: 'URL is in PhishTank database but not yet verified.',
      element: null,
    };
  }

  return {
    signal: 'phishTank',
    score: 0,
    weight: 1.00,
    detail: 'URL is not in PhishTank phishing database.',
    element: null,
  };
}

// ─── Run All DOM-based Signals ────────────────────────────────────────────────
export function runAllDOMSignals() {
  return [
    checkTitleDomainMismatch(),
    checkCSRFTokenAbsence(),
    checkPasswordOverHTTP(),
    checkIframeSuspicion(),
    checkExternalResources(),
    checkLinkImageMismatch(),
    checkDOMPhishingSignatures(),
    checkUnicodeHomograph(),
    checkBitBAttack(),
  ];
}
