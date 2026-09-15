/**
 * Automatic TOTP (authenticator-app) handling for Applied Information
 * Playwright suites.
 *
 * DROP-IN AND PORTABLE BY DESIGN. Its only dependency is `otpauth`. It does
 * not import a project's config, constants, logger or wait helpers, because
 * those differ per project and coupling to them is what stops a helper being
 * reusable. Everything project-specific arrives through `options`.
 *
 * SCOPE - this file handles exactly one screen: the 2FA prompt that appears
 * after valid username/password. It deliberately does NOT know or assert what
 * comes after it (business selection, dashboard, portal, anything) - that
 * belongs to the calling script and differs per product.
 *
 * Only works against *.appinfoinc.com. See assertAllowedDomain.
 */

import * as OTPAuth from 'otpauth';

const ALLOWED_DOMAIN = 'appinfoinc.com';
const PERIOD = 30;

const DEFAULTS = {
  maxAttempts: 3,
  // Never submit a code with less than this much of its window left: it can
  // expire server-side mid-validation and read as a wrong code.
  minWindowSeconds: 5,
  // How long to wait for the OTP screen to appear at all before concluding
  // this login has no 2FA step.
  detectTimeout: 15000,
  // How long to wait for the screen to resolve after clicking submit.
  resultTimeout: 15000,
  // Manual fallback: how long a human is given to type a code.
  manualWaitMs: 300000,
};

// Heuristics that identify the OTP field across products without
// configuration. Explicit `options.selectors.input` always wins over these.
const OTP_INPUT_PATTERNS = [
  '#txt2faOtp',
  'input[id*="otp" i]',
  'input[name*="otp" i]',
  'input[placeholder*="otp" i]',
  'input[aria-label*="otp" i]',
  'input[id*="2fa" i]',
  'input[id*="mfa" i]',
  'input[name*="code" i]',
  'input[placeholder*="code" i]',
  'input[autocomplete="one-time-code"]',
];

const SUBMIT_PATTERNS = [
  'button.auth-btn',
  'button:has-text("Authenticate")',
  'button:has-text("Verify")',
  'button:has-text("Submit")',
  'button:has-text("Continue")',
  'input[type="submit"]',
];

// Containers products use to report a rejected code. `.swal2-popup` is the
// SweetAlert2 modal Glance and 85 Utility use; the rest cover the usual
// inline/toast shapes. A product that uses something else must pass
// options.selectors.error - do NOT guess, probe the live app once.
const ERROR_PATTERNS = [
  '.swal2-popup',
  '[role="alert"]',
  '.error-message',
  '.validation-error',
  '.toast-error',
];

/**
 * HARD GUARD. This helper is for Applied Information products only. Refuse to
 * type a TOTP code into anything else - a look-alike host must never receive
 * a live second factor.
 *
 * Matches the domain itself or any subdomain of it. `evil-appinfoinc.com` and
 * `appinfoinc.com.attacker.net` both correctly fail.
 */
export function assertAllowedDomain(url) {
  let hostname;
  try {
    hostname = new URL(url).hostname.toLowerCase();
  } catch {
    throw new Error(`Cannot check the domain of an unparseable URL: "${url}"`);
  }

  const allowed = hostname === ALLOWED_DOMAIN || hostname.endsWith(`.${ALLOWED_DOMAIN}`);
  if (!allowed) {
    throw new Error(
      `Refusing to enter an OTP on "${hostname}". This helper only works on ` +
      `${ALLOWED_DOMAIN} and its subdomains.`
    );
  }
  return hostname;
}

/* ------------------------------------------------------------------ *
 * Code generation
 * ------------------------------------------------------------------ */

/**
 * Accepts either form of the enrollment value, so whatever is on hand can be
 * pasted into .env without reformatting:
 *   - a raw Base32 key ("JBSWY3DPEHPK3PXP"; spaces/lowercase tolerated)
 *   - the full QR payload ("otpauth://totp/Issuer:user?secret=...&digits=6")
 * Parameters come from the URI when it supplies them, because a non-default
 * enrollment (8 digits, SHA256, 60s) would otherwise silently generate wrong
 * codes that look exactly like a stale secret.
 */
function buildTotp(rawSecret) {
  if (!rawSecret || !String(rawSecret).trim()) {
    throw new Error('No TOTP secret supplied (expected options.secret or TOTP_SECRET in .env).');
  }

  const value = String(rawSecret).trim();

  if (value.toLowerCase().startsWith('otpauth://')) {
    const parsed = OTPAuth.URI.parse(value);
    if (!(parsed instanceof OTPAuth.TOTP)) {
      throw new Error('The secret is an otpauth:// URI but not a TOTP one (HOTP is not supported).');
    }
    return parsed;
  }

  // Base32 ignores case, padding and whitespace; setup screens routinely show
  // the key lowercased in groups of four, so normalise rather than reject.
  const base32 = value.replace(/\s+/g, '').replace(/=+$/, '').toUpperCase();

  try {
    return new OTPAuth.TOTP({
      secret: OTPAuth.Secret.fromBase32(base32),
      digits: 6,
      period: PERIOD,
      algorithm: 'SHA1',
    });
  } catch (error) {
    throw new Error(
      `The TOTP secret is not valid Base32 (${error.message}). Paste the key shown ` +
      'on the 2FA setup screen, or the full otpauth:// value behind its QR code.'
    );
  }
}

/** Seconds of validity left in the current 30-second window. */
export function secondsRemaining() {
  return PERIOD - (Math.floor(Date.now() / 1000) % PERIOD);
}

/** The code the authenticator app is showing right now. */
export function generateCode(secret = process.env.TOTP_SECRET) {
  return buildTotp(secret).generate();
}

/**
 * A code with enough life left to survive the submit round-trip. If the
 * window is about to roll over, wait it out rather than sending a code the
 * server will already have expired by the time it validates it.
 */
export async function getFreshCode(secret = process.env.TOTP_SECRET, minWindowSeconds = DEFAULTS.minWindowSeconds) {
  if (secondsRemaining() < minWindowSeconds) {
    await waitForNextWindow();
  }
  return generateCode(secret);
}

/**
 * Block until the current window rolls over, so a retry submits genuinely
 * different digits. Resubmitting inside one window is pointless: the server
 * rejects identical digits identically, and many validators refuse a code
 * that has already been consumed even while it is still in its window.
 */
export async function waitForNextWindow() {
  await new Promise(resolve => setTimeout(resolve, (secondsRemaining() + 1) * 1000));
}

/* ------------------------------------------------------------------ *
 * Screen detection
 * ------------------------------------------------------------------ */

/**
 * Find the OTP entry control, trying an explicit selector first, then the
 * shared heuristics, then the split-box variant (six single-character inputs,
 * common in newer UIs).
 *
 * @returns {Promise<{ kind: 'single'|'split', locator?, locators?, count?: number }|null>}
 */
export async function findOtpField(page, explicitSelector, timeout = DEFAULTS.detectTimeout) {
  if (explicitSelector) {
    const locator = page.locator(explicitSelector).first();
    const visible = await locator.waitFor({ state: 'visible', timeout }).then(() => true).catch(() => false);
    return visible ? { kind: 'single', locator } : null;
  }

  // One pass over the heuristics with a short per-pattern timeout, repeated
  // until the overall budget runs out - the screen may still be rendering.
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    for (const pattern of OTP_INPUT_PATTERNS) {
      const locator = page.locator(pattern).first();
      if (await locator.isVisible().catch(() => false)) {
        return { kind: 'single', locator };
      }
    }

    // Split-box form: several visible one-character inputs side by side.
    const boxes = page.locator('input[maxlength="1"]:visible');
    const count = await boxes.count().catch(() => 0);
    if (count >= 4 && count <= 8) {
      return { kind: 'split', locators: boxes, count };
    }

    await new Promise(resolve => setTimeout(resolve, 300));
  }

  return null;
}

/** True when a 2FA screen is on display. Cheap probe for callers that branch. */
export async function isOtpScreenPresent(page, explicitSelector, timeout = DEFAULTS.detectTimeout) {
  return Boolean(await findOtpField(page, explicitSelector, timeout));
}

async function fillOtp(field, code) {
  if (field.kind === 'single') {
    await field.locator.fill('');
    await field.locator.fill(code);
    return;
  }

  // Split boxes: one character each, in order. Many such widgets auto-advance
  // focus, but filling each box directly works with and without that.
  for (let i = 0; i < field.count; i++) {
    await field.locators.nth(i).fill(code[i] ?? '');
  }
}

async function clearOtp(field) {
  if (field.kind === 'single') {
    await field.locator.fill('').catch(() => {});
    return;
  }
  for (let i = 0; i < field.count; i++) {
    await field.locators.nth(i).fill('').catch(() => {});
  }
}

async function findSubmitButton(page, explicitSelector) {
  if (explicitSelector) return page.locator(explicitSelector).first();

  for (const pattern of SUBMIT_PATTERNS) {
    const locator = page.locator(pattern).first();
    if (await locator.isVisible().catch(() => false)) return locator;
  }
  return null;
}

/* ------------------------------------------------------------------ *
 * Result handling
 * ------------------------------------------------------------------ */

/**
 * What happened after submitting.
 *
 * Success is defined ONLY as "the OTP screen went away" - never as the
 * appearance of a particular next page, because the next page differs per
 * product and per script. Rejection is whichever error container the product
 * uses; its text is returned verbatim so a failure reports the app's own
 * wording instead of a guess.
 *
 * @returns {Promise<{ status: 'success'|'rejected'|'timeout', message: string|null }>}
 */
async function checkResult(page, field, errorSelector, timeout) {
  const errorSelectors = errorSelector ? [errorSelector] : ERROR_PATTERNS;
  const deadline = Date.now() + timeout;

  while (Date.now() < deadline) {
    for (const selector of errorSelectors) {
      const error = page.locator(selector).first();
      if (await error.isVisible().catch(() => false)) {
        const text = await error.innerText().catch(() => '');
        return { status: 'rejected', message: text.replace(/\s+/g, ' ').trim() || null };
      }
    }

    const stillThere = field.kind === 'single'
      ? await field.locator.isVisible().catch(() => false)
      : await field.locators.first().isVisible().catch(() => false);

    if (!stillThere) return { status: 'success', message: null };

    await new Promise(resolve => setTimeout(resolve, 300));
  }

  return { status: 'timeout', message: null };
}

/**
 * Dismiss a modal rejection before retrying. A SweetAlert overlay is modal:
 * left open, the next attempt types into a field behind it and the retry is
 * wasted. It also swallows clicks while fading, so wait for it to be gone
 * rather than assuming the click landed.
 */
async function dismissError(page) {
  for (const selector of ['.swal2-confirm', '.toast-close', 'button:has-text("OK")']) {
    const button = page.locator(selector).first();
    if (await button.isVisible().catch(() => false)) {
      await button.click().catch(() => {});
      break;
    }
  }

  await page.locator('.swal2-popup').first()
    .waitFor({ state: 'hidden', timeout: 5000 })
    .catch(() => {});
}

async function waitForManualEntry(field, timeoutMs) {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    if (field.kind === 'single') {
      const value = await field.locator.inputValue().catch(() => '');
      if (value.trim().length >= 6) return value.trim();
    } else {
      const values = [];
      for (let i = 0; i < field.count; i++) {
        values.push(await field.locators.nth(i).inputValue().catch(() => ''));
      }
      const joined = values.join('').trim();
      if (joined.length >= field.count) return joined;
    }
    await new Promise(resolve => setTimeout(resolve, 500));
  }

  return null;
}

/* ------------------------------------------------------------------ *
 * Main entry point
 * ------------------------------------------------------------------ */

/**
 * Handle the 2FA screen if one is present, then return. Safe to call
 * unconditionally after submitting username/password: when no OTP screen
 * appears it returns `{ handled: false }` without failing.
 *
 * @param {import('@playwright/test').Page} page
 * @param {object} [options]
 * @param {string} [options.secret]      TOTP secret. Default: process.env.TOTP_SECRET.
 * @param {'auto'|'manual'} [options.mode]  Default 'auto'; 'manual' waits for a
 *   human to type, for when the 2FA screen itself is under test.
 *   process.env.OTP_MODE=manual forces this globally.
 * @param {object} [options.selectors]   { input, submit, error } - only needed
 *   where the heuristics miss. Probe the live app; never guess these.
 * @param {number} [options.maxAttempts]
 * @param {object} [options.logger]      Anything with .log/.warn; defaults to console.
 * @returns {Promise<{ handled: boolean, attempts: number }>}
 */
export async function handleOtpScreen(page, options = {}) {
  const config = { ...DEFAULTS, ...options };
  const selectors = options.selectors || {};
  const log = options.logger || console;
  const say = (message) => (log.log ? log.log(message) : console.log(message));
  const warn = (message) => (log.warn ? log.warn(message) : say(message));

  assertAllowedDomain(page.url());

  const field = await findOtpField(page, selectors.input, config.detectTimeout);
  if (!field) {
    say('No OTP screen presented - continuing.');
    return { handled: false, attempts: 0 };
  }

  const secret = options.secret || process.env.TOTP_SECRET;
  const manual = config.mode === 'manual'
    || process.env.OTP_MODE === 'manual'
    || !secret;

  if (manual && !secret) {
    warn('No TOTP secret available - falling back to manual OTP entry.');
  }

  for (let attempt = 1; attempt <= config.maxAttempts; attempt++) {
    let code;

    if (manual) {
      say(`Waiting for manual OTP entry (attempt ${attempt} of ${config.maxAttempts})...`);
      code = await waitForManualEntry(field, config.manualWaitMs);
      if (!code) {
        throw new Error(`No OTP was entered within ${config.manualWaitMs}ms.`);
      }
    } else {
      // A retry is only meaningful in a NEW window - see waitForNextWindow.
      if (attempt > 1) {
        say('Waiting for the next 30s code window before retrying...');
        await waitForNextWindow();
      }
      code = await getFreshCode(secret, config.minWindowSeconds);
      // Never log the digits themselves - they are a live credential.
      say(`Generated OTP (attempt ${attempt} of ${config.maxAttempts}, ${secondsRemaining()}s left in window)`);
      await fillOtp(field, code);
    }

    const submit = await findSubmitButton(page, selectors.submit);
    if (!submit) {
      throw new Error(
        'OTP submit button not found. Pass options.selectors.submit for this product.'
      );
    }
    await submit.click();

    const { status, message } = await checkResult(page, field, selectors.error, config.resultTimeout);

    if (status === 'success') {
      say('OTP accepted.');
      return { handled: true, attempts: attempt };
    }

    // 'timeout' means the screen neither advanced nor complained. Retry it
    // like a rejection, but say so plainly - a silent retry reads as a hang.
    const reason = message || (status === 'timeout' ? 'no response from the 2FA screen' : 'rejected');
    await dismissError(page);

    if (attempt < config.maxAttempts) {
      warn(`OTP not accepted (${reason}). Attempt ${attempt} of ${config.maxAttempts}.`);
      await clearOtp(field);
      continue;
    }

    throw new Error(
      `OTP authentication failed after ${config.maxAttempts} attempts (${reason}).` +
      (manual ? '' : ' If the codes are being rejected, the secret is probably stale or the clock has drifted - run the diagnosis in the appinfo-otp skill.')
    );
  }
}

export default {
  handleOtpScreen,
  isOtpScreenPresent,
  findOtpField,
  generateCode,
  getFreshCode,
  waitForNextWindow,
  secondsRemaining,
  assertAllowedDomain,
};
