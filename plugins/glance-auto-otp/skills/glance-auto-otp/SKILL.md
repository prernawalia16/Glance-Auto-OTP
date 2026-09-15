---
name: glance-auto-otp
description: Automatic authenticator-app (TOTP) handling for Applied Information Playwright suites - fills the 2FA screen that appears after username/password so scripts run unattended, on appinfoinc.com products only. Use when setting up or debugging automated login for any appinfoinc project (Glance, Device Config / 85 Utility, Portal and the individual products), when someone says the script stops at the OTP screen or asks to stop typing codes from Microsoft Authenticator, and whenever OTP codes are being rejected.
---

# Glance Auto OTP

Every Applied Information product shares one login shape:

```
username + password  ->  (if credentials valid) OTP screen  ->  whatever the script needs next
```

The OTP comes from an authenticator app (Microsoft Authenticator). That app is
not a source of truth — it is a *reader* of a shared secret captured when 2FA
was enrolled. Anything holding the same secret computes the same six digits at
the same moment. So a test suite with the secret needs no phone and no human.

This skill automates that middle screen and nothing else.

---

## Hard rules

These are not preferences. Do not relax them unless the person you are working
with says so explicitly, for that specific case.

### 1. appinfoinc.com only

`assertAllowedDomain` refuses to type a code on any host that is not
`appinfoinc.com` or a subdomain of it, and it runs before every attempt. A
live second factor must never be typed into a look-alike host. If someone
wants this on a non-Applied-Information site, stop and ask — do not edit the
guard to let it through.

### 2. Never store credentials

**Never write a username, password or TOTP secret into a memory file, a
journal, a report, a commit, a skill file, or any note that outlives the
session.** This covers every appinfoinc project and every teammate's.

What may be recorded is the *shape*: which env var holds it, which account
type is in use, that a secret exists. Never the value. When a credential
appears in conversation, use it and let it stay in the conversation — do not
copy it anywhere persistent.

### 3. Ask before touching a credentials file

When picking up a project folder — **especially a teammate's** — do not read
or write `.env` (or any credentials file) without asking first:

- *"May I read `.env` for the username/password, or would you rather supply
  them another way?"*
- *"Where should the TOTP secret live — `.env` as `TOTP_SECRET`, or somewhere
  else you prefer?"*

If any of username, password or secret is missing, **ask which project is
being worked on and request them** rather than guessing, reusing another
project's values, or hunting through the filesystem for them.

### 4. Never print the digits

Log that a code was generated and how much window it has left — never the code
itself. It is a live credential for up to 30 seconds. The one exception is the
deliberate diagnosis command below, which exists so a human can compare
against their phone.

---

## Setting it up in a project

1. **Confirm the domain.** The product must be on `*.appinfoinc.com`.

2. **Get the secret** (ask; never go looking for it). Either form works:
   - the Base32 key shown next to the QR on the 2FA setup screen, or
   - the whole `otpauth://totp/...` value behind that QR.

   If 2FA is not enrolled yet, or the existing secret turns out to be stale,
   the person must re-enroll: scan the QR into Microsoft Authenticator **and**
   paste the same key into the project. Microsoft Authenticator cannot export
   a key it already holds, so re-enrollment is the only recovery. Both should
   end up holding the same secret so manual testing still works.

3. **Store it where they say** — default `TOTP_SECRET` in `.env`, after
   confirming `.env` is gitignored. Confirm that with them; don't assume.

4. **Install the dependency and copy the helper:**
   ```bash
   npm install --save-dev otpauth
   ```
   Copy `otpAuth.js` from this skill into the project's helpers directory. It
   imports nothing but `otpauth`, so it needs no adaptation to the project's
   config/logger/constants.

5. **Call it straight after submitting username and password:**
   ```js
   import { handleOtpScreen } from './helpers/otpAuth.js';

   await performLogin(page, username, password);
   await handleOtpScreen(page, { logger });   // no-op when no 2FA screen appears
   // ...then whatever this script needs next - business selection, dashboard, portal
   ```

   It is safe to call unconditionally: with no OTP screen present it returns
   `{ handled: false }` instead of failing.

6. **Verify with a real login** before declaring it done, and delete any
   throwaway spec written for that check.

---

## What this helper deliberately does not do

**It does not know what comes after the OTP screen.** Success is defined as
*"the OTP field is gone and no error appeared"* — never as the arrival of a
particular page. The next screen differs per product and per script
(business selection, dashboard, portal, an individual product), so asserting
it belongs to the caller. Do not add next-screen assertions into the helper;
that is exactly what stops it being reusable.

---

## Behaviours that cost real debugging time

Carry these across; they are not obvious from the code.

- **A retry only means something in a new 30-second window.** Resubmitting
  inside one window sends identical digits, which are rejected identically —
  and many validators refuse an already-consumed code even inside its window.
  The ~30s pause between attempts is correctness, not slack. Say why it is
  waiting, or it reads as a hang.

- **Rejection is reported differently per product.** Glance and 85 Utility use
  the SweetAlert2 modal (`.swal2-popup`), *not* an inline `[role="alert"]`.
  The helper covers the usual shapes, but if a product uses something else,
  **probe the live app once and pass `selectors.error`** — never guess it. An
  undetected rejection degrades into a silent timeout, which is what makes an
  OTP failure look like a hang.

- **A modal rejection must be dismissed before retrying**, or the retry types
  into a field behind the overlay. SweetAlert also swallows clicks while
  fading, so wait for it to be hidden rather than trusting the click.

- **Never tick "Remember this device."** It suppresses the 2FA screen on later
  runs, which silently stops exercising this path.

---

## When codes are rejected — diagnosis, in this order

A stale secret, a drifted clock and a wrong selector all look identical from
the outside. Do these in order; the first two take seconds.

1. **Clock skew.** Compare the server's own clock against the machine's:
   ```bash
   node -e "require('https').get('https://<host>.appinfoinc.com/',r=>{console.log('skew:',Math.round((Date.now()-new Date(r.headers.date))/1000),'s');r.destroy()})"
   ```
   TOTP is a function of the clock. More than ~15s of skew breaks it, and the
   fix is the machine's time sync, not the code.

2. **Compare against the phone.** This deliberately prints the digits so a
   human can check them against Microsoft Authenticator:
   ```bash
   node -r dotenv/config -e "import('./helpers/otpAuth.js').then(async m=>console.log(await m.getFreshCode(), m.secondsRemaining()+'s left'))"
   ```
   Zero skew **and** a code that does not match the phone means the stored
   secret no longer matches the enrollment — it must be re-enrolled (step 2 of
   setup). This is the common case; it is what happened on 85 Utility on
   2026-09-15.

3. **Only then suspect selectors.** If the code matches the phone and is still
   refused, the submit or error selector is probably wrong for that product —
   probe the live screen and pass `selectors`.

---

## Bypassing it

`OTP_MODE=manual` in the environment, or `{ mode: 'manual' }`, restores the
wait-for-a-human path. Use it when the 2FA screen itself is what is under
test — automatic entry would defeat the purpose of testing that screen.
