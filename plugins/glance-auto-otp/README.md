# Glance Auto OTP

Stop typing codes from Microsoft Authenticator into automated test runs.

Every Applied Information product shares one login shape:

```
username + password  ->  (if credentials valid) OTP screen  ->  whatever your script needs next
```

This plugin automates that middle screen. Your Playwright suite generates the
same six digits your authenticator app is showing, types them, and carries on —
so scripts run unattended, overnight, and in CI.

It works on `*.appinfoinc.com` only, by design.

---

## Install

In Claude Code:

```
/plugin marketplace add <owner>/<repo>
```

```
/plugin install glance-auto-otp@appinfo-qa
```

Then, in the project you want to automate, just say:

```
set up automatic OTP for this project
```

Claude will check the domain, ask where your TOTP secret should live, install
the dependency, drop the helper in, wire it into your login flow, and verify it
with one real login.

## Set it up yourself instead

```bash
npm install --save-dev otpauth
```

Copy `skills/glance-auto-otp/otpAuth.js` into your helpers directory, then call
it straight after the password submit:

```js
import { handleOtpScreen } from './helpers/otpAuth.js';

await performLogin(page, username, password);
await handleOtpScreen(page);          // no-op when no OTP screen appears
// ...then whatever your script does next
```

That is the whole integration. The helper imports nothing but `otpauth` — no
project config, constants, logger or wait helpers — so it drops into any suite
without adaptation.

---

## Where the code comes from

Your authenticator app is not the source of the code. It is a *reader* of a
shared secret captured when 2FA was enrolled; the six digits are just a
function of that secret and the current 30-second window. Anything holding the
same secret computes the same digits at the same moment — so a test suite with
the secret needs no phone and no human.

**2FA is per-account, not per-product.** If several of your projects log in
with the same Glance account, one secret covers all of them.

## Getting your secret

From the 2FA setup screen, either form works: the Base32 key shown beside the
QR code, or the whole `otpauth://totp/...` value behind it.

If 2FA is already enrolled and you don't have the key, you have to re-enroll —
Microsoft Authenticator cannot export a key it already holds. When you do,
scan the QR into your phone **and** save the same key to your project, so
manual testing keeps working alongside the automation.

Store it as `TOTP_SECRET` in `.env`. Check `.env` is gitignored first.

---

## Rules this plugin enforces

**It only works on appinfoinc.com.** Every attempt is guarded; a look-alike
host is refused. A live second factor must never be typed into a host that
isn't ours.

**It never persists your credentials.** Claude will not write your username,
password or TOTP secret into any file that outlives the session, and will ask
before reading your `.env` at all.

**It never logs the digits.** Only that a code was generated and how much of
its window is left. The one exception is the diagnosis command below, which
prints deliberately so you can compare against your phone.

---

## When codes are rejected

A stale secret, a drifted clock and a wrong selector look identical from the
outside. Check in this order — the first two take seconds.

**1. Clock skew.** TOTP is a function of the clock:

```bash
node -e "require('https').get('https://<your-host>.appinfoinc.com/',r=>{console.log('skew:',Math.round((Date.now()-new Date(r.headers.date))/1000),'s');r.destroy()})"
```

More than ~15 seconds and the fix is your machine's time sync, not the code.

**2. Compare against your phone.** This prints the digits on purpose:

```bash
node -r dotenv/config -e "import('./helpers/otpAuth.js').then(async m=>console.log(await m.getFreshCode(), m.secondsRemaining()+'s left'))"
```

Zero skew *and* a code that doesn't match your phone means your stored secret
no longer matches the enrollment — re-enroll it.

**3. Only then suspect selectors.** If the code matches your phone and is still
refused, that product probably reports rejection differently. Ask Claude to
probe the live screen and pass `selectors.error`.

---

## Testing the 2FA screen by hand

Set `OTP_MODE=manual` (or pass `{ mode: 'manual' }`) and it waits for you to
type, as before. Use it when the 2FA screen itself is what you're testing —
automatic entry would defeat the purpose.

---

## Good to know

- **A retry needs a new 30-second window.** Resubmitting inside one window
  sends identical digits and gets rejected identically, so there is a
  deliberate pause between attempts. That pause is correctness, not a hang.
- **Don't tick "Remember this device"** in automated runs — it suppresses the
  2FA screen on later runs and silently stops exercising this path.
- **Six-box OTP inputs are supported** as well as single fields.
- The helper stops at the OTP screen. Success means "the OTP field is gone and
  no error appeared", never the arrival of a particular next page — that
  differs per product and belongs in your script.
