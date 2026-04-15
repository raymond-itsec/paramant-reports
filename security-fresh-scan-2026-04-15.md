# PARAMANT Fresh Security Scan

Date: 2026-04-15

This report is a fresh, read-only security review of the checked-in repository. I did not patch code. I did not rely on the older findings reports for conclusions.

Scope of this pass:

- Manual code and config review of the repository
- CWE-oriented review of server code, browser code, Docker/nginx config, and checked-in imported artifacts
- Explicit callout of anything I could not fully verify from the current workspace

What this report is not:

- Not a network pentest
- Not an online CVE/advisory sweep
- Not a claim that minified or compiled third-party artifacts are fully audited

## Summary

| Severity | Finding | CWE |
| --- | --- | --- |
| High | Static relay-registry viewer has a real DOM XSS path from attacker-controlled relay metadata | CWE-79 |
| High | Thunderbird FileLink uploads embed the raw AES key next to the ciphertext, so the relay can decrypt attachment content | CWE-320 |
| Medium | Several public relay routes call `decodeURIComponent()` without a guard; malformed path bytes can raise an uncaught exception and trigger emergency process exit | CWE-248, CWE-20 |
| High | Admin and public trial-key rate limits can be bypassed via spoofed `X-Forwarded-For` because the app trusts the first forwarded IP and shipped nginx configs preserve attacker input | CWE-290, CWE-307 |
| Medium | `users.json` persistence is still race-prone and can lose key create/revoke/trial updates under concurrent requests | CWE-362, CWE-367 |
| Medium | Other relay endpoints do the opposite proxy mistake: they ignore forwarded client IPs entirely, so trial-key and MFA rate limits collapse to the reverse proxy IP | CWE-307 |
| Medium | Public `/v2/sign-dpa` is unauthenticated and effectively unthrottled in the shipped live config, allowing email/disk spam and noisy operator abuse | CWE-770 |
| Low | Trial/DPA email templates interpolate user-controlled HTML without output encoding | CWE-116 |
| Low | The new admin SPA keeps its session token in `localStorage`; I did not find a direct XSS in that app during this pass, but any future same-origin script injection would expose it | CWE-922 |
| Low | Installer scripts emit SHA-1 TOTP provisioning URIs while the relay verifies TOTP-SHA256 codes | CWE-436 |

## Reality Check

| Finding | Hypothetical or real? | Operational impact |
| --- | --- | --- |
| Static relay-registry viewer XSS | Real in the static-site deployment path | Real browser-side compromise of the static site origin; can steal same-origin data such as stored API keys |
| Thunderbird FileLink raw-key packaging | Real in the checked-in Thunderbird/FileLink path | Real confidentiality failure for Thunderbird attachment uploads; the relay can decrypt uploaded chunks because the AES key is carried inside the uploaded blob |
| Malformed percent-encoded path crash | Real code-path issue; external reachability depends on whether the front proxy rejects malformed encodings before Node sees them | If such a request reaches the relay process, it exits and zeroizes active in-memory blobs, causing immediate availability loss and pending-transfer data loss |
| Spoofable `X-Forwarded-For` in `admin/server.js` | Real where the new admin service or `/api/request-key` is deployed behind the shipped nginx configs | Real rate-limit bypass on login in self-hosted admin deployments, and real bypass on public key-request throttling where `/api/request-key` is exposed |
| `users.json` lost-update race | Real but concurrency-dependent | Real integrity drift between in-memory auth state and persisted auth state; most visible after restart/reload |
| Relay-side use of `remoteAddress` behind a proxy | Real in proxied deployments, which is exactly how the shipped nginx configs are intended to run | Real shared-bucket denial of service on MFA/trial-key rate limits |
| Public `/v2/sign-dpa` abuse | Real where `RESEND_API_KEY` is configured and the live nginx path is exposed | Real mail spam, operator-noise, and append-only file growth |
| HTML injection in trial/DPA emails | Real but low impact | Real markup/phishing-style abuse inside mail clients, but I did not validate a mail-client script-execution path |
| Admin SPA session in `localStorage` | Residual / hypothetical on its own | Not a standalone exploit in this code review; becomes operational only if a separate same-origin XSS exists |
| Installer TOTP algorithm mismatch | Real in installer-driven deployments | Real admin MFA onboarding failure or lockout until the operator manually reprovisions the authenticator entry for SHA-256 |

In short:

- Findings 1 through 8 are not merely theoretical. They are either directly exploitable or operationally relevant in the repository's intended deployment paths.
- Finding 9 is the only one I would downgrade to a residual-risk note rather than a present exploit.

## Confirmed Findings

### 1. High: Static relay-registry viewer has a DOM XSS path

Affected refs:

- `relay/relay.js:1830-1851`
- `relay/relay.js:1867-1889`
- `frontend/ct-log.html:556-592`
- `frontend/drop.html:882-884`
- `frontend/parashare.html:596-598`

Why this is real:

- Public relay registration accepts caller-supplied `url`, `sector`, `version`, and `edition` values and stores them in the public relay registry after verifying only that the caller signed its own payload: `relay/relay.js:1830-1851`, `relay/relay.js:1867-1889`.
- The static CT/registry page renders those fields with raw string concatenation into `innerHTML` with no escaping: `frontend/ct-log.html:576-591`.
- An attacker does not need a pre-approved registry identity. They can generate their own ML-DSA keypair, sign their own malicious metadata, register it, and wait for a victim to load the page.

Impact:

- Arbitrary JavaScript can run in the origin serving `frontend/ct-log.html`.
- That same origin stores user API keys in `localStorage` on the file-send pages:
  - `frontend/drop.html:884`
  - `frontend/parashare.html:598`
- A successful XSS on the CT page can therefore steal `paramant_api_key` values for users who have used those pages on the same origin.

Operational verdict:

- Real-world operational impact.
- This is exploitable in the static-site deployment path represented by `deploy/nginx-paramant-live.conf`, which serves the static frontend and allows inline script execution via CSP.

Example attack shape:

- Register a relay with a `url` such as `https://x" onmouseover="...` or HTML-bearing content in `version` or `edition`.
- The CT page injects that value into the `title` attribute and visible HTML without encoding.
- Browser executes attacker-controlled markup/script in the page origin.

Notes:

- I checked the relay-served built-in `/ct` UI in `relay/relay.js:912-983`; that version escapes dynamic content correctly.
- The XSS is in the static `frontend/ct-log.html` implementation, not in the relay's built-in self-hosted `/ct` page.

### 2. High: Thunderbird FileLink uploads carry the AES key next to the ciphertext

Affected refs:

- `thunderbird-filelink/background.js:33-48`
- `thunderbird-filelink/background.js:61-84`
- `frontend/parashare.html:773-778`

Why this is real:

- The Thunderbird/FileLink path generates an AES-GCM content key, immediately exports that key as raw bytes, and serializes it directly into the uploaded packet:
  - key generation/export: `thunderbird-filelink/background.js:40-41`
  - packet layout comment and construction: `thunderbird-filelink/background.js:45-48`
- The resulting padded blob is then uploaded verbatim to `/v2/inbound` as the transfer payload: `thunderbird-filelink/background.js:61-84`.
- That means the relay does not merely hold ciphertext for this path. It holds `nonce + rawKey + ciphertext`, which is sufficient to decrypt the attachment content.

Impact:

- Any relay operator, host compromise, memory disclosure, or other server-side access to stored blobs can decrypt Thunderbird/FileLink uploads.
- This breaks the "relay cannot decrypt payload" property for that integration path.

Operational verdict:

- Real-world operational impact.
- This is a confidentiality failure in the checked-in Thunderbird/FileLink implementation, not a hypothetical crypto concern.

Scope note:

- I did not find the same raw-key packaging pattern in the main web send flow. The main browser path calls the Rust/WASM hybrid encryptor with receiver ML-KEM/ECDH public keys: `frontend/parashare.html:773-778`.
- So this finding is specific to the Thunderbird/FileLink upload path, not a blanket statement about every send path in the repository.

### 3. Medium: Malformed percent-encoded public paths can crash the relay process

Affected refs:

- `relay/relay.js:2014-2016`
- `relay/relay.js:2247-2249`
- `relay/relay.js:2265-2267`
- `relay/relay.js:2757-2759`
- `relay/relay.js:3469-3471`

Why this is real:

- Several public routes call `decodeURIComponent()` directly on attacker-controlled path segments:
  - `/v2/did/:did`: `relay/relay.js:2014-2016`
  - `/v2/pubkey/:device`: `relay/relay.js:2247-2249`
  - `/v2/fingerprint/:device`: `relay/relay.js:2265-2267`
  - `/v2/attest/:device`: `relay/relay.js:2757-2759`
- `decodeURIComponent()` throws on malformed percent-encoding such as truncated `%` sequences.
- Those route fragments are not wrapped in local `try/catch`, and the process-wide `uncaughtException` handler immediately calls `emergencyZeroAndExit(...)`: `relay/relay.js:3469-3471`.

Impact:

- If a malformed request reaches the Node process, it can terminate the relay.
- The exit path zeroizes and clears in-memory blobs before exit, so pending transfers are lost rather than merely interrupted.

Operational verdict:

- Real code-level operational impact.
- I am not silently assuming that every front proxy will pass malformed encodings through. What I can verify from the repository is that the relay process itself will exit if it receives one of these malformed route segments.

Why this matters:

- This is not just a crash-only bug. Because the product deliberately stores ciphertext blobs only in RAM, a forced process exit also destroys any in-flight transfer state.

### 4. High: Spoofable `X-Forwarded-For` defeats per-IP protections in the admin service

Affected refs:

- `admin/server.js:127-132`
- `admin/server.js:287-289`
- `deploy/nginx-selfhost.conf:90-94`
- `deploy/nginx-paramant-live.conf:49-53`
- `deploy/nginx-paramant-live.conf:58-62`

Why this is real:

- The admin service derives the client IP from the first entry of `X-Forwarded-For`:
  - login: `admin/server.js:127-132`
  - public key request: `admin/server.js:287-289`
- The shipped nginx configs forward `$proxy_add_x_forwarded_for`, which appends the upstream proxy IP to any attacker-supplied header instead of overwriting it:
  - `deploy/nginx-selfhost.conf:93`
  - `deploy/nginx-paramant-live.conf:53`
  - `deploy/nginx-paramant-live.conf:62`
- Because the application trusts the first entry, the caller can choose the IP bucket by sending its own `X-Forwarded-For`.

Impact:

- Login brute-force throttling on the admin service can be bypassed by rotating spoofed `X-Forwarded-For` values.
- The public `/request-key` flow can be farmed the same way, which matters because the endpoint returns the raw generated key in the JSON response after issuing it.

Operational verdict:

- Real-world operational impact, with deployment nuance.
- In self-hosted deployments using the new admin service behind `deploy/nginx-selfhost.conf`, the admin login path is affected.
- In the shipped live nginx config, the directly exposed impact is the public `/api/request-key` path. I did not verify that the new admin SPA login path is exposed in that live config.

Why this matters operationally:

- This is not just a generic header-trust concern. The repository ships nginx configs that make the bad trust decision exploitable as written.

### 5. Medium: `users.json` writes can still lose updates

Affected refs:

- `relay/relay.js:1249-1255`
- `relay/relay.js:1609-1615`
- `relay/relay.js:2828-2834`
- `relay/relay.js:2861-2867`

Why this is still present:

- `_writeUsersJson()` only serializes writes, not the full read-modify-write transaction: `relay/relay.js:1249-1255`.
- Trial-key persistence reads the file first, mutates the parsed object, and only then enqueues the write: `relay/relay.js:1609-1615`.
- Admin create-key does the same: `relay/relay.js:2828-2834`.
- Admin revoke-key does the same: `relay/relay.js:2861-2867`.

Impact:

- Two concurrent operations can read the same old snapshot and then overwrite each other in sequence.
- Plausible outcomes include:
  - a created key disappearing from `users.json`
  - a revoke being silently lost
  - a trial key existing in memory/JSONL but not in `users.json`

Operational verdict:

- Real-world operational impact, but concurrency-dependent rather than trivially triggerable by a single request.
- The most likely failure mode is persistent state divergence that only becomes obvious on restart, reload, backup restore, or another persistence-dependent workflow.

Why this is security-relevant:

- This is an integrity problem in the access-control data store, not just a reliability nit.

### 6. Medium: Other endpoints ignore proxy identity completely, so rate limits collapse to the proxy IP

Affected refs:

- `relay/relay.js:1575-1592`
- `relay/relay.js:2779-2792`
- `deploy/nginx-selfhost.conf:91-94`
- `deploy/nginx-paramant-live.conf:52-53`
- `deploy/nginx-paramant-live.conf:61-62`

Why this is real:

- `POST /v2/request-trial` keys its IP throttling off `req.socket.remoteAddress`: `relay/relay.js:1575-1592`.
- `POST /v2/admin/verify-mfa` does the same: `relay/relay.js:2779-2792`.
- Behind the shipped nginx setups, the relay sees the proxy connection IP, not the real caller, because these endpoints do not consume a trusted forwarded address.

Impact:

- On proxied deployments, trial-key requests effectively share a single 3-per-day bucket.
- MFA verification attempts effectively share a single 5-per-minute bucket.
- One noisy client can deny everyone else the rate-limited action until the window resets.

Additional note:

- `POST /v2/sign-dpa` also logs `req.socket.remoteAddress`, so the stored DPA audit IP is the proxy IP rather than the user IP: `relay/relay.js:1695-1697`.

This is the opposite failure mode from Finding 4:

- Finding 4 trusts forwarded IP too much.
- Finding 6 does not trust the proxy boundary at all.

Both are present in the same repository.

Operational verdict:

- Real-world operational impact.
- This is not hypothetical because the repository's intended deployment pattern is reverse-proxied nginx in front of the relay.

### 7. Medium: Public `/v2/sign-dpa` can be abused for spam/storage churn

Affected refs:

- `relay/relay.js:1671-1736`
- `deploy/nginx-paramant-live.conf:58-63`
- `frontend/dpa.html:347-353`

Why this is real:

- `POST /v2/sign-dpa` is public and unauthenticated: `relay/relay.js:1671-1736`.
- Each accepted request appends a record to disk: `relay/relay.js:1694-1697`.
- If `RESEND_API_KEY` is configured, each request also sends email to the submitted signer address and copies `privacy@paramant.app`: `relay/relay.js:1700-1731`.
- The shipped live nginx config exposes `/api/sign-dpa` directly and does not apply a dedicated `limit_req` to that location: `deploy/nginx-paramant-live.conf:58-63`.

Impact:

- Operator mailbox spam
- DPA record file growth
- Abuse of the public agreement-signing flow for nuisance traffic

This is not theoretical:

- The browser page `frontend/dpa.html` calls this endpoint directly with no auth barrier: `frontend/dpa.html:347-353`.

Operational verdict:

- Real-world operational impact.
- If mail delivery is enabled, an attacker can cause real outbound mail and real operator copy-mail traffic.
- Even without mail delivery, the append-only DPA record write still creates operational noise.

## Additional Observations

### 8. Low: Trial and DPA emails embed user-controlled HTML without encoding

Affected refs:

- `relay/relay.js:1629-1646`
- `relay/relay.js:1652-1662`
- `relay/relay.js:1702-1719`

What I saw:

- Trial welcome/notification emails interpolate `name` and `useCase` directly into HTML.
- DPA confirmation emails interpolate `name`, `org`, and `title` directly into HTML.

Impact:

- I did not identify a browser-script execution path here because modern mail clients usually strip or block active content.
- This is still enough for markup injection, misleading formatting, external resource loads in some clients, or phishing-style content inside operator mailboxes.

Operational verdict:

- Real but low impact.
- I would not classify this as hypothetical, because the unsafe interpolation is present and the resulting malformed/phishing-style email content is operationally meaningful even without script execution.

### 9. Low: New admin SPA stores its session token in `localStorage`

Affected refs:

- `admin/public/index.html:533`
- `admin/public/index.html:572`
- `admin/public/index.html:587-589`
- `admin/server.js:115`

What I saw:

- The admin SPA stores `paramant-admin-session` in `localStorage`.
- The admin CSP still allows `'unsafe-inline'` for scripts and styles.

Assessment:

- I did not find a direct XSS in `admin/public/index.html` during this pass.
- This is therefore a residual-risk note, not a confirmed exploit.
- If a same-origin XSS is introduced later, the session token is trivially recoverable from browser storage.

Operational verdict:

- Residual / hypothetical on its own.
- I would not treat this as a present operational finding unless it is paired with a separate XSS or same-origin script-injection bug.

### 10. Low: Installer scripts provision SHA-1 TOTP entries but the relay verifies SHA-256

Affected refs:

- `relay/relay.js:741-749`
- `frontend/install.sh:435-444`
- `frontend/install-pi.sh:363-372`
- `docs/self-hosting.md:543-546`

What I saw:

- The relay's TOTP verifier uses `HMAC-SHA256`: `relay/relay.js:741-749`.
- Both installer scripts print an `otpauth://` provisioning URI that explicitly says `algorithm=SHA1`, and they tell the operator to use SHA-1 when entering the secret manually:
  - `frontend/install.sh:435-444`
  - `frontend/install-pi.sh:363-372`
- The self-hosting documentation correctly says the product expects TOTP-SHA256 and warns that SHA-1 will produce wrong codes: `docs/self-hosting.md:543-546`.

Impact:

- Operators following the installer output can provision an authenticator app with the wrong TOTP algorithm.
- The practical outcome is failed MFA verification and possible self-lockout from the admin panel until the entry is recreated manually with SHA-256.

Operational verdict:

- Real-world operational impact, even though this is not an attacker-driven exploit by itself.
- I am including it because it is a real security-control failure mode in the shipped setup path.

## Notable Non-Findings

- The relay-served built-in `/ct` page escapes the dynamic fields it renders. The registry XSS is in `frontend/ct-log.html`, not in the relay's own `/ct` UI.
- The main browser send path uses the WASM hybrid encryptor with receiver public keys. I did not find the Thunderbird/FileLink raw-key pattern in that path:
  - `frontend/parashare.html:773-778`
- The checked-in Docker/compose baseline is relatively solid:
  - non-root containers
  - `no-new-privileges:true`
  - `cap_drop: ALL`
  - `read_only: true`
  - localhost-only port binds in `docker-compose.yml`
- `frontend/crypto-bridge.js:9-41` verifies the SHA-256 of the checked-in WASM binary before initializing it.
- I reviewed the readable Rust source in `crypto-wasm/src/lib.rs` and did not find an immediate cryptographic misuse that rose to a reportable finding in this pass.

## Imported Code and Verification Gaps

I do not need any more first-party source to support the findings above. I do need more provenance if you want a full imported-code assurance review.

Readable imported/runtime-adjacent code that I reviewed:

- `frontend/crypto-bridge.js`
- `frontend/pkg/paramant_crypto.js`
- `crypto-wasm/src/lib.rs`
- `frontend/noble-mlkem.js`
- `frontend/noble-mlkem-bundle.js`
- `frontend/noble-utils.js`

Artifacts present in the tree but not fully verifiable from the current workspace:

- `frontend/globe.gl.min.js` — minified vendor bundle, 992,755 bytes
- `frontend/vendor/jsQR.min.js` — minified vendor bundle, 130,594 bytes
- `frontend/vendor/qrcode.min.js` — minified vendor bundle, 19,927 bytes
- `frontend/pkg/paramant_crypto_bg.wasm` — compiled WASM binary, 114,261 bytes

Why these remain gaps:

- Minified JavaScript is not a trustworthy substitute for upstream source review.
- The compiled WASM artifact can be inspected behaviorally, but this repository alone does not prove that the checked-in binary was reproducibly built from the checked-in Rust source.

External dependency source not present in this repository:

- Relay runtime deps from `relay/package.json`: `@noble/post-quantum`, `argon2`, `bip39`, `nats`, `ws`
- Admin runtime deps from `admin/package.json`: `express`
- Python SDK deps from `sdk-py/pyproject.toml`: `requests`, `cryptography`, `websockets`

If you want a deeper imported-code review, I need one of the following for each artifact/dependency you want verified:

- exact upstream repository and commit/tag
- unminified source copy
- reproducible build instructions plus expected output hashes

## Dependency Lockfile Check

I also checked the checked-in npm lockfiles against npm's live advisory service using `npm audit --package-lock-only --json` on 2026-04-15.

Audited lockfiles:

- `package-lock.json`
- `relay/package-lock.json`
- `admin/package-lock.json`
- `sdk-js/package-lock.json`

Result:

- No unresolved npm advisory findings were returned for any of the locked dependency trees at audit time.
- Reported totals:
  - root `package-lock.json`: 0 vulnerabilities
  - `relay/package-lock.json`: 0 vulnerabilities
  - `admin/package-lock.json`: 0 vulnerabilities
  - `sdk-js/package-lock.json`: 0 vulnerabilities

Interpretation:

- As of the audit date, npm's advisory database did not flag any of the exact locked package versions in these lockfiles as vulnerable.
- That means I did not find a currently unresolved lockfile-based dependency issue in the npm trees.

Important limits:

- This check covers npm advisory data for the lockfiles above. It does not cover:
  - Python dependencies in `sdk-py/pyproject.toml`
- vendored/minified frontend libraries that are checked into the repository outside npm resolution
- unpublished or not-yet-indexed vulnerabilities
- non-security correctness bugs in dependencies

## Python Dependency Check

I also checked the Python dependency declarations in `sdk-py/pyproject.toml` on 2026-04-15.

Important difference from npm:

- There is no Python lockfile in `sdk-py`.
- That means I cannot verify an exact installed dependency set from the repository alone.
- What I can verify is whether the declared version ranges allow known vulnerable releases.

Declared runtime dependencies:

- `requests>=2.28`
- `cryptography>=41`
- `websockets>=12`

Declared dev dependencies:

- `pytest>=7`
- `pytest-asyncio>=0.21`
- `responses>=0.24`

Method used:

- Queried PyPI's JSON release endpoints for the minimum supported versions implied by the specifiers:
  - `requests` 2.28.0
  - `cryptography` 41.0.0
  - `websockets` 12.0
  - `pytest` 7.0.0
  - `pytest-asyncio` 0.21.0
  - `responses` 0.24.0
- Used the `vulnerabilities` field returned by PyPI for each exact release.

### Python Findings

| Package spec | Checked release | Result | Notes |
| --- | --- | --- | --- |
| `requests>=2.28` | `requests==2.28.0` | Vulnerable | Minimum supported release has multiple advisories; fixed versions include `2.31.0`, `2.32.0`, `2.32.4`, `2.33.0` depending on issue |
| `cryptography>=41` | `cryptography==41.0.0` | Vulnerable | Minimum supported release has multiple advisories; fixes begin at `41.0.2`, `41.0.3`, `41.0.4`, `41.0.6`, `42.0.0`, `42.0.4`, `43.0.1`, `46.0.5`, `46.0.6` depending on issue |
| `websockets>=12` | `websockets==12.0` | No current PyPI advisory listed | No vulnerability listed on PyPI for the exact checked release |
| `pytest>=7` | `pytest==7.0.0` | Vulnerable | PyPI lists `CVE-2025-71176`, fixed in `9.0.3` |
| `pytest-asyncio>=0.21` | `pytest-asyncio==0.21.0` | No current PyPI advisory listed | No vulnerability listed on PyPI for the exact checked release |
| `responses>=0.24` | `responses==0.24.0` | No current PyPI advisory listed | No vulnerability listed on PyPI for the exact checked release |

### Python Assessment

- I did not find an exact locked Python environment to audit.
- I did find that the declared minimum supported versions for `requests`, `cryptography`, and `pytest` are known-vulnerable releases according to PyPI's current vulnerability metadata.
- Therefore the Python dependency specifications are not "clean by construction": they permit vulnerable versions.
- This is weaker evidence than a lockfile finding, because I cannot say the vulnerable versions are what an operator is actually using right now.
- It is still operationally important because anyone resolving the project at or near the lower bounds can land on vulnerable versions unless they upgrade beyond the fixed releases.

### Practical interpretation

- npm side: current checked-in lockfiles came back clean.
- Python side: no lockfile, but the version ranges are permissive enough to include known-vulnerable minimum versions.

If you want exact Python exposure rather than range exposure, I need one of:

- a Python lockfile
- a `requirements.txt` with exact pins
- the output of the environment actually used to build or deploy the SDK

## Bottom Line

The highest-signal issues in the current tree are:

1. A real DOM XSS in the static relay-registry viewer
2. A real confidentiality break in the Thunderbird/FileLink upload path
3. Broken client-IP handling on both sides of the proxy boundary

Those are followed by:

- a real `users.json` persistence race
- a real malformed-path crash path in the relay process
- an abuse-prone public DPA signing path
