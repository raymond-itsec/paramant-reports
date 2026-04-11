# Security Findings Report

**Date:** 2026-04-11  
**Prepared by:** R. Zwarts
**Function:** Verification review / code audit
**Classification:** Responible disclosed on April 11th 2026

## Summary

This report documents findings confirmed by direct inspection of the current JavaScript codebase for the PARAMANT relay platform on 2026-04-11. The review focused on issues with a realistic chance of causing security exposure, broken authentication, delivery failures, operational instability, or meaningful performance degradation.

The most significant risks identified are:

- relay-side and admin-side `ADMIN_TOKEN` checks still bypass constant-time comparison on multiple paths, with the primary admin login path also lacking rate limiting
- two issues already reported on 2026-04-10 remain present: inconsistent enterprise admin login support and one-time download links burning blobs before transfer completion
- operational limits remain weak around blocking disk I/O, unbounded registry growth, and synchronous CT logging

Two findings in this report were already reported in the earlier 2026-04-10 report and are called out explicitly below.

---

## Findings

### 1. Admin login uses plain `ADMIN_TOKEN` comparison and has no request throttling

**Severity:** High  
**Status:** Confirmed  
**Earlier reported:** No  
**Location:** `admin/server.js:80-93`

**Issue**  
The admin login route compares the submitted token with `ADMIN_TOKEN` using plain `===` at line 84. The same route also has no rate limiting, no exponential backoff, and no lockout behavior before issuing a relay-side MFA verification request.

**Why it matters**  
This is the primary authentication path for the admin panel. The lack of constant-time comparison is a correctness gap in a security-sensitive check, and the lack of throttling makes brute-force or repeated probing materially easier than it should be.

**Concrete fix**  
Use `crypto.timingSafeEqual()` through a shared helper for the master token comparison, and add route-level throttling on `POST /auth/login` with a small burst limit plus backoff. Because this app normally sits behind nginx, make the limiter proxy-aware so it keys on the real client IP rather than rate-limiting the reverse proxy address.

---

### 2. Relay-side `ADMIN_TOKEN` checks still bypass the existing constant-time helper

**Severity:** Medium  
**Status:** Confirmed  
**Earlier reported:** No  
**Location:** `relay/relay.js:949-951`  
**Location:** `relay/relay.js:980-984`  
**Location:** `relay/relay.js:1216-1219`

**Issue**  
The relay defines a `safeEqual()` helper at `relay/relay.js:840-852`, but three code paths still compare `ADMIN_TOKEN` with plain string equality: `GET /health`, `GET /metrics`, and `POST /v2/reload-users`.

**Why it matters**  
Security-sensitive token checks should be implemented consistently. Leaving a hardened helper unused on adjacent paths increases the chance of subtle auth behavior differences and leaves multiple places that should be normalized to the same comparison model.

**Concrete fix**  
Replace the plain equality checks on all relay-side admin-token paths with the existing `safeEqual()` helper so every privileged comparison uses the same constant-time behavior.

---

### 3. Admin login still advertises enterprise `pgp_` support that the relay does not honor

**Severity:** Medium  
**Status:** Confirmed  
**Earlier reported:** Yes — `findings-report-2026-04-10.md`, Finding 5  
**Location:** `admin/server.js:84-88`  
**Location:** `relay/relay.js:1341-1347`

**Issue**  
The admin server still treats a `pgp_` token as an acceptable login credential, but the relay-side `/v2/admin/*` routes still require a matching `ADMIN_TOKEN` and reject all other credentials.

**Why it matters**  
This creates a broken end-to-end admin flow. The UI and server-side login logic tell the operator one credential type is valid, while the downstream relay authorization layer rejects it.

**Concrete fix**  
Choose a single admin authorization model and apply it consistently. Either remove enterprise-key login support from the admin server or extend relay-side admin authorization to explicitly support a scoped enterprise admin credential.

---

### 4. One-time download links still burn blobs before transfer completion

**Severity:** Medium  
**Status:** Confirmed  
**Earlier reported:** Yes — `findings-report-2026-04-10.md`, Finding 6  
**Location:** `relay/relay.js:1137-1147`

**Issue**  
The download-token handler still marks a token as used and removes the blob from memory before the response body has actually been delivered successfully.

**Why it matters**  
A dropped client connection, proxy reset, or mid-transfer failure can still destroy the only remaining copy of the blob even though the recipient never completed the download.

**Concrete fix**  
Track an `in_progress` state as soon as the transfer starts so a second request cannot race the same token, but defer blob deletion until the response finishes cleanly. If the socket closes early or the transfer errors, clear the in-progress state and keep the blob available for one retry.

---

### 5. TOTP verification remains timing-sensitive and allows code reuse inside the accepted window

**Severity:** Medium  
**Status:** Partially confirmed  
**Earlier reported:** No  
**Location:** `relay/relay.js:435-442`

**Issue**  
`verifyTotp()` loops across the accepted time windows and returns immediately on the first match. It also compares the generated code with the submitted token using plain string equality, and it does not track already-used codes within the valid time window.

**Why it matters**  
This is weaker than a constant-time, full-window verification routine with replay prevention. The code path is security-sensitive, even if the most aggressive timing-attack narrative is stronger than what static inspection alone proves.

**Concrete fix**  
Always evaluate the full TOTP window and compare codes with a timing-safe helper. If replay prevention is added, bind it to a login challenge or session attempt rather than globally blacklisting every accepted 6-digit code for the whole time window, otherwise legitimate parallel logins or retries can be broken.

---

### 6. Admin key create and revoke paths perform blocking synchronous file I/O

**Severity:** Medium  
**Status:** Confirmed  
**Earlier reported:** No  
**Location:** `relay/relay.js:1747-1752`  
**Location:** `relay/relay.js:1778-1784`

**Issue**  
The admin key creation and revocation handlers still call `readFileSync()` and `writeFileSync()` directly on the live request path while persisting `users.json`.

**Why it matters**  
Node.js executes this synchronously on the event loop. Under slower storage or I/O pressure, unrelated requests can stall while admin key operations are writing to disk.

**Concrete fix**  
Replace the synchronous persistence path with a serialized async write queue or dedicated persistence worker. A naive `readFile` / `await` / `writeFile` conversion without serialization would introduce a real lost-update race that the current synchronous code does not have.

---

### 7. Relay registry growth is unbounded and the public listing is unpaginated

**Severity:** Medium  
**Status:** Confirmed  
**Earlier reported:** No  
**Location:** `relay/relay.js:1051-1071`

**Issue**  
`relayRegistry` has no entry cap or eviction policy, and `GET /v2/relays` serializes the full registry into one response with no pagination or limit controls.

**Why it matters**  
This creates a straightforward memory-growth and response-size problem. A public-facing registry should not allow unlimited in-memory accumulation followed by full serialization in one request.

**Concrete fix**  
Add pagination with explicit `limit` and `offset` parameters while preserving the current `relays` response shape for existing consumers. If a memory cap is introduced, make it configurable and tie eviction to an explicit freshness policy so active relays are not hidden accidentally.

---

### 8. CT logging still performs synchronous hot-path writes and the file can grow without rotation

**Severity:** Medium  
**Status:** Confirmed  
**Earlier reported:** No  
**Location:** `relay/relay.js:166-179`  
**Location:** `relay/relay.js:318`  
**Location:** `relay/relay.js:346`

**Issue**  
When `CT_FILE` is enabled, relay and pubkey CT entries are appended with `fs.appendFileSync()` on live request paths, and the backing file is only appended to. There is no size cap or rotation behavior.

**Why it matters**  
This combines two operational risks: synchronous disk writes increase request latency under load, and long-lived deployments can grow the CT file indefinitely until disk pressure becomes a production issue.

**Concrete fix**  
Move CT persistence to a single async write stream or queue that preserves append order and the current NDJSON format, then rotate the file once it exceeds a configured size threshold. Flush or drain the queue on shutdown so persisted CT history stays consistent with startup reload expectations.

---

### 9. DID lookups still perform unnecessary linear scans

**Severity:** Low  
**Status:** Confirmed  
**Earlier reported:** No  
**Location:** `relay/relay.js:854-856`  
**Location:** `relay/relay.js:1075-1078`

**Issue**  
The code scans `didRegistry.values()` to find an entry by `doc.id` even though the registry is already keyed by the DID value itself.

**Why it matters**  
This adds avoidable `O(n)` work to both DID-auth and public DID-resolution paths. The cost is modest at low volume but grows linearly with registry size for no real benefit.

**Concrete fix**  
Use `didRegistry.get(did)` directly, or maintain a secondary index only if the data model truly requires more than one key.

---

### 10. Admin login error responses disclose internal relay addressing

**Severity:** Low  
**Status:** Confirmed  
**Earlier reported:** No  
**Location:** `admin/server.js:93`

**Issue**  
The unauthenticated login route returns `Relay unreachable: ${e.message}` on upstream failure. In practice, Node request errors often include internal hostnames, IPs, or ports.

**Why it matters**  
This leaks internal service topology to any caller who can reach the admin endpoint and trigger a relay connectivity failure.

**Concrete fix**  
Return a generic failure such as `Relay unreachable` and log the detailed upstream error only on the server side.

---

### 11. Webhook SSRF validation still does not restrict destination ports

**Severity:** Medium  
**Status:** Confirmed  
**Earlier reported:** No — the earlier 2026-04-10 report covered a different SSRF gap that now appears addressed  
**Location:** `relay/relay.js:768-795`

**Issue**  
`isSsrfSafeUrl()` validates the scheme and host but does not restrict `u.port`, so public HTTPS URLs on unusual ports still pass validation.

**Why it matters**  
This broadens the outbound connection surface more than necessary and leaves room for scanning or probing behavior against HTTPS services running on non-standard ports.

**Concrete fix**  
Restrict allowed ports to a configurable allowlist such as `443` plus any intentionally supported alternates. Do not hardcode a single port unless the product explicitly guarantees that webhook targets will only use that port.

---

### 12. Revoked API keys do not terminate existing WebSocket subscribers

**Severity:** Low  
**Status:** Confirmed  
**Earlier reported:** No  
**Location:** `relay/relay.js:1777`  
**Location:** `relay/relay.js:2037-2049`

**Issue**  
Key revocation flips the in-memory `active` flag, but existing WebSocket connections associated with that key remain open and continue receiving `blob_ready` events until they disconnect naturally.

**Why it matters**  
Revocation does not take full effect immediately for connected clients, which weakens operator expectations around cutting off access.

**Concrete fix**  
On key revocation, look up any active WebSocket clients for that key and close them with an authorization-related close code.

---

### 13. Admin key creation accepts arbitrary plan strings without validation

**Severity:** Low  
**Status:** Confirmed  
**Earlier reported:** No  
**Location:** `relay/relay.js:1741-1746`  
**Location:** `relay/relay.js:1853-1856`

**Issue**  
The admin key creation route stores `d.plan` as-is with no allowlist validation.

**Why it matters**  
Unexpected plan values can produce inconsistent behavior later. The risk is not purely hypothetical: downstream checks sometimes rely on exact string matches, such as the `kd.plan === 'dev'` gate in the team-device path.

**Concrete fix**  
Normalize incoming plan values to a canonical set before enforcing an allowlist. That compatibility layer should account for values already emitted elsewhere in the codebase, including `dev`, `community`, and any legacy admin UI values, otherwise current admin clients or existing `users.json` entries may break.

---

### 14. Invalid Base32 characters in `TOTP_SECRET` are silently accepted

**Severity:** Low  
**Status:** Confirmed  
**Earlier reported:** No  
**Location:** `relay/relay.js:412-421`

**Issue**  
`base32Decode()` does not reject invalid characters. `alpha.indexOf(c)` can return `-1`, which is then fed into bit operations instead of triggering a configuration error.

**Why it matters**  
A malformed TOTP secret can fail in a non-obvious way and leave operators diagnosing broken MFA behavior without a clear startup or runtime error.

**Concrete fix**  
Reject invalid Base32 input explicitly and surface a clear operator-facing error when `TOTP_SECRET` is malformed. The safest implementation is startup-time validation or a one-time cached validation path, rather than silently coercing bad input during live MFA checks.
