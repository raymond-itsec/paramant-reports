# Security Findings Report

**Date:** 2026-04-10  
**Prepared by:** R. Zwarts  
**Function:** Independant Security Researcher

**Classification:** Reported to author only. (Responsible disclosure on 10-04-2026)

## Summary

This report documents review findings identified in the JavaScript codebase for the PARAMANT relay platform. The review focused exclusively on issues with the potential to cause incorrect behavior, security exposure, delivery failures, or meaningful operational impact.

The most significant risks identified are:

- broken secure WebSocket proxying in the edge gateway
- a message streaming path that returns identifiers that do not map to stored blobs
- webhook SSRF protection that can be bypassed through DNS-based resolution attacks

These issues affect core reliability and security boundaries and should be prioritized for remediation.

---

## Findings

### 1. WebSocket proxy to HTTPS upstreams is not using TLS

**Severity:** High  
**Location:** `/Coding/paramant-relay/fly-relay/relay.js:98`  
**Location:** `/Coding/paramant-relay/fly-relay/relay.js:156`

**Issue**  
The WebSocket proxy connects to HTTPS upstream relays using plain TCP via `net.createConnection()` rather than establishing a TLS session.

**Why it matters**  
The configured upstream relays use `https://` endpoints on port `443`, which expect a TLS handshake before any HTTP upgrade request is sent. Because the current implementation writes raw HTTP directly to the socket, WebSocket upgrades through the edge gateway will fail or behave unpredictably. Any production feature depending on upgraded connections can therefore break.

**Concrete fix**  
Replace the upstream socket with a TLS-capable connection such as `tls.connect()`, or move this path to a reverse proxy implementation that explicitly supports secure WebSocket forwarding to HTTPS origins. The proxy should only send the upgrade request after the TLS session is established successfully.

---

### 2. Streaming endpoint returns synthetic identifiers instead of real blob hashes

**Severity:** High  
**Location:** `/Coding/paramant-relay/relay/relay.js:1263`  
**Location:** `/Coding/paramant-relay/sdk-js/src/index.js:370`

**Issue**  
The `/v2/stream-next` endpoint returns an HMAC-derived value based on `device` and `seq`, while stored blobs are indexed by `sha256(blob)`. The SDK then attempts to pass that returned value into `receive()` as though it were a real blob hash.

**Why it matters**  
This breaks the message consumption flow. Polling clients using `listen()` are not receiving stable identifiers that correspond to actual stored blobs, so they cannot reliably fetch pending messages. In practice this can lead to missed deliveries, repeated failed receives, and a broken stream/polling experience.

**Concrete fix**  
Maintain a per-device delivery queue when `/v2/inbound` stores a blob, and enqueue the actual stored blob hash for the intended recipient device. Update `/v2/stream-next` so it returns the next queued real blob hash instead of synthesizing one from device and sequence.

---

### 3. Webhook SSRF protection does not validate resolved IP addresses

**Severity:** High  
**Location:** `/Coding/paramant-relay/relay/relay.js:584`  
**Location:** `/Coding/paramant-relay/relay/relay.js:607`

**Issue**  
The webhook SSRF guard validates only the URL text and hostname pattern. It does not resolve DNS before opening the outbound connection.

**Why it matters**  
An attacker can register a hostname that appears public but resolves to loopback, RFC1918, link-local, or metadata-service addresses. That would allow the relay to make server-side requests into internal infrastructure despite the existing blacklist logic. This creates a real SSRF risk in the relay environment.

**Concrete fix**  
Resolve the hostname before each outbound webhook request and reject targets whose resolved IPs fall into loopback, private, link-local, multicast, or otherwise non-public ranges. If redirects are supported, resolve and validate each redirect target before following it.

---

### 4. SDK relay detection still uses a query-string API key that the relay rejects

**Severity:** Medium  
**Location:** `/Coding/paramant-relay/sdk-js/src/index.js:108`  
**Location:** `/Coding/paramant-relay/relay/relay.js:677`

**Issue**  
The SDK relay auto-detection logic sends the API key as `?k=...`, but the relay now rejects requests containing `query.k` before routing.

**Why it matters**  
Relay auto-detection can no longer validate candidate relays correctly, even when the key is valid. The current fallback then selects any reachable relay, which can hide the actual authentication problem and route the client to the wrong sector. This results in incorrect behavior and makes diagnosis more difficult.

**Concrete fix**  
Update `detectRelay()` to call `/v2/check-key` with the API key in the `X-Api-Key` header instead of the query string. The fallback behavior should also be tightened so a failed validation does not silently degrade into choosing an arbitrary healthy relay.

---

### 5. Admin login flow advertises enterprise key support that the relay does not honor

**Severity:** Medium  
**Location:** `/Coding/paramant-relay/admin/server.js:102`  
**Location:** `/Coding/paramant-relay/relay/relay.js:996`  
**Location:** `/Coding/paramant-relay/relay/relay.js:1368`

**Issue**  
The admin server indicates that an enterprise `pgp_` key can be used to authenticate, but the relay-side MFA and admin endpoints only accept `ADMIN_TOKEN`.

**Why it matters**  
This creates a broken authentication flow. Enterprise users are told they can log in, but relay-side authorization prevents that path from succeeding end-to-end. The result is a real operational failure for administrative access.

**Concrete fix**  
Choose one authorization model and enforce it consistently. Either remove `pgp_` admin login support from the admin server and require `ADMIN_TOKEN` only, or extend the relay admin endpoints to explicitly authorize a scoped enterprise admin key.

---

### 6. One-time download links burn files before transfer completion

**Severity:** Medium  
**Location:** `/Coding/paramant-relay/relay/relay.js:810`

**Issue**  
Download tokens are marked as used and the corresponding blob is removed before the file transfer has actually completed.

**Why it matters**  
If the client disconnects mid-transfer, the connection resets, or an intermediary fails after headers are sent, the file is still permanently burned. That turns transient network issues into irreversible data loss for one-time downloads.

**Concrete fix**  
Introduce an in-progress state and delay destructive deletion until the response completes successfully. If the transfer aborts, clear the in-progress state and allow a retry. If burn-on-first-access semantics must remain strict, require a positive completion acknowledgement before deleting the blob.
