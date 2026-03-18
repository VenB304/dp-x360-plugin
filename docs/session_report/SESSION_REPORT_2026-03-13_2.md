# Session Report — March 13, 2026

## dp-x360-plugin: piflc Redirect Confirmed, XEAS Auth Failure Identified

## Executive Summary

This session continued from the previous XEX-patch session. The known blocker was `piflc.xboxlive.com` — the Xbox Live XSTS token caching proxy called by xam.xex before the UbiServices SDK runs. The session goals were to make the piflc redirect work and observe whatever came next.

Key outcomes: The XHttpConnect hook successfully intercepts piflc connections (confirmed by OpenParty receiving `POST /vortex/logbinary.ashx`). Decoding the binary XON/2 body revealed a `LogonFail_As` telemetry event — meaning Xbox Live authentication via XEAS already failed before we see anything in HTTP. XEAS uses a binary (non-HTTP) protocol, so it cannot be intercepted at the Node.js server level. The root cause is now identified: **XEAS authentication fails, xam.xex never issues an XSTS token, and the UbiServices SDK never makes HTTP calls because it has no token to include.**

---

## Environment

- **Console**: Xbox 360, soft-modded via ABadAvatar/XeUnshackle
- **Build**: VS2010 + XDK 21256, `Sunrise2.xex` DashLaunch plugin
- **PC IP**: 192.168.50.47 (Wi-Fi)
- **Xbox IP**: 192.168.50.49 (DHCP)
- **Servers**: OpenParty on port 80, DNS server on port 53

---

## Key Findings

### 1. piflc Never Appears in DNS — Caught by XHttpConnect Hook

`piflc.xboxlive.com` was confirmed to **never appear in DNS queries**. xam.xex uses a hardcoded or cached IP address for piflc, bypassing the DNS layer entirely.

However, the XHttpConnect hook in `CoreHooks.cpp` intercepts connections by domain name string (not DNS), so it still catches piflc:

```
Toast: [C] piflc.xboxlive.com
Toast: http redirected
```

This confirmed the redirect path is: XHttpConnect hook intercepts by domain → strips HTTPS → rewrites port to 80 → connection lands on OpenParty as plain HTTP.

---

### 2. XEAS and XETGS Added as Redirect Targets

The DNS log showed two new Xbox Live auth services appearing regularly:

| Domain | Service | Behavior |
|--------|---------|----------|
| `XEAS.XBOXLIVE.COM` | Xbox Entertainment Auth Service | Polls every ~60s for background auth |
| `XETGS.XBOXLIVE.COM` | Xbox Entertainment Token Generation Service | Issues XSTS service tokens for titles |

Both were added to:
- `Sunrise2/CoreHooks.cpp` → `REDIRECT_DOMAINS[]`
- `dp-x360-server/dns-server.js` → `REDIRECT_DOMAINS`

DNS redirect of XEAS/XETGS was confirmed in the DNS server log:
```
[DNS] REDIRECT XEAS.XBOXLIVE.COM -> 192.168.50.47 (from 192.168.50.49)
[DNS] REDIRECT XEAS.XBOXLIVE.COM -> 192.168.50.47 (from 192.168.50.49)
```

However, despite DNS redirect, XEAS/XETGS **never appear in OpenParty's HTTP log**. This is because they use a **binary protocol over TCP, not HTTP**. Node.js's HTTP parser silently drops non-HTTP connections without logging.

---

### 3. POST /vortex/logbinary.ashx — piflc Telemetry Stub

Once piflc redirect was confirmed active, OpenParty began receiving:

```
[HTTP] POST /vortex/logbinary.ashx
user-agent: Xbox Live Client/2.0.17559.0
content-type: xon/2
x-iflcdigest: 556FAA...
content-length: 359
```

The `x-iflcdigest` header (Identity Federation Layer Cache Digest) confirms this originates from the piflc subsystem.

Express's `express.json()` middleware silently skips `xon/2` content type bodies, leaving `req.body` as `{}`. A dedicated stub was added to `DefaultRouteHandler.js` using `express.raw({ type: '*/*' })` as inline route middleware to capture the binary:

```js
app.post('/vortex/logbinary.ashx', express.raw({ type: '*/*' }), (req, res) => {
    if (Buffer.isBuffer(req.body) && req.body.length > 0) {
        console.log(`[XBLIVE] /vortex body (${req.body.length} bytes): ${req.body.toString('hex').substring(0, 400)}`);
    }
    res.sendStatus(200);
});
```

This stub returns HTTP 200 to satisfy piflc.

---

### 4. XON/2 Body Decoded — LogonFail_As

The captured vortex body (359 bytes, hex `015cae22de9eb2dc01100adc...`) was decoded. XON/2 is Xbox Live's binary object notation format. The decoded content included:

| Field | Value |
|-------|-------|
| Event name | `LogonFail_As` |
| Locale | `zz-US` |
| Display | `1920x1080p W HDMI` |

`LogonFail_As` is a telemetry event reporting that the XEAS authentication attempt **already failed**. This vortex POST is the console reporting the failure, not initiating any new request.

**Critical implication**: Returning HTTP 200 for `/vortex/logbinary.ashx` does not trigger any follow-up action. The auth chain is already dead by the time this telemetry fires.

---

### 5. Root Cause Identified: XEAS Binary Auth Failure

The full chain is now understood:

```
xam.xex: XUserGetTokenAndSignature called
  └── xam calls XEAS (Xbox Entertainment Auth Service)
        └── XEAS: binary TCP protocol, not HTTP
              └── DNS redirected to .47, but no XEAS server stub exists
                    └── TCP connect succeeds, binary handshake fails
                          └── XEAS returns auth failure
                                └── xam.xex: no XSTS token issued
                                      └── UbiServices SDK: token required → HTTP calls never made
                                            └── piflc: logs LogonFail_As telemetry to /vortex
```

The UbiServices SDK (patched via XEX to target `192.168.50.47`) is ready and waiting for an XSTS token from xam.xex. It never receives one because XEAS fails at the binary protocol level.

---

### 6. bNeuteredToastShown One-Shot Flag

The `[DIAG] XNet neutered ON` toast was firing on **every** `XHttpSendRequest` call. With XEAS polling every ~60 seconds in the background, this was flooding the toast queue and obscuring diagnostic information.

A one-shot guard was added:

```cpp
static BOOL bNeuteredToastShown = FALSE;
// ...
if (setResult == 0) {
    didSetNeutered = TRUE;
    if (!bNeuteredToastShown) {
        XNotify(L"[DIAG] XNet neutered ON");
        bNeuteredToastShown = TRUE;
    }
}
```

Reset added to `TeardownNetDllHooks`:
```cpp
bNeuteredToastShown = FALSE;
```

---

## Architecture: Current State

```
xam.xex (Xbox System)
  ├── XUserGetTokenAndSignature (XAM export)
  │   └── Calls XEAS for XSTS token
  │       └── XEAS: binary protocol → DNS redirected → no stub → AUTH FAILS ❌
  │           └── No XSTS token issued
  │
  └── UbiServices SDK (patched XEX, targets 192.168.50.47)
      └── SDK requires XSTS token before HTTP calls
          └── NEVER RUNS (blocked by missing token) ❌

piflc.xboxlive.com:
  └── XHttpConnect hook intercepts ✅
  └── POST /vortex/logbinary.ashx hits OpenParty ✅
  └── Body: LogonFail_As (XEAS failure telemetry) — aftermath, not cause
```

---

## Next Steps (Priority Order)

1. **Hook XUserGetTokenAndSignature** — This XAM function is what the UbiServices SDK calls to get an XSTS token. Using `PatchModuleImport` on its ordinal, the hook can return a fake (but valid-looking) token structure directly, bypassing the entire XEAS/piflc chain.
   - First step: find the ordinal number for `XUserGetTokenAndSignature` in xam.xex's export table (Ghidra or xbsdb lookup)
   - Return a fake token with the fields UbiServices actually checks (likely just a userid + token string)

2. **XEAS Stub (binary protocol)** — As an alternative or complement to hooking `XUserGetTokenAndSignature`, a stub TCP server on port 443 that speaks enough of the XEAS protocol to return a success response would allow xam.xex to issue a real XSTS token. Requires protocol analysis (no public docs).

3. **Rebuild Sunrise2.xex** — The XEAS/XETGS redirect changes and the neutered toast one-shot require a rebuild and redeploy before they take effect on the console.

---

## Files Modified This Session

| File | Change |
|------|--------|
| `Sunrise2/CoreHooks.cpp` | Added `xeas.xboxlive.com` and `xetgs.xboxlive.com` to `REDIRECT_DOMAINS[]`; added `bNeuteredToastShown` one-shot guard around XNet neutered toast; reset flag in `TeardownNetDllHooks` |
| `dp-x360-server/dns-server.js` | Added `piflc.xboxlive.com`, `xeas.xboxlive.com`, `xetgs.xboxlive.com` to `REDIRECT_DOMAINS` |
| `OpenParty/core/classes/Core.js` | Added POST/PUT body logging in `configure404Handler` |
| `OpenParty/core/classes/routes/DefaultRouteHandler.js` | Added `const express = require('express')`; added `POST /vortex/logbinary.ashx` stub with `express.raw({ type: '*/*' })` inline middleware |

---

## Key Learnings

1. **piflc uses hardcoded IP, not DNS** — The XHttpConnect domain-name hook is the only intercept point; DNS redirect alone would not work for piflc.

2. **XEAS uses a binary protocol, not HTTP** — DNS redirect puts XEAS connections on our server, but Node.js HTTP parser drops non-HTTP data silently. XEAS cannot be stubbed at the HTTP level.

3. **vortex/logbinary.ashx is consequence, not cause** — The `LogonFail_As` telemetry body confirms XEAS already failed before this call. Returning 200 has no effect on the auth chain.

4. **The actual gate is XUserGetTokenAndSignature** — The UbiServices SDK requires an XSTS token from xam before making any HTTP calls. Hooking this function to return a fake token is the most direct fix.

5. **express.raw() must be inline route middleware** — Placing `express.raw()` globally after `express.json()` would not help because JSON middleware runs first. It must be passed as a route-level middleware argument before the handler function for the specific binary endpoint.
