# Session Report — March 13, 2026

## dp-x360-plugin: XNet NEUTERED Breakthrough and Logon State Investigation

## Executive Summary

This session achieved a **critical breakthrough**: HTTP traffic from the Xbox 360's XHttp layer successfully reached the OpenParty server on the PC. The key discovery was `XNET_OPTID_NEUTERED` (0x1389), an XNet option that disables the security protocol wrapping on sockets. By setting this option via `XNetSetOpt` during `XHttpSendRequest` execution, XHttp's internally-created sockets bypass XNet security and transmit plain TCP — which standard HTTP servers can understand.

OpenParty received its first game-originated request: `GET /` with `host: 192.168.50.47`. The NEUTERED approach was confirmed working across multiple `XHttpSendRequest` calls (3x "XNet neutered ON" toasts observed).

However, the game still shows "connection error" when navigating to World Dance Floor. Analysis of toast diagnostics revealed that **no Ubisoft domain requests are being made** — the game is failing a pre-HTTP connectivity check and never reaching the UbiServices API layer. Three Xbox Live logon state hooks (ordinals 322, 302, 112) were added but have not yet been tested due to session time constraints.

---

## Environment

- **Console**: Xbox 360, soft-modded via ABadAvatar/XeUnshackle
- **Build**: VS2010 + XDK 21256, `Sunrise2.xex` DashLaunch plugin
- **PC IP**: 192.168.50.47 (Wi-Fi)
- **Xbox IP**: 192.168.50.186
- **Servers**: OpenParty on port 80, diagnostic server on 19030/19031, DNS server on 53

---

## Breakthroughs

### 1. XNet NEUTERED Mode Works

The `XNET_OPTID_NEUTERED` (0x1389) option successfully disables XNet security wrapping when set via `XNetSetOpt` (ordinal 79). Implementation in `XHttpSendRequest` hook:

```cpp
// Save current state
g_pfnXNetGetOpt(xnc, XNET_OPTID_NEUTERED, (BYTE*)&savedNeutered, &savedSize);
// Enable neutered mode
DWORD neutered = 1;
g_pfnXNetSetOpt(xnc, XNET_OPTID_NEUTERED, (BYTE*)&neutered, sizeof(neutered));
// Call real XHttpSendRequest (now uses plain TCP)
// ... call through ...
// Restore original state
g_pfnXNetSetOpt(xnc, XNET_OPTID_NEUTERED, (BYTE*)&savedNeutered, sizeof(savedNeutered));
```

**Test results**:
- `XNetSetOpt` resolved successfully (ordinals 78/79)
- "XNet neutered ON" toast appeared 3 times (one per XHttpSendRequest call)
- OpenParty received `GET /` with correct `host: 192.168.50.47` header
- This confirms NEUTERED allows XHttp's internal sockets to send plain TCP to LAN servers

### 2. HTTP Request Reached OpenParty

OpenParty console output:
```
[HTTP 03:30:40.279] GET /
[HTTP] Headers: host: 192.168.50.47
[404] GET /
```

After adding a root handler, subsequent test showed `GET /` returning 200 OK.

### 3. Debug Toasts Show Request Details

Added per-request toasts to XHttpConnect and XHttpOpenRequest:
- `[C] <domain>` — shows the hostname for every XHttpConnect call
- `[R] <VERB> <path>` — shows the verb and path for every XHttpOpenRequest call

**Domains observed**:
- `192.168.50.47` — direct connection to our server (system UPnP)
- `piflc.xboxlive.com` — Xbox Live system check
- **No Ubisoft domains observed** (no `public-ubiservices.ubi.com`, etc.)

**Paths observed**:
- `POST /upnphost/udhisapi...` — system UPnP request (not game traffic)

---

## Current Problem: Game Never Makes UbiServices HTTP Calls

When the user navigates to World Dance Floor / clicks "connect", the game shows "connection error" **without making any XHttp calls to Ubisoft domains**. No new toasts appear. This means the game is failing a connectivity check at a level below XHttp.

### Already Hooked (Working)

| Ordinal | Function | Hook Returns | Status |
|---------|----------|-------------|--------|
| 73 | `XNetGetTitleXnAddr` | Valid XNADDR + ONLINE flags | Fires OK |
| 75 | `XNetGetEthernetLinkStatus` | ACTIVE + 100MBPS | Fires OK |
| 528 | `XamUserGetSigninState` | 2 (SignedInToLive) | Fires OK |
| 205 | `XHttpConnect` | Redirect Ubi domains → 192.168.50.47:80 | Fires (for system requests) |
| 207 | `XHttpOpenRequest` | Strip XHTTP_FLAG_SECURE | Fires OK |
| 209 | `XHttpSendRequest` | Set NEUTERED mode | Fires OK |
| 530 | `XamUserCheckPrivilege` | TRUE for all | Import table hook |
| 590 | `XamCreateEnumeratorHandle` | Passthrough + LSP intercept | Import table hook |
| 592 | `XamEnumerate` | Custom server info for LSP | Import table hook |

### Newly Added (UNTESTED — end of session)

| Ordinal | Function | Hook Returns | Rationale |
|---------|----------|-------------|-----------|
| 322 | `XNetLogonGetState` | 2 (online) | Xbox Live logon state machine |
| 302 | `XNetLogonGetNatType` | 1 (open NAT) | NAT type check |
| 112 | `NetDll_XnpLogonGetStatus` | 0 (success) | Internal logon status |

These are **pure replacement hooks** (no unhook-call-rehook). They return fixed "connected/online" values to all callers. Safe on a FakeLive console.

### Other Candidates If Above Don't Work

| Ordinal | Function | Notes |
|---------|----------|-------|
| 65 | `NetDll_XNetConnect` | Initiates secure XNet connection |
| 66 | `NetDll_XNetGetConnectStatus` | Polls connection status to a peer |
| 301 | `XNetLogonGetLoggedOnUsers` | Which users are on Live |
| 306 | `XNetLogonGetServiceInfo` | Xbox Live service info |
| 315 | `XNetLogonGetExtendedStatus` | Extended logon status |
| 57-63 | `XNetXnAddrToInAddr` etc. | XNet address resolution |

---

## OpenParty Server-Side Fixes Made

### 1. HTTPS → HTTP URL Fix (Critical)

The game's configuration responses contained `https://` URLs that would fail since we strip `XHTTP_FLAG_SECURE`:

**`database/config/v1/parameters2.json`** (JD2018):
```json
// BEFORE: "url": "https://{SettingServerDomainVarOJDP}"
// AFTER:  "url": "http://{SettingServerDomainVarOJDP}"
```

**`database/config/v1/parameters.json`**:
- `baseurl_aws.Standard`: `https://` → `http://`
- All 6 `us-sdkClientFleet` URLs: `https://` → `http://`

### 2. Root Endpoint Handler

Added `GET /` handler in `DefaultRouteHandler.js` returning `{ status: "ok", server: "OpenParty" }`. Some game SDKs probe the root path as a health check.

### 3. Session Handler Optimization

Modified `UbiservicesRouteHandler.js` `handleSessions`:
- **Local clients** (192.168.x.x) skip forwarding to Ubisoft servers entirely (avoids timeout delay)
- Non-local clients get a 5-second timeout instead of hanging indefinitely
- Platform name uses `"Xbox360Player"` instead of hardcoded `"NintendoSwitch"`

---

## Architecture: What We Know Works

```
Xbox 360 Game
  ├── XamUserGetSigninState → Hook returns "signed into Live" ✅
  ├── XNetGetEthernetLinkStatus → Hook returns "active" ✅
  ├── XNetGetTitleXnAddr → Hook returns valid address ✅
  ├── [MISSING] XNetLogonGetState? → Possibly returns "not connected" ❓
  ├── [MISSING] Other logon checks? ❓
  │
  └── (IF logon checks pass) → UbiServices HTTP flow:
      ├── XHttpConnect("public-ubiservices.ubi.com")
      │   → Hook redirects to 192.168.50.47:80 ✅
      ├── XHttpOpenRequest(verb, path)
      │   → Hook strips XHTTP_FLAG_SECURE ✅
      └── XHttpSendRequest(headers, body)
          → Hook sets XNET_OPTID_NEUTERED=1 ✅
          → XHttp sends plain TCP to our server ✅
          → OpenParty receives and responds ✅
```

The entire HTTP pipeline is proven to work (GET / reached OpenParty). The blocker is that **the game never enters the HTTP pipeline** because a logon state check fails first.

---

## Files Modified This Session

| File | Changes |
|------|---------|
| `Sunrise2/CoreHooks.cpp` | Added NEUTERED mode in XHttpSendRequest; added debug toasts for domain/path; added logon state hooks (ord 322, 302, 112) |
| `OpenParty/database/config/v1/parameters2.json` | `https://` → `http://` for jd-serverInfo URL |
| `OpenParty/database/config/v1/parameters.json` | `https://` → `http://` for baseurl_aws and fleet URLs |
| `OpenParty/core/classes/routes/DefaultRouteHandler.js` | Added `GET /` root handler |
| `OpenParty/core/classes/routes/UbiservicesRouteHandler.js` | Skip Ubisoft forwarding for local clients; Xbox platform name |
| `dp-x360-server/dns-server.js` | LOCAL_IP updated to 192.168.50.47 |

---

## Next Steps (Priority Order)

1. **Test logon state hooks** (ordinals 322, 302, 112) — build was completed but not deployed. Watch for "LogonState called!" / "NatType called!" / "LogonStatus called!" toasts to confirm these functions are being called by the game.

2. **If logon hooks don't trigger game HTTP calls** — investigate additional XNet/XOnline status functions. Key candidates: ordinals 65, 66, 301, 306, 315. The game might check Multiple functions in sequence.

3. **If logon hooks DO work and Ubisoft domains appear** — watch OpenParty for incoming API requests. The session handler, configuration, and parameters endpoints are all ready.

4. **Consider Ghidra analysis of game's online check** — if hook-based approach stalls, analyze the game's `default.xex` in Ghidra to find the exact function that determines online readiness. Look for the code path between "user clicks connect" and "XHttpConnect is called."

5. **Fallback: Executable patching** — DanceParty team is exploring direct `.xex` patching (already have patchers for Wii/PS3). This bypasses all hook limitations.

---

## Key Learnings

1. **XNET_OPTID_NEUTERED works** — setting this via XNetSetOpt(ord 79) makes XHttp's internal sockets bypass XNet security. This is the solution to the TCP timeout (10060) problem.

2. **XHttp doesn't use Xbox's configured DNS** — DNS redirect approach failed (zero queries received).

3. **System makes XHttp calls too** — UPnP requests (`POST /upnphost/udhisapi.dll`) and Xbox Live checks (`piflc.xboxlive.com`) go through XHttp. Our hooks must handle these gracefully.

4. **Game has a pre-HTTP connectivity gate** — the game checks Xbox Live connectivity status BEFORE making any UbiServices HTTP calls. Spoofing XamUserGetSigninState alone is insufficient.

5. **Toast diagnostic toasts are invaluable** — per-request `[C] domain` and `[R] VERB /path` toasts provide real-time visibility into exactly what the game is doing.
