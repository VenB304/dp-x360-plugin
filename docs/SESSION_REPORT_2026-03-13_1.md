# Session Report — March 13, 2026

## dp-x360-plugin: Ghidra Deep Dive, OpenParty Platform Gap, and XEX Patch Planning

## Executive Summary

This session focused on understanding why Just Dance 2018 makes zero UbiServices HTTP calls despite all hooks being installed and confirmed working. Three parallel investigations were conducted: analysis of a developer conversation (yunyl, DanceParty team), two Wireshark captures, and Ghidra reverse engineering of `default.xex`.

The toast sequence confirmed that the five logon/tunnel hooks added last session (ordinals 322, 302, 112, 65, 66) are **installed but never invoked** — the game does not reach the code that calls these functions. Wireshark confirmed JD2018 generates zero network traffic when the user navigates to World Dance Floor. Ghidra revealed the two-stage online flow (UbiServices HTTP login → RDV/Quazal connection), located the UbiServices URL template at `0x822998c8`, and identified a descriptor table of UbiServices endpoint constructors. A critical gap was also found in OpenParty: Xbox 360 (`xenon`) is not a supported platform.

The session concluded with an identified path forward: **XEX patching** the URL template to redirect UbiServices traffic directly to our server, bypassing both DNS and the XHttpConnect domain-matching hook.

---

## Environment

- **Console**: Xbox 360, soft-modded via ABadAvatar/XeUnshackle
- **Build**: VS2010 + XDK 21256, `Sunrise2.xex` DashLaunch plugin
- **PC IP**: 192.168.50.47 (Wi-Fi)
- **Xbox IP**: 192.168.50.48 (changed from .186 — DHCP conflict, see below)
- **Servers**: OpenParty on port 80, diagnostic server on 19030/19031, DNS server on 53

---

## Key Findings

### 1. Logon Hooks Never Fire

The toast sequence from booting with the current build confirmed all hooks install correctly, but the five functions added at the end of the previous session are never called:

| Ordinal | Function | Status |
|---------|----------|--------|
| 322 | `XNetLogonGetState` | Installed, **never called** |
| 302 | `XNetLogonGetNatType` | Installed, **never called** |
| 112 | `XnpLogonGetStatus` | Installed, **never called** |
| 65 | `NetDll_XNetConnect` | Installed, **never called** |
| 66 | `NetDll_XNetGetConnectStatus` | Installed, **never called** |

The only XHttp activity observed was `POST /upnphost/udhisapi.dll` — a system UPnP probe, not game traffic. No Ubisoft domain appeared in any `[C] <domain>` toast.

**Conclusion**: Something gates the game's online flow before it reaches the Quazal `JobGetLSPTunnel` or logon state check code paths. The game never attempts to invoke the functions we have hooked.

---

### 2. Xbox IP Changed — DHCP Conflict

The second Wireshark capture revealed the Xbox's IP address changed from `192.168.50.186` to **`192.168.50.48`**:

- The DHCP server offered `192.168.50.47` (the PC's own IP) to the Xbox
- The Xbox detected the conflict via ARP and sent `DHCP Decline`
- The Xbox was subsequently assigned `192.168.50.48`

This does not break the plugin's URL redirect (which targets the PC server by domain name, not the Xbox's source IP), but OpenParty's local-client detection (`isLocalClient` check on `192.168.x.x`) still considers .48 a local client. Worth noting for future sessions.

---

### 3. JD2018 Makes Zero Network Calls

Both Wireshark captures confirmed that when the user navigates to World Dance Floor:
- **Zero DNS queries** for any Ubisoft domain
- **Zero TCP connections** to any external IP
- **Zero UDP** (no Quazal PRUDP traffic)

The only connection to port 80 on the PC in either capture was `GET / HTTP/1.0` — this is **Aurora** (the homebrew dashboard) doing a local network probe, not JD2018. Aurora also successfully made external HTTP connections to `xboxunity.net:80`, confirming that `XNCALLER_SYSAPP` context sockets can reach the internet freely. JD2018 runs in `XNCALLER_TITLE` context, which is subject to XNet security wrapping.

---

### 4. OpenParty Has No Xbox 360 Platform Support

The OpenParty README lists supported platforms as: PC, Nintendo Switch, PlayStation 4, Xbox One, and Wii U. **Xbox 360 is absent.**

Platform detection throughout OpenParty matches against the `X-SkuId` request header. Xbox 360's platform token is `xenon` (the console's codename). None of the handlers include it:

- `DefaultRouteHandler.handlePackages`: checks `['wiiu', 'nx', 'pc', 'durango', 'orbis']` — `xenon` falls through, **no response sent**
- `SongDBRouteHandler.handleSongdb`: regex `-(pc|durango|orbis|nx|wiiu)` does not match `xenon` — returns `'Invalid Game'`
- `AccountRouteHandler.handleGetProfileSessions`: maps `durango` → `'xboxone'` as the closest Xbox platform but has no `xenon` entry

The only 360-specific handling is in `UbiservicesRouteHandler.handleSessions` where LAN source IPs skip Ubisoft passthrough, and an `xbl`/`console` keyword in the `Authorization` header sets `platformType = "Xbox360Player"` in the fake session. This was added during a previous session.

If and when UbiServices HTTP calls reach OpenParty with a `jd2018-xenon-all` SKU ID, the server would return usable session data but fail entirely on SKU packages and song database requests.

---

### 5. Ghidra Analysis: UbiServices SDK Architecture

A Ghidra memory search for `ubiservices` and `WorldDanceFloor` strings revealed the full online architecture:

#### Online Architecture (Hermes + RDV)

The game's online layer is the **Hermes** middleware, which wraps two SDKs:
1. **UbiServices** (`extern/ubiservices/client-sdk`) — Ubisoft's HTTP REST API SDK, statically linked
2. **RDV** (Rendez-Vous, i.e. Quazal PRUDP) — peer discovery and session networking

The connection sequence, as revealed by debug strings:
```
"Logging in to Ubiservices..."
  → success: "UbiServices, login is success"
             "Already Logged to Ubiservices now trying to connect to RDV!!"
  → failure: "Login to Ubiservices FAILED!!..."
             "UbiServices, login is failed: %s"
```

WorldDanceFloor goes through `Hermes::RDVInterface` (`rdv::WorldDanceFloorProtocolClient`), source path:
```
x:\jd_code\main_legacy\src\online\Hermes\Private\Services\WorldDanceFloor\WorldDanceFloorService.cpp
```

#### UbiServices URL Template

The URL used to build all UbiServices endpoint addresses:

| Address | String |
|---------|--------|
| `0x822998c8` | `https://{env}public-ubiservices.ubi.com/{version}` |
| `0x822998fc` | `/applications/{applicationId}/configuration` |

In production, `{env}` resolves to an empty string, giving the final base URL `https://public-ubiservices.ubi.com`.

`Function_82CB8D28` at `0x82CB8D28` is the endpoint constructor for the `/applications/{applicationId}/configuration` endpoint. It:
1. Calls `Function_82CAAA80` to resolve the URL template (substituting `{env}`)
2. Calls `Function_82CB7ED8` to combine base URL + path
3. Stores the result at `this+0x4C` and sets `this+0x98 = 1`

This function (and 3–4 sibling constructors for other endpoints) is registered in a descriptor table at `0x823b0068` as 8-byte entries: `[4-byte function pointer][4-byte metadata]`.

#### Static Analysis Limitations

- The "Connection error:" string (`0x82295a10`), the login log strings (`0x82286a8a` etc.), and `Function_82CB8D28` all have **no static xrefs** in Ghidra — they are accessed via C++ vtable dispatch or variadic logging, both of which produce indirect calls that Ghidra cannot statically trace.
- Searching for the function address `82CB8D28` as a hex value found one descriptor table entry at `0x823b0068`, confirming the vtable/indirect call hypothesis.

---

## Architecture: Current State

```
Xbox 360 Game (Hermes + UbiServices + RDV)
  ├── XNetGetEthernetLinkStatus (ord 75) → Hook returns ACTIVE ✅
  ├── XNetGetTitleXnAddr (ord 73)        → Hook returns valid addr ✅
  ├── XamUserGetSigninState (ord 528)    → Hook returns SignedInToLive ✅
  ├── XamUserCheckPrivilege (ord 530)    → Hook returns TRUE ✅
  │
  ├── [GATE — UNKNOWN] Something fails here before logon/HTTP ❌
  │   Hooks 322, 302, 112, 65, 66 never fired — gate is upstream of them
  │
  └── (IF gate passes) → Hermes::RDVInterface login sequence:
      ├── UbiServices HTTP Login (via internal SDK HTTP client)
      │   └── URL: https://{env}public-ubiservices.ubi.com/{version}/...
      │       → Currently unreachable (HTTPS + XNet security blocks it)
      │       → XEX patch target: 0x822998c8
      ├── On success → RDV (Quazal PRUDP) connection
      └── On success → WorldDanceFloorService active
```

---

## yunyl (DanceParty) Conversation Summary

Key points from developer discussion:

1. **XEX patching is viable**: yunyl confirmed the method — decrypt with `xextool`, replace URL string in-place (same length), re-encrypt. A version mismatch issue was previously encountered when patching only `default.xex` without also patching the update package.

2. **XLSP chicken-and-egg**: The XLSP string `"UBILSP1"` (Xbox Live Lobby Server identifier) is returned by UbiServices' entities endpoint. Without connecting to UbiServices, the game never receives it, and without it the LSP address cannot be resolved. This is why DanceParty's working Harbour servers (UbiServices + PRUDP) never received a connection from Xbox 360 either.

3. **yunyl's hybrid proposal**: Patch the XEX to point to a custom UbiServices server → game retrieves the XLSP string from our server → plugin's `XamEnumerate` hook intercepts LSP resolution and provides our server's address → PRUDP connection follows.

---

## Next Steps (Priority Order)

1. **XEX Patch Test** — Patch the URL template at `0x822998c8` from:
   ```
   https://{env}public-ubiservices.ubi.com/{version}
   ```
   to (same 46-character length, HTTP, our server IP):
   ```
   http://192.168.50.047/{version}/////////////
   ```
   Using `xextool` to decrypt, hex edit, and re-encrypt. Also patch the update XEX.
   - **If our server receives a hit** on `/v?/applications/.../configuration` or `/v3/profiles/sessions` → the UbiServices SDK was always running, just routing to the wrong host. The gate is not blocking it.
   - **If no hit** → the gate prevents the SDK from running entirely. Requires deeper investigation.

2. **Add `xenon` Platform Support to OpenParty** — Regardless of when UbiServices calls arrive, they will fail when the game requests SKU packages or song DB with a `jd2018-xenon-all` SKU ID. Add `xenon` to:
   - `DefaultRouteHandler.handlePackages` platform list
   - `SongDBRouteHandler` platform regex
   - `AccountRouteHandler` platform type mapping
   - Add `database/Platforms/jd2018-xenon/sku-packages.json` (copy from `jd2017-durango` as baseline)

3. **Identify the Unknown Gate** — If the XEX patch still produces no traffic, add hooks for the remaining candidate ordinals (301, 306, 315) and consider a broader sweep of all XAM networking exports in the `0x100–0x400` ordinal range to find which function the game IS calling that returns "not connected."

4. **Plan for RDV (Quazal PRUDP) Server** — Once UbiServices login succeeds, `Hermes::RDVInterface` will attempt a Quazal PRUDP connection. OpenParty does not implement a PRUDP server. This will need to be addressed in a future session (likely requires a basic NEX/Quazal handshake handler or a stub that returns a valid session response).

---

## Files Modified This Session

None — this was an analysis-only session (Wireshark, toast diagnostics, Ghidra reverse engineering).

---

## Key Learnings

1. **Logon hooks are not the gate** — ordinals 322, 302, 112, 65, 66 are installed but the game never calls them. The blocking condition is upstream.

2. **JD2018 generates zero network I/O from TITLE context** — confirmed by two Wireshark captures. The only port-80 hit was from Aurora (sysapp context), not the game.

3. **Aurora proves sysapp sockets work** — Aurora made successful external HTTP connections to `149.56.47.64:80`. The XNet security restriction applies specifically to TITLE-context sockets.

4. **UbiServices SDK is statically linked into the XEX** — it is not a separate DLL, meaning its HTTP client and URL table can be patched directly in the XEX binary.

5. **XEX patching is the cleanest path** — changing the URL template at `0x822998c8` bypasses DNS, bypasses the XHttpConnect domain-matching hook, and converts HTTPS to HTTP in one edit. This is the recommended next action.

6. **OpenParty xenon gap** — even if HTTP calls arrive, OpenParty will serve broken responses for SKU packages and song DB until `xenon` platform support is added.
