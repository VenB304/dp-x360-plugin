# Session Report — March 11, 2026

## Objective
Redirect Just Dance 2018 (Xbox 360, soft-modded via ABadAvatar) network traffic from Ubisoft servers to a local OpenParty server at `192.168.50.228:80`.

## Environment
- Console: Xbox 360, soft-modded via ABadAvatar/XeUnshackle (NOT RGH/JTAG)
- Build: VS2010 + XDK 21256, `Sunrise2.xex` DashLaunch plugin (`<sysdll/>`)
- Build command: `& "C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe" "c:\Github\dp-x360-plugin\Sunrise2.sln" "/p:Configuration=Release21256.0" "/p:Platform=Xbox 360"`
- OpenParty: `isPublic: true` (binds `0.0.0.0:80`), confirmed accessible

## What Works
- Plugin loads successfully (`Sunrise2 Loaded!` and `DanceParty Enabled!` toasts fire)
- `SetupNetDllHooks()` runs to completion
- All `ResolveFunction` calls succeed (ordinals 73, 75, 205, 528 all resolve)
- **PatchInJump hooks that fire at runtime:**
  - `XNetGetTitleXnAddr` (ordinal 73) — returns fake XNADDR with 192.168.50.100
  - `XNetGetEthernetLinkStatus` (ordinal 75) — returns ACTIVE|100MBPS|FULL_DUPLEX
  - `XamUserGetSigninState` (ordinal 528) — returns "Signed In To Live" for user 0
- `XHttpConnect` hook (ordinal 205) fires when pressing Xbox Guide button (xam-internal HTTP)

## What Doesn't Work
- Game still shows "Ubisoft server unavailable" connection error
- `HTTP Redirected!` toast never appears — the game's Ubisoft connections don't go through `XHttpConnect`
- `DNS Redirected!` never appeared in earlier builds — game doesn't use `XNetDnsLookup` either

## Hooks That Never Fire
| Hook | Method | Ordinal | Analysis |
|------|--------|---------|----------|
| `NetDll_connectHook` | PatchModuleImport | 12 | Game doesn't directly import `connect` |
| `NetDll_sendtoHook` | PatchModuleImport | 24 | Game doesn't directly import `sendto` |
| `NetDll_WSASendToHook` | PatchModuleImport | 25 | Game doesn't directly import `WSASendTo` |
| `XamUserCheckPrivilegeHook` | PatchModuleImport | 530 | Never called by game |
| `XamCreateEnumeratorHandleHook` | PatchModuleImport | 590 | Never called by game |
| `XNetDnsLookupHook` | PatchInJump (removed) | 67 | Game doesn't use XNetDnsLookup for DNS |
| `XHttpConnectHook` (for Ubisoft domains) | PatchInJump | 205 | Fires for Guide button only, NOT for game's Ubisoft traffic |

## Key Findings

### 1. Trampoline Crash (Resolved)
PatchInJump with trampoline crashed on ordinal 205. The XHttp functions are commented out in 21256.0 `.def` files — they may be stubs/short functions where copying 16 bytes overshoots. Fixed by using **unhook-call-rehook** pattern: save original bytes, restore before calling, re-patch after.

### 2. PatchModuleImport vs PatchInJump
- `PatchModuleImport` only intercepts the game's direct imports. Worked for ordinal 205 (`S_OK`) but the hook never fired because the call goes through xam-internal code.
- `PatchInJump` patches the actual function in xam.xex, catching ALL callers. This is required.

### 3. XHttpConnect Fires But Not For Game Traffic
The `XHttpConnect` hook fires when pressing the Xbox Guide button (xam's own HTTP calls to Xbox services), proving the hook works. But the game's Ubisoft connections never trigger it. This means **Just Dance 2018 does NOT use `XHttpConnect` for its Ubisoft API calls**.

## Theories for Next Session

### Theory A: Game uses raw sockets through xam-internal wrappers
The game might call a higher-level xam function that internally uses sockets without going through `XHttpConnect`. The `connect` import hook didn't fire because PatchModuleImport only patches the game's import table — but the actual `connect` calls happen inside xam. Try **PatchInJump on `NetDll_connect` (ordinal 12)** to catch ALL connect calls system-wide.

### Theory B: Game uses Quazal/Ubisoft's custom networking layer
Just Dance's networking might use Ubisoft's Quazal/PRUDP protocol stack which handles connections at a lower level than XHttp. The "storm" domains (`ncsa-storm.ubi.com`, etc.) in the redirect list are Quazal rendezvous servers. This would use raw UDP sockets, not HTTP.

### Theory C: Game resolves DNS through the system network stack
The console's actual DNS resolver (configured in network settings) handles domain resolution, not `XNetDnsLookup` or `XHttpConnect`. The DNS server we created (`dns-server.js`) was visible on the network but the console never queried it because the console's DNS is pointed at the router, not our server. **The console's DNS settings need to be changed to point to 192.168.50.228** (the PC running dns-server.js).

### Theory D: SSL/TLS certificate validation blocks the connection
Even if we redirect traffic, the game may validate Ubisoft's SSL certificates. Connecting to our HTTP server with an HTTPS expectation would fail silently.

## Recommended Next Steps (Priority Order)

1. **Check console DNS settings** — ensure the Xbox 360's DNS is set to `192.168.50.228` (the PC). Run `dns-server.js` and verify the console's DNS queries appear in its log. This is the most likely missing piece.

2. **PatchInJump on `NetDll_connect` (ordinal 12)** — add a diagnostic that logs destination IPs/ports for ALL connect calls. This will reveal where the game is actually trying to connect.

3. **PatchInJump on `NetDll_socket` (ordinal 3)** — diagnostic to see if the game creates sockets at all.

4. **Investigate Quazal/PRUDP** — if the game uses Ubisoft's custom protocol, we may need to intercept at the socket level (connect/sendto/recvfrom) rather than at the HTTP level.

5. **Network packet capture** — use Wireshark on the PC to capture traffic from the console's IP (`192.168.50.x`) to see what DNS queries and connections it's actually making.

## Files Modified This Session
- `Sunrise2/CoreHooks.cpp` — major rewrite: added XHttp hooks, diagnostic toasts, unhook-call-rehook pattern
- `Sunrise2/stdafx.h` — added `#include <xhttp.h>`

## Files NOT Modified (unchanged)
- `Sunrise2/Sunrise2.cpp` — main loop, title detection
- `Sunrise2/Utilities.cpp` — PatchInJump, PatchModuleImport implementations
- `Sunrise2/Utilities.h` — declarations
- `Sunrise2/CoreHooks.h` — declarations
- `Sunrise2/xex.xml` — XEX build config
- `Sunrise2/Sunrise2.vcxproj` — build project
- `dp-x360-server/dns-server.js` — DNS redirect server
- `OpenParty/settings.json` — server config (isPublic: true)
