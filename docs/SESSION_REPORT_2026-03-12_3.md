# Session Report — March 13, 2026

## dp-x360-plugin: Quazal RendezVous Investigation and XNet IPSec Spoofing

## Executive Summary

This session focused on determining why Just Dance 2018 fails with a "connection error" before ever reaching the HTTP layer (UbiServices). By analyzing a GHIDRA strings dump of the game executable, a critical discovery was made: the game relies heavily on the **Quazal RendezVous SDK**. 

The SDK's connection state machine reveals that before making any HTTP queries, the game attempts to establish a secure Xbox Live IPSec tunnel to an LSP (Lobby Server Protocol) server. To spoof this, new hooks were implemented for `XNetConnect` (ordinal 65) and `XNetGetConnectStatus` (ordinal 66). Despite spoofing a successful tunnel connection, the game still reports a connection error, indicating further Quazal-specific networking hurdles remain.

---

## Environment

- **Console**: Xbox 360, soft-modded via ABadAvatar/XeUnshackle
- **Build**: VS2010 + XDK 21256, `Sunrise2.xex` DashLaunch plugin
- **PC IP**: 192.168.50.47 (Wi-Fi)
- **Xbox IP**: 192.168.50.186
- **Servers**: OpenParty on port 80, diagnostic server on 19030/19031, DNS server on 53

---

## Breakthroughs & Analysis

### 1. Discovery of Quazal RendezVous SDK

A search through `ghidra_jd2018_defined_strings.csv` revealed a massive presence of the Quazal RendezVous Client SDK. The game uses this SDK to handle low-level connections, peer-to-peer matchmaking, and secure tunnels.

Key networking classes found in the game:
- `JobBackEndServicesConnect`
- `JobBackEndServicesLogin`
- `JobGetLSPTunnel`
- `PRUDPEndPoint` and `UDPTransport`
- `SecureConnectionProtocol`

### 2. The Pre-HTTP Blocker: LSP Tunnel Initialization

The GHIDRA strings revealed the exact sequence of operations the game performs when trying to go online:

```cpp
JobGetLSPTunnel::QueryLSPAddress
JobGetLSPTunnel::WaitForQueryLSPAddress
JobGetLSPTunnel::SecureConnect
JobGetLSPTunnel::StepXNetGetConnectStatus
```

This explains the pre-HTTP connection error:
1. The game queries the LSP address (which our `XamEnumerate` hook successfully spoofs to `192.168.50.47`).
2. The game calls `XNetConnect` (ordinal 65) to establish an encrypted IPSec tunnel to that address.
3. The game loops, calling `XNetGetConnectStatus` (ordinal 66), waiting for it to return **CONNECTED** (value `2`).
4. Because the PC is not a real Xbox Live LSP server, the real `xam.xex` fails to negotiate IPSec, returns `LOST` or `IDLE`, and the Quazal SDK aborts the online sequence. `XHttpConnect` is never called.

### 3. Implementation of XNet Tunnel Spoofing

To bypass the `JobGetLSPTunnel` blocker, two new hooks were added to `Sunrise2/CoreHooks.cpp`:

| Ordinal | Function | Hook Returns | Rationale |
|---------|----------|-------------|-----------|
| 65 | `NetDll_XNetConnect` | 0 (Success) | Pretends the IPSec tunnel initiation succeeded immediately. |
| 66 | `NetDll_XNetGetConnectStatus` | 2 (`XNET_CONNECT_STATUS_CONNECTED`) | Tells the Quazal SDK polling loop that the tunnel is ready. |

---

## Current Problem: Connection Error Persists

Despite writing hooks for `XNetConnect` and `XNetGetConnectStatus` to spoof a successful IPSec tunnel, the game still fails with a connection error. 

Possible reasons for this continued failure:
1. **The Hooks Weren't Called**: The game might be failing *even earlier* in the process (e.g., during `QueryLSPAddress` processing or DNS resolution).
2. **PRUDP Handshake (Quazal)**: After establishing the IPSec tunnel, the Quazal SDK usually sends a UDP handshake (PRUDP) to the LSP server. If OpenParty doesn't implement a Quazal PRUDP listener to respond to this handshake, the Quazal SDK will time out and fail.
3. **Logon State Failure**: A separate logon check (`XNetLogonGetState`, etc.) might still be failing if the newly implemented hooks (ordinals 322, 302, 112) have side effects or return values the game doesn't like.

---

## Files Modified This Session

| File | Changes |
|------|---------|
| `Sunrise2/CoreHooks.cpp` | Added `XNetConnectHook` (ord 65) returning 0.<br>Added `XNetGetConnectStatusHook` (ord 66) returning 2.<br>Registered hooks and added diagnostic UDP toggles. |

---

## Architecture: The Quazal Blocker

```
Xbox 360 Game (Quazal RendezVous)
  ├── XamEnumerate → Hook returns LSP server info (192.168.50.47) ✅
  ├── Xbox Live Logon Checks (XNetLogonGetState, etc.) → Hooked, returning online status ✅
  ├── JobGetLSPTunnel::SecureConnect (ord 65) → Hooked, returning success ✅
  ├── JobGetLSPTunnel::StepXNetGetConnectStatus (ord 66) → Hooked, returning CONNECTED (2) ✅
  ├── [MISSING?] Quazal PRUDP Handshake over UDP? ❓
  │   └── If game expects a PRUDP response from OpenParty, this will fail.
  │
  └── (IF Quazal tunnel succeeds) → UbiServices HTTP flow:
      └── XHttpConnect("public-ubiservices.ubi.com") → Redirected locally ✅
```

---

## Next Steps (Priority Order)

1. **Verify Toast Output**: Run the game and watch the `[DIAG]` notifications on the Xbox screen. We must confirm:
   - Did `[DIAG] XNetConnect called!` appear?
   - Did `[DIAG] XNetGetConnStat!` appear?
   - Did the logon toasts (`[DIAG] LogonState called!`) appear?
   *If the XNet connection toasts never appear, the game is failing on a different condition before it even tries to connect.*

2. **Sniff Quazal UDP Traffic (Wireshark)**: Use Wireshark on the PC to monitor traffic from the Xbox 360 IP (`192.168.50.186`). 
   - See if the Xbox is sending binary UDP packets to the PC over port 3074 or another port.
   - If PRUDP packets are being sent, we will need to emulate a basic Quazal RendezVous server in OpenParty to acknowledge them.

3. **Check DNS Operations**: Determine if the game is using `NetDll_XNetDnsLookup` (ordinal 67) to resolve the LSP or RendezVous server before connecting. Hooking DNS resolution entirely might be necessary if it's strictly validating XNDNS structures.

4. **Quazal Sandbox Config**: Quazal requires a specific "sandbox" and authentication keys. Review the game's executable for configurations (often found near `RVCID` or `ClientVersionInfo` strings) to determine if authentication needs to be perfectly mirrored.
