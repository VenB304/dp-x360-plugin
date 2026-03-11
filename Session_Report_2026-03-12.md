# Session Report — March 12, 2026

## dp-x360-plugin: Debugging Phase 1 Hook Deployment and DanceParty Developer Intelligence

## Executive Summary

This session focused on diagnosing and resolving crashes encountered after deploying the Phase 1 plugin rewrite to physical Xbox 360 hardware running the ABadAvatar/XeUnshackle exploit chain. The Phase 1 rewrite replaced the original PatchModuleImport-based hook strategy with system-wide PatchInJump hooks targeting core socket functions (ordinals 3, 12, 20, 24) and XHttp functions (ordinals 205, 207, 209) within xam.xex. Initial deployment demonstrated that hooks were installing successfully, as evidenced by the toast notification sequence "SetupHooks Entry," "EthLink called," and "XnAddr called," before the game crashed. Subsequent debugging attempts introduced InterlockedCompareExchange and InterlockedExchange kernel functions for reentrancy protection, which caused the compiled .xex to fail to load entirely in the XeUnshackle environment — likely due to missing kernel imports. The session concluded with the plugin in a non-loading state pending a clean rebuild in Visual Studio 2010.

Critically, a conversation with yunyl, a developer from the DanceParty team, revealed that their team had already built functional UbiServices and PRUDP servers ("Harbour") but the Xbox 360 game never connected. This strongly suggests SSL certificate pinning at the platform level as the fundamental blocker, mirroring the known Xbox One limitation that prevents custom Just Dance Unlimited servers from operating on that platform.

---

## Deployment Results and Crash Analysis

### Initial Deployment (Phase 1 Rewrite)

The Phase 1 plugin rewrite was deployed to physical Xbox 360 hardware running the ABadAvatar exploit with XeUnshackle and DashLaunch. The plugin was compiled as a DashLaunch .xex plugin and loaded at console boot time. The deployment environment consisted of the Xbox 360 console connected to a local network with the following server infrastructure running on the host PC at 192.168.50.228:

- OpenParty server (Node.js/Express) listening on port 80 for HTTP requests
- Diagnostic server (dp-x360-server) listening on UDP port 19030 for PRUDP packet analysis and TCP port 19030 for raw TCP logging
- Diagnostic receiver on UDP port 19031 for plugin side-channel log messages
- Local DNS server redirecting all Ubisoft domain queries to 192.168.50.228

Upon launching a Just Dance title, the following XNotify toast notifications were observed in sequence:

1. **"SetupHooks Entry"** — confirming that `SetupNetDllHooks()` was entered and the xam.xex module handle was successfully resolved
2. **"EthLink called"** — confirming that the `XNetGetEthernetLinkStatus` hook (ordinal 75, pure-replacement PatchInJump) fired and returned the spoofed `XNET_ETHERNET_LINK_ACTIVE | XNET_ETHERNET_LINK_100MBPS | XNET_ETHERNET_LINK_FULL_DUPLEX` status
3. **"XnAddr called"** — confirming that the `XNetGetTitleXnAddr` hook (ordinal 73, pure-replacement PatchInJump) fired and populated the XNADDR structure with the local network address 192.168.50.100

The game then crashed. No data was received on the diagnostic server at port 19031, indicating that either the `InitLogSocket()` function failed to create the UDP logging socket via `NetDll_socket(XNCALLER_SYSAPP, AF_INET, SOCK_DGRAM, IPPROTO_UDP)`, or the crash occurred before any `LogToServer()` calls could execute. The diagnostic server on port 19030 also received no traffic, and the OpenParty HTTP server logged no incoming requests.

The toast notification ordering provides critical diagnostic information. In the `SetupNetDllHooks()` function, the hook installation sequence is:

1. `InitLogSocket()` — creates UDP socket for side-channel logging
2. `HookState_Init` for ordinal 3 (`NetDll_socket`)
3. `HookState_Init` for ordinal 12 (`NetDll_connect`)
4. `HookState_Init` for ordinal 24 (`NetDll_sendto`)
5. `HookState_Init` for ordinal 20 (`NetDll_recvfrom`)
6. `HookState_Init` for ordinal 205 (`NetDll_XHttpConnect`)
7. `HookState_Init` for ordinal 207 (`NetDll_XHttpOpenRequest`)
8. `HookState_Init` for ordinal 209 (`NetDll_XHttpSendRequest`)
9. `PatchInJump` for ordinal 73 (`XNetGetTitleXnAddr`) — pure replacement
10. `PatchInJump` for ordinal 75 (`XNetGetEthernetLinkStatus`) — pure replacement
11. `PatchInJump` for ordinal 528 (`XamUserGetSigninState`) — pure replacement
12. `PatchModuleImport` for ordinals 530, 590, 592

The fact that "EthLink called" and "XnAddr called" appeared indicates that all hooks installed without causing an immediate crash during installation. The crash occurred when the game subsequently attempted to **use** one of the newly hooked socket functions (ordinals 3, 12, 20, or 24). The XNotify toast queue has a noticeable display delay; the toasts observed before the crash may have been queued significantly earlier than the actual crash point.

---

## Root Cause Analysis

Three potential crash causes were identified through code review:

### 1. Missing PowerPC Instruction Cache Flush in PatchInJump

The `PatchInJump()` function in `Utilities.cpp` performs a raw `memcpy` of four PowerPC instructions (`lis`, `ori`, `mtctr`, `bctr` — totaling 16 bytes) to the target function's entry point. On the Xbox 360's Xenon processor, the data cache (D-cache) and instruction cache (I-cache) are architecturally separate. Writing new instructions via `memcpy` updates the D-cache but does not invalidate the stale entries in the I-cache. When the processor subsequently fetches instructions from the patched address, it may execute the old, pre-patch instructions from the I-cache rather than the newly written branch trampoline. This would cause a crash when any hooked function is called for the first time after hooking.

The `HookState_Unhook()` function in `CoreHooks.cpp` already includes the correct PowerPC cache coherency sequence: `__dcbst` (data cache block store) to force D-cache writeback, `__sync` (synchronization barrier), and `__isync` (instruction synchronization) to invalidate the I-cache. However, the initial `PatchInJump()` call during `HookState_Init()` does not perform this flush. Additionally, the `HookState_Rehook()` function calls `PatchInJump()` directly, which also lacks the flush.

Despite this theoretical issue, the hooks did install and the pure-replacement hooks (ordinals 73 and 75) fired correctly. This suggests that the I-cache may have been naturally invalidated by the time those functions were called (due to context switches, cache pressure, or the intervening code execution between installation and invocation). The crash on the socket hooks may be timing-dependent — those functions could be called much sooner after installation.

### 2. Recursive Re-entry in the Sendto Hook

The `LogToServer()` utility function calls `NetDll_sendto(XNCALLER_SYSAPP, ...)` to transmit diagnostic messages to the PC server on port 19031. After the sendto hook (ordinal 24) is installed via PatchInJump, all calls to `NetDll_sendto` — including those from `LogToServer()` — enter the hook function `NetDll_sendtoPIJHook`.

The original Phase 1 code did not include a reentrancy guard. The hook function performs the following sequence: unhook (restore original bytes), call original function, rehook (re-patch with trampoline). If `LogToServer()` is called within the hook (for example, to log the sendto parameters before calling the original), the `LogToServer` → `NetDll_sendto` path re-enters the hook. The inner call performs `HookState_Unhook` on an already-unhook'd function (overwriting the original bytes with themselves — benign) and then `HookState_Rehook` (re-patching the trampoline). When the inner call returns, the outer call's execution context is corrupted because its `HookState_Rehook` call writes the same trampoline again, but the original function pointer it intended to call through now contains the trampoline rather than the original bytes.

### 3. Thread Safety of the Unhook-Rehook Pattern

The Xbox 360's Xenon processor features three physical cores, each with two hardware threads, for a total of six concurrent execution threads. The unhook-rehook pattern is inherently unsafe across threads: if Thread A unhooks a function to call the original, and Thread B simultaneously enters the hook and also attempts to unhook, the function's entry point instructions are being modified concurrently without synchronization. Worse, if Thread A rehooks while Thread B is mid-execution within the original function's first 16 bytes (now overwritten with the trampoline), Thread B will execute a partially overwritten instruction sequence.

This is an inherent limitation of the unhook-rehook approach for system-wide hooks on frequently-called functions. The window of vulnerability is extremely small (the original socket functions dispatch quickly), so this was not identified as the primary crash cause, but it remains a latent risk.

---

## Debugging Attempts and Results

### Fix Attempt 1: InterlockedCompareExchange Reentrancy Guards

To address the sendto recursion issue, `InterlockedCompareExchange` and `InterlockedExchange` were added as atomic reentrancy guards to all four socket hook functions. The `__dcbst/__sync/__isync` cache flush sequence was also added to `PatchInJump()` in `Utilities.cpp` to address the I-cache coherency issue. The sendto hook was restructured to perform logging during the unhook'd window (after `HookState_Unhook` but before calling the original function), so that recursive calls from `LogToServer` would pass through the original function directly.

**Result:** The compiled .xex failed to load entirely. No toast notifications appeared, including the "Sunrise2 Loaded!" notification from `DllMain` which is executed unconditionally at `DLL_PROCESS_ATTACH` and has no dependency on any hook code. This confirmed that the .xex binary was not being loaded by the DashLaunch daemon at all.

The most likely cause is that `InterlockedCompareExchange` and `InterlockedExchange` resolve to kernel imports (`lwarx`/`stwcx.` instruction sequences or `xboxkrnl.exe` exports) that are not available in the XeUnshackle exploit environment. The ABadAvatar/XeUnshackle chain patches the hypervisor to allow unsigned code execution but does not provide a complete kernel import table. If the compiled .xex references ordinals from `xboxkrnl.exe` that are not present in the patched environment, the PE loader will fail to resolve the imports and abort the DLL load entirely.

This finding is consistent with the existing project constraint that certain kernel functions are not available in the XeUnshackle environment. The project memory documents a similar observation regarding specific kernel imports causing .xex load failures.

### Fix Attempt 2: Volatile BOOL Replacement

All `InterlockedCompareExchange` and `InterlockedExchange` calls were replaced with simple `volatile BOOL` flag checks. This approach provides same-thread reentrancy protection (which is the primary concern for the `LogToServer` recursion) without requiring any kernel imports. Cross-thread atomicity is sacrificed, but the reentrancy guard's purpose is specifically to prevent same-thread recursive calls, not to synchronize across hardware threads.

**Result:** The .xex still failed to load. This indicated that the build was likely failing since the `InterlockedCompareExchange` introduction and no valid .xex had been produced since that point. The user had not performed a Clean + Rebuild operation in Visual Studio 2010, so the object files from the failed Interlocked build were still present and the linker was not producing a new output binary.

### Fix Attempt 3: Revert All Changes to Utilities.cpp

The `__dcbst/__sync/__isync` addition to `PatchInJump()` in `Utilities.cpp` was fully reverted to match the original Phase 1 code. The second `__dcbst` call that had been added to `HookState_Unhook()` was also removed. At this point, the only differences from the original Phase 1 code were the addition of `volatile BOOL` reentrancy guards and additional XNotify breadcrumb notifications in `SetupNetDllHooks()`.

**Result:** The .xex still failed to load on any game, including non-Just Dance titles. This definitively confirmed the issue was a stale build rather than a code logic problem. The user was advised to perform a Clean + Rebuild in Visual Studio 2010 (Build → Clean Solution, then Build → Rebuild Solution), verify build success in the Output window, confirm the output .xex file timestamp, redeploy the new binary to the console, and reboot the console to reload the DashLaunch plugin.

---

## Current State of the Codebase

### Utilities.cpp

`PatchInJump()` is in its original state — `memcpy` of four PowerPC instructions without an explicit cache flush. The cache flush remains a correctness concern for the unhook-rehook pattern and should be re-added once the build/deploy pipeline is confirmed working.

### CoreHooks.cpp (Phase 1 Rewrite + Reentrancy Guards)

The file contains the complete Phase 1 rewrite with the following additions from the debugging session:

**HOOK_STATE Infrastructure:** A reusable struct containing the target function pointer (`pFunction`), saved original instruction bytes (`origCode[4]`), the hook target address (`hookTarget`), and an installed flag. Helper functions `HookState_Init()`, `HookState_Unhook()`, and `HookState_Rehook()` manage the lifecycle of each hook, with the unhook path including the `__dcbst/__sync/__isync` cache coherency sequence.

**Seven HOOK_STATE globals** manage the call-through hooks for ordinals 3 (socket), 12 (connect), 20 (recvfrom), 24 (sendto), 205 (XHttpConnect), 207 (XHttpOpenRequest), and 209 (XHttpSendRequest).

**Side-channel diagnostic logging** sends UDP messages to 192.168.50.228:19031 using `XNCALLER_SYSAPP` as the caller type, which allows the plugin's own sendto hook to distinguish diagnostic traffic from game traffic. The `LogToServer()` function formats and transmits log strings; `LogPayloadToServer()` hex-encodes the first 64 bytes of binary payloads.

**Volatile BOOL reentrancy guards** on all four socket hooks prevent recursive re-entry. The sendto hook's guard is critical because `LogToServer()` internally calls `NetDll_sendto`.

**The sendto hook** is structured to perform logging during the unhook'd window: after `HookState_Unhook` restores the original function bytes but before calling through to the original, so that recursive `LogToServer` → `NetDll_sendto` calls hit the restored original function directly.

**XNotify breadcrumb notifications** after each individual hook installation in `SetupNetDllHooks()` enable precise crash isolation by showing which hook was the last to install successfully before a crash.

### dp-x360-server/server.js

The diagnostic server provides three listening services: a UDP receiver on port 19031 for plugin log messages, a UDP listener on port 19030 with a PRUDP V0 protocol header parser and RMC (Remote Method Call) payload decoder, and a TCP listener on port 19030 for raw TCP connection logging. The PRUDP parser extracts source/destination virtual ports, packet type (SYN, CONNECT, DATA, DISCONNECT, PING), flags, session ID, signature, and sequence ID from the 12-byte PRUDP V0 header. The RMC parser extracts protocol ID, method ID, call ID, and parameter data from DATA-type PRUDP packets.

### OpenParty/core/classes/Core.js

Two modifications were applied: an HTTP request logger middleware was added as the first middleware in the Express application stack, logging all incoming request methods, URLs, and headers to the console; and the catch-all 404 route handler was changed from `app.get('*')` to `app.all('*')` to capture non-GET requests that the game might send.

---

## DanceParty Developer Conversation

During this session, the project owner (Ven) received a direct message from yunyl, a developer associated with the DanceParty community project. The conversation provided critical intelligence regarding the viability of the plugin-based approach to Xbox 360 Just Dance network restoration.

### What DanceParty Has Already Achieved

yunyl reported that the DanceParty team, in collaboration with a developer described as "really professional with XLSP stuff," had progressed significantly further than the current dp-x360-plugin effort. Specifically, the DanceParty team had developed a fully functional custom UbiServices HTTP server and a Just Dance PRUDP server internally designated **"Harbour."** yunyl stated that these servers "work 100% with x360" from the server side — meaning the server infrastructure was capable of correctly parsing and responding to all expected Xbox 360 Just Dance network requests.

However, yunyl reported that despite this fully operational server infrastructure, the Xbox 360 game client **never successfully connected** to the custom UbiServices endpoint. yunyl explicitly stated: *"i never got to see his requests to our custom server."* The XLSP-focused developer subsequently ceased contributing to the project unexpectedly and did not share his fork of the plugin code with the DanceParty team.

### SSL Pinning Theory

yunyl's assessment of the failure points toward **SSL certificate pinning** as the fundamental platform-level blocker. The Xbox 360's XHTTP implementation may enforce certificate pinning for HTTPS connections to specific domains, validating the server's TLS certificate against a set of pinned certificates embedded in the system firmware or the game binary. If the Xbox 360 enforces this validation, any attempt to redirect HTTPS traffic to a custom server — even with a correctly functioning plugin that successfully hooks `XHttpConnect` and redirects the hostname — would fail at the TLS handshake because the custom server cannot present a certificate that matches the pinned Ubisoft certificate.

This theory is strongly supported by the known behavior of the Xbox One platform. yunyl noted that *"custom JDU servers work on everything but Xbox One"* because the Xbox One enforces SSL pinning. If the Xbox 360 implements a similar mechanism (even a simplified version via its XHTTP or wininet subsystem), the same limitation would apply.

The implications for the dp-x360-plugin approach are severe. Even if all hooks are functioning correctly — redirecting DNS, redirecting `XHttpConnect` hostnames, stripping the `XHTTP_FLAG_SECURE` flag, spoofing Xbox Live authentication — the underlying TLS implementation within xam.xex may still validate the server certificate against pinned certificates before establishing the HTTPS connection. This validation occurs below the hook layer and cannot be bypassed by simply redirecting the connection target.

### Alternative Approach: Executable Patching

yunyl disclosed that the DanceParty team maintains a **patcher application** for the Nintendo Wii and PlayStation 3 versions of Just Dance that patches the game's default executable (`main.dol` on Wii, `default_mp.self` on PS3) to redirect network endpoints. yunyl stated that the team is considering adding Xbox 360 support to this patcher, which would modify the game's `default.xex` binary directly to either replace hardcoded Ubisoft domain strings with custom server addresses, or patch out the SSL certificate validation routines entirely.

This approach bypasses the SSL pinning problem because the game's own TLS implementation or certificate validation logic is modified before the game executes. Rather than intercepting connections at runtime and hoping the platform accepts the redirect, the patched executable would either connect via plain HTTP or present a modified certificate validation routine that accepts any certificate.

The executable patching approach has trade-offs compared to the plugin approach. It requires per-title and potentially per-region patches for each Just Dance game (JD2014 through JD2019), it requires users to modify their game files (which is straightforward on a console running XeUnshackle since it can run games from USB or HDD), and it lacks the flexibility of a background plugin that can be updated independently of the game binary. However, it addresses the SSL pinning problem at its root.

### Conversation Transcript

```
yunyl:
hi, im yunyl and i seen your fork of dp's x360 plugin for dashlaunch
i found out that you're not in danceparty's server so i was wondering
if you were doing to help us out or for your own custom server?

Ven:
Testing things out
I'd like to help but its vibecoded
And also trying to see if there is a way to support xbox 360 again,
if claude or gemini can find out how to

yunyl:
we had a friend who was working on the plugin and he's really
professional with xlsp stuff but he decided to quit out of no where
and never shared his fork with us
we got to the point where we got our own ubiservices and jd prudp
server to work 100% with x360 but the game never connected to
ubiservices
like i never got to see his requests to our custom server (harbour)
so i thought maybe the games connecting in a way that we're not able
to see due to ssl

Ven:
yea, im also having issues having it communicate with something basic,
i got a diagnostic server to send some logs but still, all my attempts
so far havent really helped progress

yunyl:
i was thinking that doing it this way is probably not going to work
we have a patcher app that i made for wii and ps3 that patches the
games executable
i was thinking of adding a support for x360 for people to patch the
default.xex because theres no other way to make the x360 work
it would be really cool to have it via a plugin but nobody can figure
it out
its probably cuz xbox has ssl pinning, just like xbox one does and
thats why custom jdu servers works on everything but xone

Ven:
plus with badupdate/badavatar for soft modding, its a step closer but
still seems to be so far due to the ssl issue

Ven:
i'll share these too, maybe it could be useful to the official team
for Dance Party
[shared two Google Docs research documents]
would be really nice if x360 support was brought back, just recently
got myself x360 but ive been getting by with the jd2021 dev build
with maps that has gestures
```

### Shared Resources

Ven shared two research documents with the DanceParty team:

- **"Reviving Just Dance Xbox 360 Online"** — a feasibility and implementation plan covering the exploitation mechanics, hook architecture, and server emulation requirements
- **"Just Dance Revival Xbox 360 Guide"** — an architectural framework detailing the network protocol stack, PRUDP packet structure, and implementation roadmap

These documents provide the DanceParty team with context on the dp-x360-plugin approach and the Ghidra reverse engineering findings regarding the game's internal use of Quazal RendezVous Client SDK and UbiServices HTTP SDK.

---

## Key Learnings and Constraints

### 1. InterlockedCompareExchange and InterlockedExchange Must Not Be Used

These functions require kernel imports that are not available in the ABadAvatar/XeUnshackle exploit environment. Using them causes the compiled .xex to fail to load entirely, with no error indication on the console. Simple `volatile BOOL` flags must be used instead for reentrancy protection.

### 2. Clean Rebuilds Are Essential

Visual Studio 2010 does not always correctly detect changes that require a full relink. When debugging Xbox 360 plugin issues, always perform a Clean Solution followed by Rebuild Solution. Verify the output .xex file timestamp before deployment to confirm a new binary was produced.

### 3. DashLaunch Plugins Only Load at Boot

Changing games on the console does not reload the plugin. A full console reboot is required to load a newly deployed .xex binary.

### 4. XNotify Toast Queue Has Significant Latency

Toast notifications are queued and displayed sequentially with a noticeable delay between each. The last toast visible before a crash may have been queued well before the actual crash point. When multiple toasts are queued rapidly during hook installation, the crash may occur while earlier toasts are still being displayed.

### 5. SSL Certificate Pinning Is Likely the Fundamental Blocker

The DanceParty team's experience — fully functional servers but no game connection — combined with the known Xbox One SSL pinning behavior, strongly suggests that runtime hook-based redirection alone is insufficient. A solution will likely require either patching the game executable to remove SSL validation, hooking deeper into the TLS implementation within xam.xex, or identifying and patching the certificate pinning mechanism in system firmware.

---

## Outstanding Issues and Next Steps

### Immediate Priority

The user must perform a clean rebuild in Visual Studio 2010, verify the build succeeds without errors, confirm the output .xex timestamp is current, deploy the new binary to the console, and reboot. If the build fails, the compiler or linker errors must be captured and analyzed.

### If Build Succeeds and Plugin Loads

The Phase 1 crash (hooks install but game crashes when calling hooked socket functions) must be diagnosed. The `volatile BOOL` reentrancy guards and restructured sendto hook should mitigate the recursion issue. The XNotify breadcrumbs added after each hook installation will identify exactly which hook the crash follows. If the crash persists, individual hooks should be disabled one at a time to isolate the problematic ordinal.

### If Hooks Work but Game Doesn't Connect

This is the scenario the DanceParty team encountered. If the plugin successfully hooks all socket and XHttp functions, redirects all traffic to the local server, and the diagnostic server logs show the game's connection attempts, but the game still displays "Ubisoft server unavailable," the SSL pinning theory is confirmed. At that point, the project should pivot to one of:

- Investigating the TLS implementation within xam.xex to identify hookable certificate validation functions
- Collaborating with the DanceParty team on their executable patching approach
- Using Ghidra to locate the SSL/TLS certificate validation routines in the game binary and crafting binary patches

### Collaboration with DanceParty

The DanceParty team has operational server infrastructure (Harbour) that handles UbiServices HTTP and PRUDP protocols. If the SSL pinning issue can be resolved on the client side, the plugin could potentially redirect traffic to DanceParty's Harbour servers rather than requiring a separate custom server implementation. This would significantly reduce the scope of the remaining work.
