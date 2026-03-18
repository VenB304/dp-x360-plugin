# DashLaunch Native Patch Integration Strategy

## Executive Summary

Historically, the `dp-x360-plugin` (Sunrise2) codebase has relied heavily on manual memory patching and `PatchInJump` ordinal hooks to bypass the stringent Xbox Live authentication and security layers enforced by `xam.xex`. However, recent project analysis has revealed that the target environment—a soft-modded Xbox 360 running DashLaunch (via `XeUnshackle` or `HvPatcher`)—possesses native, kernel-level capabilities that mirror or exceed the custom hooks implemented in the plugin.

By properly leveraging the `launch.ini` configuration, we can deprecate massive, brittle portions of the `Sunrise2` codebase, delegate the Xbox Live spoofing to the hypervisor/kernel via DashLaunch, and allow the plugin to focus exclusively on DNS redirection and telemetry logging.

---

## Current Architecture vs. DashLaunch Capabilities

The current `Sunrise2` plugin spends the vast majority of its execution lifecycle attempting to circumvent three major XDK networking roadblocks: XNet secure socket encapsulation, Live authentication states, and HTTP token validation. 

### 1. The Insecure Socket Problem
**The Problem:** `Sunrise2` intercepts `XHttpSendRequest` to temporarily toggle `XNET_OPTID_NEUTERED` (insecure mode) and set the `SO_MARKINSECURE` / `SO_GRANTINSECURE` flags. This is done because all `XNCALLER_TITLE` sockets strictly enforce IPSec tunnels, and we need HTTP traffic to reach a plain LAN server (OpenParty).
**The DashLaunch Solution (`sockpatch = true`):** DashLaunch natively intercepts socket creation system-wide to grant the insecure socket privilege to all titles. 
**Strategic Impact:** We can potentially delete the complex socket neutering logic from the HTTP hooks and remove the `TCPTestThread` entirely. The OS will naturally permit plain TCP connections to standard IP addresses.

### 2. The Native HTTP / XEAS Authentication Blocker
**The Problem:** As discovered in the March 13 session reports, the UbiServices SDK fails to launch because `xam.xex` attempts to contact `XEAS.XBOXLIVE.COM` using a binary protocol to fetch an XSTS token. Because our PC server cannot emulate this undocumented binary handshake, XAM refuses to issue the token, and native HTTP connections are aborted before they even begin.
**The DashLaunch Solution (`xhttp = true`):** DashLaunch has a specific patch (`xhttp = true`) designed to remove the restriction on native HTTP functions that forces the user to be logged in and verified by Live. 
**Strategic Impact:** This kernel patch may completely bypass the `XUserGetTokenAndSignature` and XEAS requirement that was universally blocking the UbiServices SDK.

### 3. Xbox Live State Spoofing
**The Problem:** `CoreHooks.cpp` manually hooks multiple ordinals (`XamUserCheckPrivilege`, `XamUserGetSigninState`, `XNetLogonGetState`, `XnpLogonGetStatus`) simply to return `TRUE` or `2` (Connected).
**The DashLaunch Solution (`fakelive = true`):** DashLaunch spoofs the firmware system-wide to believe it is fully connected to Xbox Live. 
**Strategic Impact:** Double-hooking these functions (once by DashLaunch in kernel space, once by `Sunrise2` in userland) introduces severe race conditions and memory access violations. Deprecating our manual hooks prevents conflicts and relies on a stable, community-tested spoof.

### 4. UART Console and Crash Logging
**The Problem:** Attempting to use `vfprintf` to `stdout` in the background plugin thread causes instant silent crashes because the `ABadAvatar` payload lacks an initialized UI console.
**The DashLaunch Solution (`debugout = true` & `dumpfile`):** DashLaunch natively intercepts crash states to dump stack traces to a USB text file (`crashlog.txt`) and can route debug strings directly to UART.
**Strategic Impact:** Replacing standard output with `DbgPrint` and relying on the Crash handler will save dozens of hours debugging silent black-screen freezes.

---

## Recommended Action Plan

### Phase 1: Codebase Pruning (The "Lean Plugin" Approach)
The transition to a DashLaunch-reliant architecture requires the following modifications to `CoreHooks.cpp`:
1. **Disable Logon Hooks:** Comment out or remove the installation of hooks for ordinals `322`, `302`, `112`, `65`, `66`, `528`, and `530`.
2. **Remove Neutering Logic:** Strip the `XNET_OPTID_NEUTERED` temporary toggling from `NetDll_XHttpSendRequestHook`.
3. **Change Logging Target:** Rewrite the `Sunrise_Dbg` utility to use `DbgPrint` instead of `vfprintf`.

### Phase 2: Refocusing on Redirects
With the OS handling the security bypasses, `Sunrise2` only needs to perform operations DashLaunch *cannot* do natively:
1. **Targeted Redirection:** Hook `XHttpConnect` and `sendto` to redirect `public-ubiservices.ubi.com` string occurrences to the local PC IP.
2. **XLSP Chicken-and-Egg Bypass:** Following the theoretical discussion with the DanceParty team, continue using `XamEnumerateHook` to intercept LSP resolution and force it to return the OpenParty IP, bypassing the need for Ubisoft to serve the initial connection string.
3. **XEX Binary Patching:** Verify if the recommended static URL patching inside `default.xex` (converting HTTPS to HTTP natively) is still necessary if `sockpatch` and `xhttp` effectively disable SSL enforcement.

### Conclusion
Embracing DashLaunch's `launch.ini` capabilities transforms the `Sunrise2` plugin from a monolithic, brittle Xbox Live emulator into a lightweight, stable traffic router. This eliminates the need to reverse-engineer undocumented binary sequences like XEAS and allows immediate focus on parsing the Just Dance telemetry arriving at the OpenParty server.
