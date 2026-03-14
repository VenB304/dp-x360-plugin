# dp-x360-plugin

A Dashlaunch plugin for Xbox 360 that redirects Just Dance network traffic to a custom self-hosted server ([OpenParty](https://github.com/ibratabian17/OpenParty)).

Targets soft-modded consoles running the [ABadAvatar](https://github.com/shutterbug2000/ABadAvatar) exploit.

**Status: Active research — not functional yet.**

## How It Works

The plugin hooks Xbox network APIs at the XHttp layer to intercept outbound connections to Ubisoft/UbiServices endpoints and redirect them to a local OpenParty instance. Key discoveries so far:

- XNet wraps all sockets in a security protocol by default — `SO_MARKINSECURE` / `XNET_OPTID_NEUTERED` bypasses this
- PatchModuleImport hooks don't fire for game SDKs (internal wrappers); system-wide `PatchInJump` is required
- XHttp-level hooks (ordinals 205, 207, 209) work; socket-level hooks freeze the system
- XEX patched: URL template at `0x822998c8` (`https://{env}public-ubiservices.ubi.com/{version}`) replaced with `http://192.168.50.47/{version}`; OpenParty xenon platform support added
- piflc redirect confirmed working — `POST /vortex/logbinary.ashx` received with XON/2 telemetry body (`LogonFail_As`)
- Current blocker: XEAS authentication fails (binary TCP protocol, not HTTP) — xam.xex never issues an XSTS token, so the UbiServices SDK never makes HTTP calls
- Next step: hook `XUserGetTokenAndSignature` via `PatchModuleImport` to return a fake XSTS token, bypassing the entire XEAS/piflc chain

## Setup

- **Console**: Xbox 360 soft-modded via ABadAvatar/XeUnshackle with DashLaunch
- **Plugin**: `Sunrise2.xex` deployed to USB or HDD, loaded via `launch.ini`
- **Server**: [OpenParty](https://github.com/ibratabian17/OpenParty) (Node.js, port 80) on local PC

## Building

Open `Sunrise2/Sunrise2.sln` in Visual Studio 2010 with Xbox 360 SDK (XDK 21256) installed.
Build configuration: `Release21256.0 | Xbox 360`

Output: `Sunrise2/Release/Sunrise2.xex`

## Session Reports

| Date | Report | Summary |
|------|--------|---------|
| Mar 11, 2026 | [Session 1](docs/SESSION_REPORT_2026-03-11_1.md) | Initial plugin setup, hook skeleton, network vector mapping |
| Mar 12, 2026 | [Session 2](docs/SESSION_REPORT_2026-03-12_1.md) | Debugging Phase 1, DanceParty dev intel, XNet security layer discovery |
| Mar 12, 2026 | [Session 3](docs/SESSION_REPORT_2026-03-12_2.md) | XNet NEUTERED breakthrough, XHttp redirect confirmed, logon state investigation |
| Mar 12, 2026 | [Session 4](docs/SESSION_REPORT_2026-03-12_3.md) | Quazal RendezVous analysis, XNet IPSec tunnel spoofing |
| Mar 13, 2026 | [Session 5](docs/SESSION_REPORT_2026-03-13_1.md) | Ghidra deep dive, logon hooks confirmed never-called, XEX patch plan |
| Mar 13, 2026 | [Session 6](docs/SESSION_REPORT_2026-03-13_2.md) | piflc redirect confirmed, XEAS binary auth failure identified, vortex telemetry decoded |

## Research

- [Reviving Just Dance Xbox 360 Online](https://docs.google.com/document/d/1KkvpkaBPJHN8tHenfWjC79fzUM6fS2YWbM-ywYuH2-Q/edit?usp=sharing) — Research document on re-enabling JD Xbox 360 online services
- [Just Dance Revival Xbox 360 Guide](https://docs.google.com/document/d/1jkZiGtSYnkbbGTiEWv8sKwXOibZNWTdkLx3D-4Mvk7U/edit?usp=sharing) — Initial guide covering the Xbox 360 revival setup and approach
- [Strategic Direction and Technical Roadmap](https://docs.google.com/document/d/1Un9SBWAvzRl1SEulom7gQhOb_lcgzF36dwlEwS6WA2s/edit?usp=drivesdk) — In-depth analysis of pre-connectivity blockers, SSL pinning bypasses, and the transition to a hybrid static/dynamic patching methodology.

## Credits

- Byrom — plugin architecture (2.0)
- craftycodie — Halo hooks and addresses
- FreestyleDash Team — xkelib
