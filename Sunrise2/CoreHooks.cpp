#include "stdafx.h"
#include "Sunrise2.h"
#include "Utilities.h"

XTITLE_SERVER_INFO activeServer;
WORD activeServerPort;
HANDLE lsp_enum_handle;
int enumeration_index;

// Domains to redirect to our local server
static const char* REDIRECT_DOMAINS[] = {
	"public-ubiservices.ubi.com",
	"public-ws-ubiservices.ubi.com",
	"api-ubiservices.ubi.com",
	"uplay-ubiservices.ubi.com",
	"connect.ubi.com",
	"ubiservices.ubi.com",
	"gaap.ubiservices.ubi.com",
	"pdc-prd-jdbloom.ubisoft.org",
	"jd.ubisoft.com",
	"v2.phonescoring.jd.ubisoft.com",
	"phonescoring.jd.ubisoft.com",
	"gamecfg-mob.ubi.com",
	"ncsa-storm.ubi.com",
	"emea-storm.ubi.com",
	"apac-storm.ubi.com",
};
static const int REDIRECT_DOMAIN_COUNT = sizeof(REDIRECT_DOMAINS) / sizeof(REDIRECT_DOMAINS[0]);

// Pool of fake XNDNS results for intercepted lookups
#define MAX_DNS_ENTRIES 8
static XNDNS fakeDnsResults[MAX_DNS_ENTRIES];
static int fakeDnsIndex = 0;

// Trampolines for calling original functions after PatchInJump
// Each trampoline: 16 bytes of saved original code + 16 bytes for jump back = 32 bytes
// __declspec(align(32)) to ensure proper alignment for PPC code execution
__declspec(align(32)) static DWORD dnsLookupTrampoline[8];
__declspec(align(32)) static DWORD dnsReleaseTrampoline[8];

// Original function typedef for DNS
typedef INT (*pfnXNetDnsLookup)(XNCALLER_TYPE xnc, const char* pszHost, WSAEVENT hEvent, XNDNS** ppxndns);
typedef INT (*pfnXNetDnsRelease)(XNCALLER_TYPE xnc, XNDNS* pxndns);

static BOOL ShouldRedirectDomain(const char* hostname)
{
	for (int i = 0; i < REDIRECT_DOMAIN_COUNT; i++)
	{
		if (_stricmp(hostname, REDIRECT_DOMAINS[i]) == 0)
			return TRUE;
	}
	return FALSE;
}

void RegisterActiveServer(in_addr address, WORD port, const char description[XTITLE_SERVER_MAX_SERVER_INFO_LEN]) {
	activeServer.inaServer.S_un.S_addr = address.S_un.S_addr;
	activeServerPort = port;
	memcpy(activeServer.szServerInfo, description, XTITLE_SERVER_MAX_SERVER_INFO_LEN);
}

int NetDll_connectHook(XNCALLER_TYPE n, SOCKET s, const sockaddr* name, int namelen)
{
	if (n == 1) {
		((SOCKADDR_IN*)name)->sin_addr.S_un.S_addr = activeServer.inaServer.S_un.S_addr;
		((SOCKADDR_IN*)name)->sin_port = activeServerPort;
	}
	return NetDll_connect(n, s, name, namelen);
}

int NetDll_sendtoHook(XNCALLER_TYPE xnc, SOCKET s, const VOID* buf, int len, int flags, VOID* to, int tolen)
{
	if (xnc == 1 && to != NULL) {
		((SOCKADDR_IN*)to)->sin_addr.S_un.S_addr = activeServer.inaServer.S_un.S_addr;
		((SOCKADDR_IN*)to)->sin_port = activeServerPort;
	}
	return NetDll_sendto(xnc, s, buf, len, flags, to, tolen);
}

int NetDll_WSASendToHook(XNCALLER_TYPE xnc, SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr FAR* lpTo, int iTolen, LPOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	if (xnc == 1 && lpTo != NULL) {
		((SOCKADDR_IN*)lpTo)->sin_addr.S_un.S_addr = activeServer.inaServer.S_un.S_addr;
		((SOCKADDR_IN*)lpTo)->sin_port = activeServerPort;
	}
	return NetDll_WSASendTo(xnc, s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
}

DWORD XamUserCheckPrivilegeHook(DWORD dwUserIndex, DWORD dwPrivilegeType, PBOOL pfResult)
{
	if (pfResult != NULL) {
		*pfResult = TRUE;
	}
	return 0; // ERROR_SUCCESS
}

int XamCreateEnumeratorHandleHook(DWORD user_index, HXAMAPP app_id, DWORD open_message, DWORD close_message, DWORD extra_size, DWORD item_count, DWORD flags, PHANDLE out_handle)
{
    int result = XamCreateEnumeratorHandle(user_index, app_id, open_message, close_message, extra_size, item_count, flags, out_handle);

    if (open_message == 0x58039 || ((DWORD)app_id & 0xFFFF0000) == 0x55530000) {
        lsp_enum_handle = *out_handle;
        enumeration_index = 0;
        XNotify(L"LSP intercepted!");
    }
    return result;
}

int XamEnumerateHook(HANDLE hEnum, DWORD dwFlags, PDWORD pvBuffer, DWORD cbBuffer, PDWORD pcItemsReturned, PXOVERLAPPED pOverlapped)
{
	if (hEnum == lsp_enum_handle) {
		if (cbBuffer < sizeof(XTITLE_SERVER_INFO)) return ERROR_INSUFFICIENT_BUFFER;

		memcpy(pvBuffer, &activeServer, sizeof(XTITLE_SERVER_INFO));
		int errorCode = enumeration_index == 0 ? 0 : ERROR_NO_MORE_FILES;
		enumeration_index = 1;

		if (pOverlapped) {
			pOverlapped->InternalLow = errorCode;
			pOverlapped->InternalHigh = 1;
			if (pOverlapped->hEvent) SetEvent(pOverlapped->hEvent);
			return ERROR_IO_PENDING;
		}
		return errorCode;
	}
	return XamEnumerate(hEnum, dwFlags, pvBuffer, cbBuffer, pcItemsReturned, pOverlapped);
}

// ============================================================================
// XNet status hooks — patched directly in xam.xex via PatchInJump
// These replace the functions entirely so ALL callers get our hooks,
// not just the game's direct imports.
// ============================================================================

DWORD XNetGetTitleXnAddrHook(XNCALLER_TYPE xnc, XNADDR* pxna)
{
	if (pxna != NULL)
	{
		memset(pxna, 0, sizeof(XNADDR));
		pxna->ina.S_un.S_un_b.s_b1 = 192;
		pxna->ina.S_un.S_un_b.s_b2 = 168;
		pxna->ina.S_un.S_un_b.s_b3 = 50;
		pxna->ina.S_un.S_un_b.s_b4 = 100;
		pxna->inaOnline.S_un.S_un_b.s_b1 = 192;
		pxna->inaOnline.S_un.S_un_b.s_b2 = 168;
		pxna->inaOnline.S_un.S_un_b.s_b3 = 50;
		pxna->inaOnline.S_un.S_un_b.s_b4 = 100;
		pxna->wPortOnline = htons(3074);
		pxna->abEnet[0] = 0x00;
		pxna->abEnet[1] = 0x1D;
		pxna->abEnet[2] = 0xD8;
		pxna->abEnet[3] = 0xB7;
		pxna->abEnet[4] = 0x1C;
		pxna->abEnet[5] = 0xA8;
	}
	return XNET_GET_XNADDR_DHCP | XNET_GET_XNADDR_GATEWAY | XNET_GET_XNADDR_DNS | XNET_GET_XNADDR_ONLINE;
}

DWORD XNetGetEthernetLinkStatusHook(XNCALLER_TYPE xnc)
{
	return XNET_ETHERNET_LINK_ACTIVE | XNET_ETHERNET_LINK_100MBPS | XNET_ETHERNET_LINK_FULL_DUPLEX;
}

// ============================================================================
// XNet DNS hooks — uses trampolines to call originals for non-Ubisoft domains
// ============================================================================

INT XNetDnsLookupHook(XNCALLER_TYPE xnc, const char* pszHost, WSAEVENT hEvent, XNDNS** ppxndns)
{
	if (pszHost != NULL && ShouldRedirectDomain(pszHost))
	{
		XNDNS* pDns = &fakeDnsResults[fakeDnsIndex % MAX_DNS_ENTRIES];
		fakeDnsIndex++;

		memset(pDns, 0, sizeof(XNDNS));
		pDns->iStatus = 0;
		pDns->cina = 1;
		pDns->aina[0].S_un.S_un_b.s_b1 = 192;
		pDns->aina[0].S_un.S_un_b.s_b2 = 168;
		pDns->aina[0].S_un.S_un_b.s_b3 = 50;
		pDns->aina[0].S_un.S_un_b.s_b4 = 228;

		*ppxndns = pDns;

		if (hEvent != NULL)
			SetEvent(hEvent);

		XNotify(L"DNS Redirected!");
		return 0;
	}

	// Call original via trampoline
	pfnXNetDnsLookup origFunc = (pfnXNetDnsLookup)(void*)dnsLookupTrampoline;
	return origFunc(xnc, pszHost, hEvent, ppxndns);
}

INT XNetDnsReleaseHook(XNCALLER_TYPE xnc, XNDNS* pxndns)
{
	for (int i = 0; i < MAX_DNS_ENTRIES; i++)
	{
		if (pxndns == &fakeDnsResults[i])
			return 0;
	}
	// Call original via trampoline
	pfnXNetDnsRelease origFunc = (pfnXNetDnsRelease)(void*)dnsReleaseTrampoline;
	return origFunc(xnc, pxndns);
}

// ============================================================================
// XUserGetSigninState hook — fake Xbox Live sign-in
// ============================================================================

DWORD XamUserGetSigninStateHook(DWORD dwUserIndex)
{
	// Return "signed in to Live" for user 0, not signed in for others
	if (dwUserIndex == 0)
		return 2; // eXamUserSigninState_SignedInToLive
	return 0; // eXamUserSigninState_NotSignedIn
}

// ============================================================================
// Hook setup — builds trampolines and patches xam.xex functions directly
// ============================================================================

static void BuildTrampoline(DWORD* trampoline, DWORD* originalFunc)
{
	// Copy first 4 instructions (16 bytes) of original function
	memcpy(trampoline, originalFunc, 16);
	// Write a jump to originalFunc + 16 (skip the 4 instructions we saved)
	PatchInJump(&trampoline[4], (DWORD)originalFunc + 16, FALSE);
	// Flush instruction cache
	__dcbst(0, trampoline);
	__sync();
	__isync();
}

VOID SetupNetDllHooks()
{
	HMODULE hXam = GetModuleHandle(MODULE_XAM);
	if (hXam == NULL) return;

	// --- Import table hooks (for game's direct imports) ---
	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 12, (DWORD)NetDll_connectHook);
	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 24, (DWORD)NetDll_sendtoHook);
	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 25, (DWORD)NetDll_WSASendToHook);
	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 530, (DWORD)XamUserCheckPrivilegeHook);
	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 590, (DWORD)XamCreateEnumeratorHandleHook);
	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 592, (DWORD)XamEnumerateHook);

	// --- PatchInJump hooks (patches actual xam.xex functions, affects ALL callers) ---

	// XNetGetTitleXnAddr (ordinal 73) — pure replacement, no trampoline needed
	DWORD* pXNetGetTitleXnAddr = (DWORD*)ResolveFunction(hXam, 73);
	if (pXNetGetTitleXnAddr != NULL)
		PatchInJump(pXNetGetTitleXnAddr, (DWORD)XNetGetTitleXnAddrHook, FALSE);

	// XNetGetEthernetLinkStatus (ordinal 75) — pure replacement
	DWORD* pXNetGetEthernetLinkStatus = (DWORD*)ResolveFunction(hXam, 75);
	if (pXNetGetEthernetLinkStatus != NULL)
		PatchInJump(pXNetGetEthernetLinkStatus, (DWORD)XNetGetEthernetLinkStatusHook, FALSE);

	// XNetDnsLookup (ordinal 67) — needs trampoline for non-Ubisoft passthrough
	DWORD* pXNetDnsLookup = (DWORD*)ResolveFunction(hXam, 67);
	if (pXNetDnsLookup != NULL) {
		BuildTrampoline(dnsLookupTrampoline, pXNetDnsLookup);
		PatchInJump(pXNetDnsLookup, (DWORD)XNetDnsLookupHook, FALSE);
	}

	// XNetDnsRelease (ordinal 68) — needs trampoline for non-fake releases
	DWORD* pXNetDnsRelease = (DWORD*)ResolveFunction(hXam, 68);
	if (pXNetDnsRelease != NULL) {
		BuildTrampoline(dnsReleaseTrampoline, pXNetDnsRelease);
		PatchInJump(pXNetDnsRelease, (DWORD)XNetDnsReleaseHook, FALSE);
	}

	// XamUserGetSigninState (ordinal 528) — fake Live sign-in
	DWORD* pXamUserGetSigninState = (DWORD*)ResolveFunction(hXam, 528);
	if (pXamUserGetSigninState != NULL)
		PatchInJump(pXamUserGetSigninState, (DWORD)XamUserGetSigninStateHook, FALSE);
}
