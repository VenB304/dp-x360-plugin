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

// Local server IP as a string for XHttpConnect hostname replacement
static const char* LOCAL_SERVER_IP = "192.168.50.228";

// ============================================================================
// XHttp hook — saved original function pointer (no trampoline needed)
// PatchModuleImport only changes the import table, original code stays intact
// ============================================================================

// NetDll_XHttpConnect: XNCALLER_TYPE xnc, HINTERNET hSession, LPCSTR pszServerName, INTERNET_PORT nServerPort, DWORD dwFlags
typedef HINTERNET (*pfnNetDll_XHttpConnect)(XNCALLER_TYPE xnc, HINTERNET hSession, LPCSTR pszServerName, INTERNET_PORT nServerPort, DWORD dwFlags);
static pfnNetDll_XHttpConnect g_origXHttpConnect = NULL;

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

// ============================================================================
// Import table hooks (PatchModuleImport — game's direct imports only)
// ============================================================================

static BOOL bConnectHookFired = FALSE;
int NetDll_connectHook(XNCALLER_TYPE n, SOCKET s, const sockaddr* name, int namelen)
{
	if (!bConnectHookFired) {
		XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, L"[DIAG] connect hook!", NULL);
		bConnectHookFired = TRUE;
	}
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

static BOOL bPrivilegeHookFired = FALSE;
DWORD XamUserCheckPrivilegeHook(DWORD dwUserIndex, DWORD dwPrivilegeType, PBOOL pfResult)
{
	if (!bPrivilegeHookFired) {
		XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, L"[DIAG] Privilege called!", NULL);
		bPrivilegeHookFired = TRUE;
	}
	if (pfResult != NULL) {
		*pfResult = TRUE;
	}
	return 0; // ERROR_SUCCESS
}

static BOOL bEnumCreateHookFired = FALSE;
int XamCreateEnumeratorHandleHook(DWORD user_index, HXAMAPP app_id, DWORD open_message, DWORD close_message, DWORD extra_size, DWORD item_count, DWORD flags, PHANDLE out_handle)
{
	if (!bEnumCreateHookFired) {
		XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, L"[DIAG] EnumCreate called!", NULL);
		bEnumCreateHookFired = TRUE;
	}
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
// ============================================================================

static BOOL bXnAddrHookFired = FALSE;
DWORD XNetGetTitleXnAddrHook(XNCALLER_TYPE xnc, XNADDR* pxna)
{
	if (!bXnAddrHookFired) {
		XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, L"[DIAG] XnAddr called!", NULL);
		bXnAddrHookFired = TRUE;
	}
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

static BOOL bEthLinkHookFired = FALSE;
DWORD XNetGetEthernetLinkStatusHook(XNCALLER_TYPE xnc)
{
	if (!bEthLinkHookFired) {
		XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, L"[DIAG] EthLink called!", NULL);
		bEthLinkHookFired = TRUE;
	}
	return XNET_ETHERNET_LINK_ACTIVE | XNET_ETHERNET_LINK_100MBPS | XNET_ETHERNET_LINK_FULL_DUPLEX;
}

// ============================================================================
// XUserGetSigninState hook — fake Xbox Live sign-in
// ============================================================================

static BOOL bSigninHookFired = FALSE;
DWORD XamUserGetSigninStateHook(DWORD dwUserIndex)
{
	if (!bSigninHookFired) {
		XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, L"[DIAG] SignIn called!", NULL);
		bSigninHookFired = TRUE;
	}
	if (dwUserIndex == 0)
		return 2; // eXamUserSigninState_SignedInToLive
	return 0; // eXamUserSigninState_NotSignedIn
}

// ============================================================================
// XHttp hooks — intercept HTTP connections at the API level
// This is what Just Dance actually uses (not XNetDnsLookup)
// ============================================================================

static BOOL bXHttpConnectHookFired = FALSE;
HINTERNET NetDll_XHttpConnectHook(XNCALLER_TYPE xnc, HINTERNET hSession, LPCSTR pszServerName, INTERNET_PORT nServerPort, DWORD dwFlags)
{
	if (!bXHttpConnectHookFired) {
		XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, L"[DIAG] XHttpConnect!", NULL);
		bXHttpConnectHookFired = TRUE;
	}

	if (pszServerName != NULL && ShouldRedirectDomain(pszServerName))
	{
		XNotify(L"HTTP Redirected!");
		if (g_origXHttpConnect != NULL) {
			// PatchModuleImport path: original function intact, call directly
			return g_origXHttpConnect(xnc, hSession, LOCAL_SERVER_IP, 80, dwFlags & ~XHTTP_FLAG_SECURE);
		}
		// PatchInJump path: can't call original, return NULL (connection will fail gracefully)
		return NULL;
	}

	if (g_origXHttpConnect != NULL) {
		// PatchModuleImport path: pass through to original
		return g_origXHttpConnect(xnc, hSession, pszServerName, nServerPort, dwFlags);
	}
	// PatchInJump path: can't call original for non-Ubisoft domains, return NULL
	return NULL;
}

// ============================================================================
// Hook setup — patches xam.xex functions directly
// ============================================================================

VOID SetupNetDllHooks()
{
	XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, L"[DIAG] SetupHooks Entry", NULL);

	HMODULE hXam = GetModuleHandle(MODULE_XAM);
	if (hXam == NULL) {
		XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, L"[DIAG] hXam is NULL!", NULL);
		return;
	}
	XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, L"[DIAG] hXam OK", NULL);

	// --- Import table hooks (for game's direct imports) ---
	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 12, (DWORD)NetDll_connectHook);
	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 24, (DWORD)NetDll_sendtoHook);
	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 25, (DWORD)NetDll_WSASendToHook);
	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 530, (DWORD)XamUserCheckPrivilegeHook);
	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 590, (DWORD)XamCreateEnumeratorHandleHook);
	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 592, (DWORD)XamEnumerateHook);
	XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, L"[DIAG] Imports patched", NULL);

	// --- PatchInJump hooks (patches actual xam.xex functions, affects ALL callers) ---

	// XNetGetTitleXnAddr (ordinal 73) — pure replacement, no trampoline needed
	DWORD* pXNetGetTitleXnAddr = (DWORD*)ResolveFunction(hXam, 73);
	if (pXNetGetTitleXnAddr != NULL) {
		PatchInJump(pXNetGetTitleXnAddr, (DWORD)XNetGetTitleXnAddrHook, FALSE);
		XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, L"[DIAG] Ord73 XnAddr OK", NULL);
	} else {
		XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, L"[DIAG] Ord73 FAILED", NULL);
	}

	// XNetGetEthernetLinkStatus (ordinal 75) — pure replacement
	DWORD* pXNetGetEthernetLinkStatus = (DWORD*)ResolveFunction(hXam, 75);
	if (pXNetGetEthernetLinkStatus != NULL) {
		PatchInJump(pXNetGetEthernetLinkStatus, (DWORD)XNetGetEthernetLinkStatusHook, FALSE);
		XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, L"[DIAG] Ord75 EthLink OK", NULL);
	} else {
		XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, L"[DIAG] Ord75 FAILED", NULL);
	}

	// XamUserGetSigninState (ordinal 528) — fake Live sign-in
	DWORD* pXamUserGetSigninState = (DWORD*)ResolveFunction(hXam, 528);
	if (pXamUserGetSigninState != NULL) {
		PatchInJump(pXamUserGetSigninState, (DWORD)XamUserGetSigninStateHook, FALSE);
		XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, L"[DIAG] Ord528 SignIn OK", NULL);
	} else {
		XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, L"[DIAG] Ord528 FAILED", NULL);
	}

	// --- XHttp hooks — the key hooks for Just Dance's HTTP traffic ---
	// Using PatchModuleImport (not PatchInJump) so we can call the original
	// function directly via saved pointer — no trampoline needed.

	// NetDll_XHttpConnect (ordinal 205) — redirect Ubisoft hostnames to local server
	g_origXHttpConnect = (pfnNetDll_XHttpConnect)ResolveFunction(hXam, 205);
	if (g_origXHttpConnect != NULL) {
		DWORD patchResult = PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 205, (DWORD)NetDll_XHttpConnectHook);
		if (patchResult == S_OK) {
			XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, L"[DIAG] Ord205 Import OK", NULL);
		} else {
			// PatchModuleImport failed — game may not import ordinal 205 directly.
			// Fall back to PatchInJump (no trampoline — for Ubisoft domains only,
			// non-Ubisoft calls will go through the unmodified original code path
			// since PatchInJump redirects ALL calls to our hook).
			PatchInJump((DWORD*)g_origXHttpConnect, (DWORD)NetDll_XHttpConnectHook, FALSE);
			g_origXHttpConnect = NULL; // Can't call original anymore — code is overwritten
			XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, L"[DIAG] Ord205 PatchJump", NULL);
		}
	} else {
		XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, L"[DIAG] Ord205 FAILED", NULL);
	}

	XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, L"[DIAG] All hooks done!", NULL);
}
