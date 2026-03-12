#include "stdafx.h"
#include "Sunrise2.h"
#include "Utilities.h"
#include "CoreHooks.h"

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
static const char* LOCAL_SERVER_IP = "192.168.50.47";

// ============================================================================
// HOOK_STATE — unhook-call-rehook helpers
//
// NO reentrancy guards.  On Xbox 360's multi-core PowerPC, each core has its
// own I-cache.  When we unhook (restore original bytes + dcbst/sync/isync),
// only THIS core's I-cache is flushed.  Another core calling the same function
// still sees the old I-cache entry (the hook jump) and enters our hook — but
// that's fine because the unhook writes the same bytes and the rehook is
// idempotent.  The critical point is we never return a FAILURE value
// (INVALID_SOCKET, -1) to a legitimate concurrent caller.
// ============================================================================

VOID HookState_Init(HOOK_STATE* hs, DWORD* pFunc, DWORD hookFn)
{
	hs->pFunction = pFunc;
	hs->hookTarget = hookFn;
	memcpy(hs->origCode, pFunc, 16);
	PatchInJump(pFunc, hookFn, FALSE);
	hs->installed = TRUE;
}

VOID HookState_Unhook(HOOK_STATE* hs)
{
	memcpy(hs->pFunction, hs->origCode, 16);
	__dcbst(0, hs->pFunction);
	__sync();
	__isync();
}

VOID HookState_Rehook(HOOK_STATE* hs)
{
	PatchInJump(hs->pFunction, hs->hookTarget, FALSE);
}

// Permanently remove a hook (restore original bytes, mark as not installed)
static VOID HookState_Remove(HOOK_STATE* hs)
{
	if (hs->installed) {
		HookState_Unhook(hs);
		hs->installed = FALSE;
	}
}

// Hook states for all PatchInJump hooks
static HOOK_STATE g_hookSocket       = {0};  // ordinal 3
static HOOK_STATE g_hookConnect      = {0};  // ordinal 12
static HOOK_STATE g_hookSendto       = {0};  // ordinal 24
static HOOK_STATE g_hookRecvfrom     = {0};  // ordinal 20
static HOOK_STATE g_hookXHttpConnect = {0};  // ordinal 205
static HOOK_STATE g_hookXHttpOpenReq = {0};  // ordinal 207
static HOOK_STATE g_hookXHttpSendReq = {0};  // ordinal 209
static HOOK_STATE g_hookXnAddr       = {0};  // ordinal 73
static HOOK_STATE g_hookEthLink      = {0};  // ordinal 75
static HOOK_STATE g_hookSigninState  = {0};  // ordinal 528
static HOOK_STATE g_hookLogonState   = {0};  // ordinal 322 (XNetLogonGetState)
static HOOK_STATE g_hookLogonNat     = {0};  // ordinal 302 (XNetLogonGetNatType)
static HOOK_STATE g_hookLogonStatus  = {0};  // ordinal 112 (XnpLogonGetStatus)
static HOOK_STATE g_hookXNetConnect  = {0};  // ordinal 65 (XNetConnect)
static HOOK_STATE g_hookXNetConnStat = {0};  // ordinal 66 (XNetGetConnectStatus)

// ============================================================================
// Side-channel UDP diagnostic logging
// Sends log messages to the PC server on port 19031 (separate from game data).
// Uses XNCALLER_SYSAPP — TITLE sockets fail before game calls XNetStartup.
// SYSAPP can create sockets but packets may not reach LAN (TBD).
// ============================================================================

static SOCKET g_logSocket = INVALID_SOCKET;
static SOCKADDR_IN g_logServerAddr;
static BOOL g_logInitialized = FALSE;

static void InitLogSocket()
{
	if (g_logInitialized) return;

	g_logSocket = NetDll_socket(XNCALLER_SYSAPP, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (g_logSocket == INVALID_SOCKET) return;

	memset(&g_logServerAddr, 0, sizeof(g_logServerAddr));
	g_logServerAddr.sin_family = AF_INET;
	g_logServerAddr.sin_port = htons(19031);
	g_logServerAddr.sin_addr.S_un.S_un_b.s_b1 = 192;
	g_logServerAddr.sin_addr.S_un.S_un_b.s_b2 = 168;
	g_logServerAddr.sin_addr.S_un.S_un_b.s_b3 = 50;
	g_logServerAddr.sin_addr.S_un.S_un_b.s_b4 = 47;
	g_logInitialized = TRUE;
}

static void LogToServer(const char* fmt, ...)
{
	if (!g_logInitialized) return;

	char buf[512];
	va_list args;
	va_start(args, fmt);
	int len = _vsnprintf(buf, sizeof(buf) - 1, fmt, args);
	va_end(args);
	if (len <= 0) return;
	buf[len] = '\0';

	NetDll_sendto(XNCALLER_SYSAPP, g_logSocket, buf, len, 0,
	              (VOID*)&g_logServerAddr, sizeof(g_logServerAddr));
}

static void LogPayloadToServer(const char* tag, const void* data, int dataLen)
{
	if (!g_logInitialized || dataLen <= 0) return;

	char buf[512];
	int offset = _snprintf(buf, sizeof(buf), "%s len=%d hex=", tag, dataLen);
	if (offset < 0) return;

	const BYTE* bytes = (const BYTE*)data;
	int maxBytes = dataLen > 64 ? 64 : dataLen;
	for (int i = 0; i < maxBytes && offset < (int)sizeof(buf) - 3; i++) {
		offset += _snprintf(buf + offset, sizeof(buf) - offset, "%02X", bytes[i]);
	}

	NetDll_sendto(XNCALLER_SYSAPP, g_logSocket, buf, offset, 0,
	              (VOID*)&g_logServerAddr, sizeof(g_logServerAddr));
}

// Forward declarations
static void TestTCPConnectivity();

// setsockopt resolved at runtime (ordinal 7, not in 21256 link library)
typedef int (*pfnNetDll_setsockopt)(XNCALLER_TYPE xnc, SOCKET s, int level, int optname, const char* optval, int optlen);
static pfnNetDll_setsockopt g_pfnSetsockopt = NULL;

// XNetSetOpt/XNetGetOpt resolved at runtime (ordinals 79/78)
typedef int (*pfnNetDll_XNetSetOpt)(XNCALLER_TYPE xnc, DWORD dwOptId, BYTE* pbValue, DWORD dwValueSize);
typedef int (*pfnNetDll_XNetGetOpt)(XNCALLER_TYPE xnc, DWORD dwOptId, BYTE* pbValue, DWORD* pdwValueSize);
static pfnNetDll_XNetSetOpt g_pfnXNetSetOpt = NULL;
static pfnNetDll_XNetGetOpt g_pfnXNetGetOpt = NULL;

#ifndef XNET_OPTID_NEUTERED
#define XNET_OPTID_NEUTERED 0x1389
#endif

// SO_MARKINSECURE / SO_GRANTINSECURE bypass XNet's security layer,
// allowing plain TCP to reach standard (non-Xbox) servers on LAN.
#ifndef SO_MARKINSECURE
#define SO_MARKINSECURE  0x5801
#endif
#ifndef SO_GRANTINSECURE
#define SO_GRANTINSECURE 0x5803
#endif

// ============================================================================
// Utility
// ============================================================================

static BOOL IsJDTitleActive()
{
	DWORD tid = XamGetCurrentTitleId();
	return (tid & 0xFFFF0000) == 0x55530000;
}

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
// PatchInJump socket hooks (system-wide)
//
// All hooks use unhook-call-rehook.  NO reentrancy guards — returning
// INVALID_SOCKET or -1 to concurrent system callers caused the hang.
// The I-cache race on multi-core PPC is benign (each core caches
// independently; a stale I-cache entry just means one extra pass through
// the hook, which is harmless).
//
// For hooks where LogToServer could recurse (sendto), we check
// XNCALLER_TYPE first and fast-path non-TITLE callers.
// ============================================================================

// --- NetDll_socket (ordinal 3) ---
// NOT HOOKED — marking all TITLE sockets insecure broke XNet initialization.
// Instead, we mark sockets insecure in the connect hook (ordinal 12) only
// when the destination is our server IP.

typedef SOCKET (*pfnNetDll_socket)(XNCALLER_TYPE xnc, int af, int type, int protocol);

// --- NetDll_connect (ordinal 12) ---
// NOT HOOKED — unhook-call-rehook on connect() crashes the system
// (same as socket/sendto/recvfrom — too frequently called by system services).
// Instead, we use XNetSetOpt(NEUTERED) in XHttpSendRequest to make
// XHttp's internal connections insecure.

typedef int (*pfnNetDll_connect)(XNCALLER_TYPE xnc, SOCKET s, const sockaddr* name, int namelen);

// --- NetDll_sendto (ordinal 24) ---
//
// LogToServer() calls NetDll_sendto with XNCALLER_SYSAPP.  When the hook is
// entered with SYSAPP, we skip logging and just call-through.  After unhook,
// LogToServer's sendto call hits the ORIGINAL function directly (hook bytes
// removed on this core's I-cache), so there is no infinite recursion.

typedef int (*pfnNetDll_sendto)(XNCALLER_TYPE xnc, SOCKET s, const VOID* buf, int len, int flags, VOID* to, int tolen);

static BOOL bSendtoHookFired = FALSE;

int NetDll_sendtoPIJHook(XNCALLER_TYPE xnc, SOCKET s, const VOID* buf, int len, int flags, VOID* to, int tolen)
{
	// Fast path for non-game callers (system services, our own LogToServer)
	if (xnc != XNCALLER_TITLE || to == NULL) {
		HookState_Unhook(&g_hookSendto);
		int result = ((pfnNetDll_sendto)(void*)g_hookSendto.pFunction)(xnc, s, buf, len, flags, to, tolen);
		HookState_Rehook(&g_hookSendto);
		return result;
	}

	// Game traffic — capture original destination for logging, then redirect
	SOCKADDR_IN* addr = (SOCKADDR_IN*)to;
	BYTE origIp[4];
	origIp[0] = addr->sin_addr.S_un.S_un_b.s_b1;
	origIp[1] = addr->sin_addr.S_un.S_un_b.s_b2;
	origIp[2] = addr->sin_addr.S_un.S_un_b.s_b3;
	origIp[3] = addr->sin_addr.S_un.S_un_b.s_b4;
	WORD origPort = ntohs(addr->sin_port);

	addr->sin_addr.S_un.S_addr = activeServer.inaServer.S_un.S_addr;
	addr->sin_port = htons(19030);

	// Unhook FIRST, then log.  LogToServer -> sendto hits the original
	// function directly (hook bytes removed on this core).
	HookState_Unhook(&g_hookSendto);

	LogToServer("SENDTO fd=%d ip=%d.%d.%d.%d port=%d len=%d",
		(int)s, origIp[0], origIp[1], origIp[2], origIp[3], origPort, len);

	if (buf != NULL && len > 0) {
		LogPayloadToServer("SENDTO_DATA", buf, len);
	}

	if (!bSendtoHookFired) {
		XNotify(L"[DIAG] sendto() called!");
		bSendtoHookFired = TRUE;
	}

	int result = ((pfnNetDll_sendto)(void*)g_hookSendto.pFunction)(xnc, s, buf, len, flags, to, tolen);
	HookState_Rehook(&g_hookSendto);
	return result;
}

// --- NetDll_recvfrom (ordinal 20) ---

typedef int (*pfnNetDll_recvfrom)(XNCALLER_TYPE xnc, SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);

int NetDll_recvfromPIJHook(XNCALLER_TYPE xnc, SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen)
{
	HookState_Unhook(&g_hookRecvfrom);
	int result = ((pfnNetDll_recvfrom)(void*)g_hookRecvfrom.pFunction)(xnc, s, buf, len, flags, from, fromlen);
	HookState_Rehook(&g_hookRecvfrom);

	if (xnc == XNCALLER_TITLE && result > 0) {
		LogToServer("RECVFROM fd=%d len=%d", (int)s, result);
		LogPayloadToServer("RECVFROM_DATA", buf, result);
	}

	return result;
}

// ============================================================================
// XHttp hooks — PatchInJump with unhook-call-rehook (system-wide)
// ============================================================================

// --- NetDll_XHttpConnect (ordinal 205) ---

typedef HINTERNET (*pfnNetDll_XHttpConnect)(XNCALLER_TYPE xnc, HINTERNET hSession, LPCSTR pszServerName, INTERNET_PORT nServerPort, DWORD dwFlags);

static BOOL bXHttpConnectHookFired = FALSE;
static int g_connectCount = 0;
HINTERNET NetDll_XHttpConnectHook(XNCALLER_TYPE xnc, HINTERNET hSession, LPCSTR pszServerName, INTERNET_PORT nServerPort, DWORD dwFlags)
{
	if (!bXHttpConnectHookFired) {
		XNotify(L"[DIAG] XHttpConnect!");
		bXHttpConnectHookFired = TRUE;

		// Game networking is now initialized — run deferred TCP test
		TestTCPConnectivity();
	}

	// Show domain in toast for every connect (truncated to fit)
	if (pszServerName != NULL) {
		wchar_t dmsg[48];
		int dp = 0;
		const wchar_t* prefix = L"[C] ";
		while (*prefix && dp < 4) dmsg[dp++] = *prefix++;
		for (int i = 0; pszServerName[i] && dp < 44; i++)
			dmsg[dp++] = (wchar_t)pszServerName[i];
		dmsg[dp] = 0;
		XNotify(dmsg);

		LogToServer("XHTTP_CONNECT host=%s port=%d flags=0x%08X", pszServerName, nServerPort, dwFlags);
	}
	g_connectCount++;

	// Redirect Ubisoft domains to our local server IP.
	// With the socket hook marking all TITLE sockets as insecure,
	// XHttp's internal connection should reach the PC via plain TCP.
	if (pszServerName != NULL && ShouldRedirectDomain(pszServerName))
	{
		LogToServer("XHTTP_REDIRECT %s -> %s:80", pszServerName, LOCAL_SERVER_IP);
		XNotify(L"HTTP Redirected!");

		HookState_Unhook(&g_hookXHttpConnect);
		HINTERNET result = ((pfnNetDll_XHttpConnect)(void*)g_hookXHttpConnect.pFunction)(
			xnc, hSession, LOCAL_SERVER_IP, 80, dwFlags & ~XHTTP_FLAG_SECURE);
		HookState_Rehook(&g_hookXHttpConnect);
		return result;
	}

	HookState_Unhook(&g_hookXHttpConnect);
	HINTERNET result = ((pfnNetDll_XHttpConnect)(void*)g_hookXHttpConnect.pFunction)(
		xnc, hSession, pszServerName, nServerPort, dwFlags);
	HookState_Rehook(&g_hookXHttpConnect);
	return result;
}

// --- NetDll_XHttpOpenRequest (ordinal 207) ---

typedef HINTERNET (*pfnNetDll_XHttpOpenRequest)(XNCALLER_TYPE xnc, HINTERNET hConnect,
	LPCSTR pwszVerb, LPCSTR pwszObjectName, LPCSTR pwszVersion,
	LPCSTR pwszReferrer, LPCSTR* ppwszAcceptTypes, DWORD dwFlags);

static BOOL bXHttpOpenReqHookFired = FALSE;
HINTERNET NetDll_XHttpOpenRequestHook(XNCALLER_TYPE xnc, HINTERNET hConnect,
	LPCSTR pwszVerb, LPCSTR pwszObjectName, LPCSTR pwszVersion,
	LPCSTR pwszReferrer, LPCSTR* ppwszAcceptTypes, DWORD dwFlags)
{
	if (pwszVerb != NULL && pwszObjectName != NULL) {
		LogToServer("XHTTP_OPENREQ verb=%s path=%s flags=0x%08X", pwszVerb, pwszObjectName, dwFlags);

		// Show verb+path in toast for every request (truncated to fit)
		wchar_t rmsg[48];
		int rp = 0;
		const wchar_t* rprefix = L"[R] ";
		while (*rprefix && rp < 4) rmsg[rp++] = *rprefix++;
		for (int i = 0; pwszVerb[i] && rp < 8; i++)
			rmsg[rp++] = (wchar_t)pwszVerb[i];
		rmsg[rp++] = L' ';
		for (int i = 0; pwszObjectName[i] && rp < 46; i++)
			rmsg[rp++] = (wchar_t)pwszObjectName[i];
		rmsg[rp] = 0;
		XNotify(rmsg);
	}

	if (!bXHttpOpenReqHookFired) {
		bXHttpOpenReqHookFired = TRUE;
	}

	dwFlags &= ~XHTTP_FLAG_SECURE;

	HookState_Unhook(&g_hookXHttpOpenReq);
	HINTERNET result = ((pfnNetDll_XHttpOpenRequest)(void*)g_hookXHttpOpenReq.pFunction)(
		xnc, hConnect, pwszVerb, pwszObjectName, pwszVersion,
		pwszReferrer, ppwszAcceptTypes, dwFlags);
	HookState_Rehook(&g_hookXHttpOpenReq);
	return result;
}

// --- NetDll_XHttpSendRequest (ordinal 209) ---

typedef DWORD (*pfnNetDll_XHttpSendRequest)(XNCALLER_TYPE xnc, HINTERNET hRequest,
	LPCSTR pwszHeaders, DWORD dwHeadersLength, const VOID* lpOptional,
	DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext);

static BOOL bXHttpSendReqHookFired = FALSE;
DWORD NetDll_XHttpSendRequestHook(XNCALLER_TYPE xnc, HINTERNET hRequest,
	LPCSTR pwszHeaders, DWORD dwHeadersLength, const VOID* lpOptional,
	DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext)
{
	if (!bXHttpSendReqHookFired) {
		XNotify(L"[DIAG] XHttpSendRequest!");
		bXHttpSendReqHookFired = TRUE;
	}

	LogToServer("XHTTP_SEND hdrs_len=%d body_len=%d total_len=%d", dwHeadersLength, dwOptionalLength, dwTotalLength);

	if (pwszHeaders != NULL && dwHeadersLength > 0) {
		int logLen = dwHeadersLength > 400 ? 400 : dwHeadersLength;
		char hdrBuf[410];
		memcpy(hdrBuf, pwszHeaders, logLen);
		hdrBuf[logLen] = '\0';
		LogToServer("XHTTP_HDRS %s", hdrBuf);
	}

	// Temporarily put XNet in "neutered" (insecure) mode while XHttp
	// makes its internal connection.  This makes XHttp's internally-created
	// sockets bypass XNet security, allowing plain TCP to our LAN server.
	// We can't hook socket/connect directly (crashes the system), so this
	// is the only way to make XHttp's connections insecure.
	DWORD savedNeutered = 0;
	DWORD savedSize = sizeof(savedNeutered);
	BOOL didSetNeutered = FALSE;

	if (g_pfnXNetSetOpt && g_pfnXNetGetOpt) {
		// Save current value
		g_pfnXNetGetOpt(xnc, XNET_OPTID_NEUTERED, (BYTE*)&savedNeutered, &savedSize);
		// Enable neutered (insecure) mode
		DWORD neutered = 1;
		int setResult = g_pfnXNetSetOpt(xnc, XNET_OPTID_NEUTERED, (BYTE*)&neutered, sizeof(neutered));
		if (setResult == 0) {
			didSetNeutered = TRUE;
			XNotify(L"[DIAG] XNet neutered ON");
		}
	}

	HookState_Unhook(&g_hookXHttpSendReq);
	DWORD result = ((pfnNetDll_XHttpSendRequest)(void*)g_hookXHttpSendReq.pFunction)(
		xnc, hRequest, pwszHeaders, dwHeadersLength, lpOptional,
		dwOptionalLength, dwTotalLength, dwContext);
	HookState_Rehook(&g_hookXHttpSendReq);

	// Restore original neutered state
	if (didSetNeutered) {
		g_pfnXNetSetOpt(xnc, XNET_OPTID_NEUTERED, (BYTE*)&savedNeutered, sizeof(savedNeutered));
	}

	return result;
}

// ============================================================================
// Privilege / Enumerator hooks (PatchModuleImport — game imports only)
// ============================================================================

static BOOL bPrivilegeHookFired = FALSE;
DWORD XamUserCheckPrivilegeHook(DWORD dwUserIndex, DWORD dwPrivilegeType, PBOOL pfResult)
{
	if (!bPrivilegeHookFired) {
		XNotify(L"[DIAG] Privilege called!");
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
		XNotify(L"[DIAG] EnumCreate called!");
		bEnumCreateHookFired = TRUE;
	}
	int result = XamCreateEnumeratorHandle(user_index, app_id, open_message, close_message, extra_size, item_count, flags, out_handle);

	LogToServer("ENUM_CREATE app_id=0x%08X open_msg=0x%08X result=%d", (DWORD)app_id, open_message, result);

	if (open_message == 0x58039 || ((DWORD)app_id & 0xFFFF0000) == 0x55530000) {
		lsp_enum_handle = *out_handle;
		enumeration_index = 0;
		LogToServer("LSP_INTERCEPT handle=0x%08X", (DWORD)lsp_enum_handle);
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

		LogToServer("LSP_ENUMERATE returning server info, errorCode=%d", errorCode);

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
// XNet status hooks — call through to original for non-JD titles
// ============================================================================

typedef DWORD (*pfnXNetGetTitleXnAddr)(XNCALLER_TYPE xnc, XNADDR* pxna);

static BOOL bXnAddrHookFired = FALSE;
DWORD XNetGetTitleXnAddrHook(XNCALLER_TYPE xnc, XNADDR* pxna)
{
	if (!bXnAddrHookFired) {
		XNotify(L"[DIAG] XnAddr called!");
		bXnAddrHookFired = TRUE;
	}

	if (!IsJDTitleActive()) {
		HookState_Unhook(&g_hookXnAddr);
		DWORD result = ((pfnXNetGetTitleXnAddr)(void*)g_hookXnAddr.pFunction)(xnc, pxna);
		HookState_Rehook(&g_hookXnAddr);
		return result;
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

typedef DWORD (*pfnXNetGetEthernetLinkStatus)(XNCALLER_TYPE xnc);

static BOOL bEthLinkHookFired = FALSE;
DWORD XNetGetEthernetLinkStatusHook(XNCALLER_TYPE xnc)
{
	if (!bEthLinkHookFired) {
		XNotify(L"[DIAG] EthLink called!");
		bEthLinkHookFired = TRUE;
	}

	if (!IsJDTitleActive()) {
		HookState_Unhook(&g_hookEthLink);
		DWORD result = ((pfnXNetGetEthernetLinkStatus)(void*)g_hookEthLink.pFunction)(xnc);
		HookState_Rehook(&g_hookEthLink);
		return result;
	}

	return XNET_ETHERNET_LINK_ACTIVE | XNET_ETHERNET_LINK_100MBPS | XNET_ETHERNET_LINK_FULL_DUPLEX;
}

typedef DWORD (*pfnXamUserGetSigninState)(DWORD dwUserIndex);

static BOOL bSigninHookFired = FALSE;
DWORD XamUserGetSigninStateHook(DWORD dwUserIndex)
{
	if (!bSigninHookFired) {
		XNotify(L"[DIAG] SignIn called!");
		bSigninHookFired = TRUE;
	}

	if (!IsJDTitleActive()) {
		HookState_Unhook(&g_hookSigninState);
		DWORD result = ((pfnXamUserGetSigninState)(void*)g_hookSigninState.pFunction)(dwUserIndex);
		HookState_Rehook(&g_hookSigninState);
		return result;
	}

	if (dwUserIndex == 0)
		return 2; // eXamUserSigninState_SignedInToLive
	return 0; // eXamUserSigninState_NotSignedIn
}

// ============================================================================
// Xbox Live Logon state hooks — spoof "online" for all callers
//
// These functions are called by the game BEFORE making any HTTP calls.
// If they report "not connected", the game shows "connection error" and
// never reaches the UbiServices HTTP layer.
// Signatures are undocumented — on PPC, unused register params are harmless.
// ============================================================================

// --- XNetLogonGetState (ordinal 322) ---
// Returns Xbox Live logon state. We return a value indicating "logged on".

static BOOL bLogonStateHookFired = FALSE;
DWORD XNetLogonGetStateHook()
{
	if (!bLogonStateHookFired) {
		XNotify(L"[DIAG] LogonState called!");
		bLogonStateHookFired = TRUE;
	}
	// Common XDK values: 0=offline, 1=connecting, 2=online
	// Return "online" so game proceeds to HTTP calls
	return 2;
}

// --- XNetLogonGetNatType (ordinal 302) ---
// Returns NAT type. Games may refuse to go online with strict NAT.

static BOOL bLogonNatHookFired = FALSE;
DWORD XNetLogonGetNatTypeHook()
{
	if (!bLogonNatHookFired) {
		XNotify(L"[DIAG] NatType called!");
		bLogonNatHookFired = TRUE;
	}
	// XONLINE_NAT_OPEN = 1, MODERATE = 2, STRICT = 3
	return 1; // Open NAT
}

// --- NetDll_XnpLogonGetStatus (ordinal 112) ---
// Internal logon status. Returns 0 for success.

static BOOL bLogonStatusHookFired = FALSE;
DWORD XnpLogonGetStatusHook(DWORD xnc)
{
	if (!bLogonStatusHookFired) {
		XNotify(L"[DIAG] LogonStatus called!");
		bLogonStatusHookFired = TRUE;
	}
	// Return 0 (success/connected)
	return 0;
}

// --- NetDll_XNetConnect (ordinal 65) ---
// Initiates an XNet secure connection (IPSec tunnel) to a peer/server.
// The Quazal RendezVous SDK calls this in JobGetLSPTunnel::SecureConnect.
// We return 0 (success) immediately — no real tunnel is needed since we
// redirect traffic to a plain LAN server via NEUTERED mode.

static BOOL bXNetConnectHookFired = FALSE;
int XNetConnectHook(XNCALLER_TYPE xnc, const IN_ADDR ina)
{
	if (!bXNetConnectHookFired) {
		XNotify(L"[DIAG] XNetConnect called!");
		bXNetConnectHookFired = TRUE;
	}
	LogToServer("XNETCONNECT ip=%d.%d.%d.%d",
		ina.S_un.S_un_b.s_b1, ina.S_un.S_un_b.s_b2,
		ina.S_un.S_un_b.s_b3, ina.S_un.S_un_b.s_b4);
	return 0; // Success — pretend tunnel is initiated
}

// --- NetDll_XNetGetConnectStatus (ordinal 66) ---
// Polls XNet secure connection status. The Quazal SDK spins on this in
// JobGetLSPTunnel::StepXNetGetConnectStatus until it returns CONNECTED.
// XNET_CONNECT_STATUS values: 0=IDLE, 1=PENDING, 2=CONNECTED, 3=LOST

static BOOL bXNetConnStatHookFired = FALSE;
DWORD XNetGetConnectStatusHook(XNCALLER_TYPE xnc, const IN_ADDR ina)
{
	if (!bXNetConnStatHookFired) {
		XNotify(L"[DIAG] XNetGetConnStat!");
		bXNetConnStatHookFired = TRUE;
	}
	return 2; // XNET_CONNECT_STATUS_CONNECTED
}

// ============================================================================
// Hook setup — installs all hooks
// ============================================================================

static BOOL g_hooksInstalled = FALSE;
static BOOL g_tcpTestDone = FALSE;

// TCP connectivity test — tries raw socket connection to the PC
// Tests 4 combinations: {TITLE,SYSAPP} x {insecure, normal}
// Runs in its own thread to avoid blocking the XHttpConnect hook
static DWORD WINAPI TCPTestThread(LPVOID)
{
	// Resolve setsockopt at runtime
	if (!g_pfnSetsockopt) {
		HMODULE hXam = GetModuleHandle(MODULE_XAM);
		if (hXam) g_pfnSetsockopt = (pfnNetDll_setsockopt)ResolveFunction(hXam, 7);
	}

	SOCKADDR_IN addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(80);
	addr.sin_addr.S_un.S_un_b.s_b1 = 192;
	addr.sin_addr.S_un.S_un_b.s_b2 = 168;
	addr.sin_addr.S_un.S_un_b.s_b3 = 50;
	addr.sin_addr.S_un.S_un_b.s_b4 = 47;

	// Test plan: try insecure socket first (most likely to work), then normal
	struct { XNCALLER_TYPE xnc; BOOL insecure; const wchar_t* label; } tests[] = {
		{ XNCALLER_TITLE,  TRUE,  L"TITLE+INSEC"  },
		{ XNCALLER_SYSAPP, TRUE,  L"SYSAPP+INSEC" },
		{ XNCALLER_TITLE,  FALSE, L"TITLE"        },
		{ XNCALLER_SYSAPP, FALSE, L"SYSAPP"       },
	};

	for (int t = 0; t < 4; t++) {
		SOCKET s = NetDll_socket(tests[t].xnc, AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (s == INVALID_SOCKET) continue;

		// Try marking socket as insecure (bypass XNet security)
		if (tests[t].insecure && g_pfnSetsockopt) {
			BOOL val = TRUE;
			g_pfnSetsockopt(tests[t].xnc, s, SOL_SOCKET, SO_MARKINSECURE, (const char*)&val, sizeof(val));
			g_pfnSetsockopt(tests[t].xnc, s, SOL_SOCKET, SO_GRANTINSECURE, (const char*)&val, sizeof(val));
		}

		// Build toast: "[TCP] <label>..."
		wchar_t msg[48]; int pos = 0;
		const wchar_t* p = L"[TCP] "; while (*p) msg[pos++] = *p++;
		p = tests[t].label; while (*p) msg[pos++] = *p++;
		msg[pos++] = L'.'; msg[pos++] = L'.'; msg[pos++] = L'.'; msg[pos] = 0;
		XNotify(msg);

		int result = NetDll_connect(tests[t].xnc, s, (sockaddr*)&addr, sizeof(addr));
		if (result == 0) {
			// Build success toast
			pos = 0;
			p = L"[TCP] "; while (*p) msg[pos++] = *p++;
			p = tests[t].label; while (*p) msg[pos++] = *p++;
			p = L" OK!"; while (*p) msg[pos++] = *p++;
			msg[pos] = 0;
			XNotify(msg);

			const char* httpReq = "GET / HTTP/1.0\r\nHost: 192.168.50.47\r\n\r\n";
			NetDll_send(tests[t].xnc, s, httpReq, (int)strlen(httpReq), 0);

			char respBuf[64];
			memset(respBuf, 0, sizeof(respBuf));
			int recvd = NetDll_recv(tests[t].xnc, s, respBuf, sizeof(respBuf) - 1, 0);
			XNotify(recvd > 0 ? L"[TCP] HTTP recv OK!" : L"[TCP] HTTP recv fail");

			NetDll_closesocket(tests[t].xnc, s);
			return 0; // Success — stop testing
		} else {
			int err = NetDll_WSAGetLastError();
			// Build error toast: "[TCP] <label> err=NNNNN"
			pos = 0;
			p = L"[TCP] "; while (*p) msg[pos++] = *p++;
			p = tests[t].label; while (*p) msg[pos++] = *p++;
			p = L" err="; while (*p) msg[pos++] = *p++;
			char digits[12]; int dpos = 0;
			int val = err < 0 ? -err : err;
			if (err < 0) msg[pos++] = L'-';
			if (val == 0) { digits[dpos++] = '0'; }
			else { while (val > 0) { digits[dpos++] = '0' + (val % 10); val /= 10; } }
			for (int i = dpos - 1; i >= 0; i--) msg[pos++] = (wchar_t)digits[i];
			msg[pos] = 0;
			XNotify(msg);
			NetDll_closesocket(tests[t].xnc, s);
		}
	}

	XNotify(L"[TCP] All 4 FAIL");
	return 0;
}

static void TestTCPConnectivity()
{
	if (g_tcpTestDone) return;
	g_tcpTestDone = TRUE;

	XNotify(L"[DIAG] TCP test...");
	// Launch in a separate thread so we don't block the XHttp hook
	ThreadMe((LPTHREAD_START_ROUTINE)TCPTestThread);
}

VOID SetupNetDllHooks()
{
	if (g_hooksInstalled) {
		XNotify(L"[DIAG] Hooks already installed");
		return;
	}

	XNotify(L"[DIAG] SetupHooks Entry");

	HMODULE hXam = GetModuleHandle(MODULE_XAM);
	if (hXam == NULL) {
		XNotify(L"[DIAG] hXam is NULL!");
		return;
	}

	// Initialize diagnostic logging socket first (before any hooks)
	InitLogSocket();
	if (g_logInitialized) {
		LogToServer("INIT SetupNetDllHooks starting");
		XNotify(L"[DIAG] LogSocket OK");
	} else {
		XNotify(L"[DIAG] LogSocket FAILED");
	}

	DWORD* pAddr;

	// ---- Resolve setsockopt at runtime (ordinal 7, not in 21256 link lib) ----
	if (!g_pfnSetsockopt) {
		g_pfnSetsockopt = (pfnNetDll_setsockopt)ResolveFunction(hXam, 7);
		if (g_pfnSetsockopt) {
			XNotify(L"[DIAG] setsockopt resolved");
		} else {
			XNotify(L"[DIAG] setsockopt FAIL");
		}
	}

	// ---- Resolve XNetSetOpt/XNetGetOpt at runtime (ordinals 79/78) ----
	if (!g_pfnXNetSetOpt) {
		g_pfnXNetSetOpt = (pfnNetDll_XNetSetOpt)ResolveFunction(hXam, 79);
		g_pfnXNetGetOpt = (pfnNetDll_XNetGetOpt)ResolveFunction(hXam, 78);
		if (g_pfnXNetSetOpt && g_pfnXNetGetOpt) {
			XNotify(L"[DIAG] XNetSetOpt resolved");
		} else {
			XNotify(L"[DIAG] XNetSetOpt FAIL");
		}
	}

	// ---- PatchInJump hooks on XHttp functions (system-wide) ----

	pAddr = (DWORD*)ResolveFunction(hXam, 205);
	if (pAddr) {
		HookState_Init(&g_hookXHttpConnect, pAddr, (DWORD)NetDll_XHttpConnectHook);
		LogToServer("HOOK ord205 XHttpConnect OK at 0x%08X", (DWORD)pAddr);
		XNotify(L"[DIAG] Hook ord205 OK");
	} else {
		XNotify(L"[DIAG] ord205 resolve FAIL");
	}

	pAddr = (DWORD*)ResolveFunction(hXam, 207);
	if (pAddr) {
		HookState_Init(&g_hookXHttpOpenReq, pAddr, (DWORD)NetDll_XHttpOpenRequestHook);
		LogToServer("HOOK ord207 XHttpOpenRequest OK at 0x%08X", (DWORD)pAddr);
		XNotify(L"[DIAG] Hook ord207 OK");
	} else {
		XNotify(L"[DIAG] ord207 resolve FAIL");
	}

	pAddr = (DWORD*)ResolveFunction(hXam, 209);
	if (pAddr) {
		HookState_Init(&g_hookXHttpSendReq, pAddr, (DWORD)NetDll_XHttpSendRequestHook);
		LogToServer("HOOK ord209 XHttpSendRequest OK at 0x%08X", (DWORD)pAddr);
		XNotify(L"[DIAG] Hook ord209 OK");
	} else {
		XNotify(L"[DIAG] ord209 resolve FAIL");
	}

	// ---- PatchInJump hooks with title-active gating ----

	pAddr = (DWORD*)ResolveFunction(hXam, 73);
	if (pAddr) {
		HookState_Init(&g_hookXnAddr, pAddr, (DWORD)XNetGetTitleXnAddrHook);
		LogToServer("HOOK ord73 XnAddr OK at 0x%08X", (DWORD)pAddr);
	}

	pAddr = (DWORD*)ResolveFunction(hXam, 75);
	if (pAddr) {
		HookState_Init(&g_hookEthLink, pAddr, (DWORD)XNetGetEthernetLinkStatusHook);
		LogToServer("HOOK ord75 EthLink OK at 0x%08X", (DWORD)pAddr);
	}

	pAddr = (DWORD*)ResolveFunction(hXam, 528);
	if (pAddr) {
		HookState_Init(&g_hookSigninState, pAddr, (DWORD)XamUserGetSigninStateHook);
		LogToServer("HOOK ord528 SignIn OK at 0x%08X", (DWORD)pAddr);
	}

	// ---- Xbox Live logon state hooks (spoof "online") ----

	pAddr = (DWORD*)ResolveFunction(hXam, 322);
	if (pAddr) {
		HookState_Init(&g_hookLogonState, pAddr, (DWORD)XNetLogonGetStateHook);
		LogToServer("HOOK ord322 LogonState OK at 0x%08X", (DWORD)pAddr);
		XNotify(L"[DIAG] Hook ord322 OK");
	} else {
		XNotify(L"[DIAG] ord322 resolve FAIL");
	}

	pAddr = (DWORD*)ResolveFunction(hXam, 302);
	if (pAddr) {
		HookState_Init(&g_hookLogonNat, pAddr, (DWORD)XNetLogonGetNatTypeHook);
		LogToServer("HOOK ord302 NatType OK at 0x%08X", (DWORD)pAddr);
		XNotify(L"[DIAG] Hook ord302 OK");
	} else {
		XNotify(L"[DIAG] ord302 resolve FAIL");
	}

	pAddr = (DWORD*)ResolveFunction(hXam, 112);
	if (pAddr) {
		HookState_Init(&g_hookLogonStatus, pAddr, (DWORD)XnpLogonGetStatusHook);
		LogToServer("HOOK ord112 LogonStatus OK at 0x%08X", (DWORD)pAddr);
		XNotify(L"[DIAG] Hook ord112 OK");
	} else {
		XNotify(L"[DIAG] ord112 resolve FAIL");
	}

	// ---- XNet connection hooks (spoof secure tunnel) ----

	pAddr = (DWORD*)ResolveFunction(hXam, 65);
	if (pAddr) {
		HookState_Init(&g_hookXNetConnect, pAddr, (DWORD)XNetConnectHook);
		LogToServer("HOOK ord65 XNetConnect OK at 0x%08X", (DWORD)pAddr);
		XNotify(L"[DIAG] Hook ord65 OK");
	} else {
		XNotify(L"[DIAG] ord65 resolve FAIL");
	}

	pAddr = (DWORD*)ResolveFunction(hXam, 66);
	if (pAddr) {
		HookState_Init(&g_hookXNetConnStat, pAddr, (DWORD)XNetGetConnectStatusHook);
		LogToServer("HOOK ord66 XNetGetConnStat OK at 0x%08X", (DWORD)pAddr);
		XNotify(L"[DIAG] Hook ord66 OK");
	} else {
		XNotify(L"[DIAG] ord66 resolve FAIL");
	}

	// ---- Import table hooks (game imports only) ----

	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 530, (DWORD)XamUserCheckPrivilegeHook);
	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 590, (DWORD)XamCreateEnumeratorHandleHook);
	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 592, (DWORD)XamEnumerateHook);
	LogToServer("HOOK imports (530,590,592) patched");

	g_hooksInstalled = TRUE;
	LogToServer("INIT SetupNetDllHooks complete - all hooks installed");
	XNotify(L"[DIAG] All hooks done!");
}

// ============================================================================
// Hook teardown — removes all PatchInJump hooks (called on game exit)
// Import table hooks don't need removal — they die with the game module.
// ============================================================================

VOID TeardownNetDllHooks()
{
	if (!g_hooksInstalled) return;

	HookState_Remove(&g_hookXHttpConnect);
	HookState_Remove(&g_hookXHttpOpenReq);
	HookState_Remove(&g_hookXHttpSendReq);
	HookState_Remove(&g_hookXnAddr);
	HookState_Remove(&g_hookEthLink);
	HookState_Remove(&g_hookSigninState);
	HookState_Remove(&g_hookLogonState);
	HookState_Remove(&g_hookLogonNat);
	HookState_Remove(&g_hookLogonStatus);
	HookState_Remove(&g_hookXNetConnect);
	HookState_Remove(&g_hookXNetConnStat);

	// Close diagnostic socket
	if (g_logInitialized && g_logSocket != INVALID_SOCKET) {
		NetDll_closesocket(XNCALLER_SYSAPP, g_logSocket);
		g_logSocket = INVALID_SOCKET;
		g_logInitialized = FALSE;
	}

	// Reset one-shot toast flags for next launch
	bXHttpConnectHookFired = FALSE;
	bXHttpOpenReqHookFired = FALSE;
	bXHttpSendReqHookFired = FALSE;
	bXnAddrHookFired = FALSE;
	bEthLinkHookFired = FALSE;
	bSigninHookFired = FALSE;
	bPrivilegeHookFired = FALSE;
	bEnumCreateHookFired = FALSE;
	bLogonStateHookFired = FALSE;
	bLogonNatHookFired = FALSE;
	bLogonStatusHookFired = FALSE;
	bXNetConnectHookFired = FALSE;
	bXNetConnStatHookFired = FALSE;
	g_tcpTestDone = FALSE;

	g_hooksInstalled = FALSE;
	XNotify(L"[DIAG] Hooks removed");
}
