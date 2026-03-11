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
static const char* LOCAL_SERVER_IP = "192.168.50.228";

// ============================================================================
// HOOK_STATE — reusable unhook-call-rehook helpers
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

// Hook states for all PatchInJump hooks that need call-through
static HOOK_STATE g_hookSocket      = {0};  // ordinal 3
static HOOK_STATE g_hookConnect     = {0};  // ordinal 12
static HOOK_STATE g_hookSendto      = {0};  // ordinal 24
static HOOK_STATE g_hookRecvfrom    = {0};  // ordinal 20
static HOOK_STATE g_hookXHttpConnect = {0}; // ordinal 205
static HOOK_STATE g_hookXHttpOpenReq = {0}; // ordinal 207
static HOOK_STATE g_hookXHttpSendReq = {0}; // ordinal 209

// ============================================================================
// Side-channel UDP diagnostic logging
// Sends log messages to the PC server on port 19031 (separate from game data).
// Uses XNCALLER_SYSAPP so our own hooks (which filter XNCALLER_TITLE) skip it.
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
	g_logServerAddr.sin_addr.S_un.S_un_b.s_b4 = 228;
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

// ============================================================================
// Utility
// ============================================================================

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
// PatchInJump socket hooks (system-wide — catches Quazal internal calls)
//
// IMPORTANT: LogToServer() calls NetDll_sendto internally, so the sendto
// hook MUST guard against recursion. We use a per-hook volatile guard flag
// checked at the TOP of each hook — if re-entered, skip straight to the
// original function without touching HOOK_STATE (which would corrupt the
// outer call's unhook-rehook sequence).
// ============================================================================

// --- NetDll_socket (ordinal 3) — diagnostic: log all socket creation ---

typedef SOCKET (*pfnNetDll_socket)(XNCALLER_TYPE xnc, int af, int type, int protocol);

static BOOL bSocketHookFired = FALSE;
static volatile BOOL g_inSocketHook = FALSE;

SOCKET NetDll_socketPIJHook(XNCALLER_TYPE xnc, int af, int type, int protocol)
{
	// Reentrancy guard (same-thread only)
	if (g_inSocketHook) return INVALID_SOCKET;
	g_inSocketHook = TRUE;

	HookState_Unhook(&g_hookSocket);
	SOCKET result = ((pfnNetDll_socket)(void*)g_hookSocket.pFunction)(xnc, af, type, protocol);
	HookState_Rehook(&g_hookSocket);

	if (xnc == XNCALLER_TITLE) {
		LogToServer("SOCKET af=%d type=%d proto=%d fd=%d", af, type, protocol, (int)result);

		if (!bSocketHookFired) {
			XNotify(L"[DIAG] socket() called!");
			bSocketHookFired = TRUE;
		}
	}

	g_inSocketHook = FALSE;
	return result;
}

// --- NetDll_connect (ordinal 12) — redirect + log all TCP connections ---

typedef int (*pfnNetDll_connect)(XNCALLER_TYPE xnc, SOCKET s, const sockaddr* name, int namelen);

static BOOL bConnectHookFired = FALSE;
static volatile BOOL g_inConnectHook = FALSE;

int NetDll_connectPIJHook(XNCALLER_TYPE xnc, SOCKET s, const sockaddr* name, int namelen)
{
	if (g_inConnectHook) return -1;
	g_inConnectHook = TRUE;

	// Redirect destination IP before calling original
	if (xnc == XNCALLER_TITLE && name != NULL && namelen >= (int)sizeof(SOCKADDR_IN)) {
		SOCKADDR_IN* addr = (SOCKADDR_IN*)name;
		LogToServer("CONNECT fd=%d ip=%d.%d.%d.%d port=%d",
			(int)s,
			addr->sin_addr.S_un.S_un_b.s_b1,
			addr->sin_addr.S_un.S_un_b.s_b2,
			addr->sin_addr.S_un.S_un_b.s_b3,
			addr->sin_addr.S_un.S_un_b.s_b4,
			ntohs(addr->sin_port));

		if (!bConnectHookFired) {
			XNotify(L"[DIAG] connect() called!");
			bConnectHookFired = TRUE;
		}

		addr->sin_addr.S_un.S_addr = activeServer.inaServer.S_un.S_addr;
	}

	HookState_Unhook(&g_hookConnect);
	int result = ((pfnNetDll_connect)(void*)g_hookConnect.pFunction)(xnc, s, name, namelen);
	HookState_Rehook(&g_hookConnect);

	g_inConnectHook = FALSE;
	return result;
}

// --- NetDll_sendto (ordinal 24) — redirect + log UDP packets (PRUDP) ---

typedef int (*pfnNetDll_sendto)(XNCALLER_TYPE xnc, SOCKET s, const VOID* buf, int len, int flags, VOID* to, int tolen);

static BOOL bSendtoHookFired = FALSE;
static volatile BOOL g_inSendtoHook = FALSE;

int NetDll_sendtoPIJHook(XNCALLER_TYPE xnc, SOCKET s, const VOID* buf, int len, int flags, VOID* to, int tolen)
{
	// CRITICAL: LogToServer() calls NetDll_sendto — must guard against recursion.
	// If re-entered, the original function bytes are restored (we're inside the
	// unhook'd window), so we can safely call through pFunction.
	if (g_inSendtoHook) {
		// Recursive call (from LogToServer during unhook'd window).
		// Original bytes are restored, safe to call through.
		return ((pfnNetDll_sendto)(void*)g_hookSendto.pFunction)(xnc, s, buf, len, flags, to, tolen);
	}
	g_inSendtoHook = TRUE;

	// Capture original destination for logging before we modify it
	BYTE origIp[4] = {0};
	WORD origPort = 0;
	BOOL isTitleCall = (xnc == XNCALLER_TITLE && to != NULL);

	if (isTitleCall) {
		SOCKADDR_IN* addr = (SOCKADDR_IN*)to;
		origIp[0] = addr->sin_addr.S_un.S_un_b.s_b1;
		origIp[1] = addr->sin_addr.S_un.S_un_b.s_b2;
		origIp[2] = addr->sin_addr.S_un.S_un_b.s_b3;
		origIp[3] = addr->sin_addr.S_un.S_un_b.s_b4;
		origPort = ntohs(addr->sin_port);

		// Redirect destination to our server
		addr->sin_addr.S_un.S_addr = activeServer.inaServer.S_un.S_addr;
		addr->sin_port = htons(19030);
	}

	// Unhook first, then log (so LogToServer's recursive sendto hits
	// the original function directly), then call original, then rehook.
	HookState_Unhook(&g_hookSendto);

	// Log DURING the unhook'd window — LogToServer()->NetDll_sendto() will
	// re-enter this hook, hit the reentrancy guard, and call the original
	// function (whose bytes are currently restored).
	if (isTitleCall) {
		LogToServer("SENDTO fd=%d ip=%d.%d.%d.%d port=%d len=%d",
			(int)s, origIp[0], origIp[1], origIp[2], origIp[3], origPort, len);

		if (buf != NULL && len > 0) {
			LogPayloadToServer("SENDTO_DATA", buf, len);
		}

		if (!bSendtoHookFired) {
			XNotify(L"[DIAG] sendto() called!");
			bSendtoHookFired = TRUE;
		}
	}

	int result = ((pfnNetDll_sendto)(void*)g_hookSendto.pFunction)(xnc, s, buf, len, flags, to, tolen);
	HookState_Rehook(&g_hookSendto);

	g_inSendtoHook = FALSE;
	return result;
}

// --- NetDll_recvfrom (ordinal 20) — log incoming UDP data ---

typedef int (*pfnNetDll_recvfrom)(XNCALLER_TYPE xnc, SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);

static volatile BOOL g_inRecvfromHook = FALSE;

int NetDll_recvfromPIJHook(XNCALLER_TYPE xnc, SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen)
{
	if (g_inRecvfromHook) return -1;
	g_inRecvfromHook = TRUE;

	HookState_Unhook(&g_hookRecvfrom);
	int result = ((pfnNetDll_recvfrom)(void*)g_hookRecvfrom.pFunction)(xnc, s, buf, len, flags, from, fromlen);
	HookState_Rehook(&g_hookRecvfrom);

	if (xnc == XNCALLER_TITLE && result > 0) {
		LogToServer("RECVFROM fd=%d len=%d", (int)s, result);
		LogPayloadToServer("RECVFROM_DATA", buf, result);
	}

	g_inRecvfromHook = FALSE;
	return result;
}

// ============================================================================
// XHttp hooks — PatchInJump with unhook-call-rehook (system-wide)
// ============================================================================

// --- NetDll_XHttpConnect (ordinal 205) — redirect Ubisoft domains ---

typedef HINTERNET (*pfnNetDll_XHttpConnect)(XNCALLER_TYPE xnc, HINTERNET hSession, LPCSTR pszServerName, INTERNET_PORT nServerPort, DWORD dwFlags);

static BOOL bXHttpConnectHookFired = FALSE;
HINTERNET NetDll_XHttpConnectHook(XNCALLER_TYPE xnc, HINTERNET hSession, LPCSTR pszServerName, INTERNET_PORT nServerPort, DWORD dwFlags)
{
	if (!bXHttpConnectHookFired) {
		XNotify(L"[DIAG] XHttpConnect!");
		bXHttpConnectHookFired = TRUE;
	}

	if (pszServerName != NULL) {
		LogToServer("XHTTP_CONNECT host=%s port=%d flags=0x%08X", pszServerName, nServerPort, dwFlags);
	}

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

// --- NetDll_XHttpOpenRequest (ordinal 207) — log HTTP verbs + paths ---

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
	}

	if (!bXHttpOpenReqHookFired) {
		XNotify(L"[DIAG] XHttpOpenRequest!");
		bXHttpOpenReqHookFired = TRUE;
	}

	// Strip HTTPS flag — our local server is plain HTTP
	dwFlags &= ~XHTTP_FLAG_SECURE;

	HookState_Unhook(&g_hookXHttpOpenReq);
	HINTERNET result = ((pfnNetDll_XHttpOpenRequest)(void*)g_hookXHttpOpenReq.pFunction)(
		xnc, hConnect, pwszVerb, pwszObjectName, pwszVersion,
		pwszReferrer, ppwszAcceptTypes, dwFlags);
	HookState_Rehook(&g_hookXHttpOpenReq);
	return result;
}

// --- NetDll_XHttpSendRequest (ordinal 209) — log request details ---

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

	// Log headers if present (truncated to fit log buffer)
	if (pwszHeaders != NULL && dwHeadersLength > 0) {
		int logLen = dwHeadersLength > 400 ? 400 : dwHeadersLength;
		char hdrBuf[410];
		memcpy(hdrBuf, pwszHeaders, logLen);
		hdrBuf[logLen] = '\0';
		LogToServer("XHTTP_HDRS %s", hdrBuf);
	}

	HookState_Unhook(&g_hookXHttpSendReq);
	DWORD result = ((pfnNetDll_XHttpSendRequest)(void*)g_hookXHttpSendReq.pFunction)(
		xnc, hRequest, pwszHeaders, dwHeadersLength, lpOptional,
		dwOptionalLength, dwTotalLength, dwContext);
	HookState_Rehook(&g_hookXHttpSendReq);
	return result;
}

// ============================================================================
// Privilege / Enumerator hooks (PatchModuleImport — game imports only)
// These remain as import-table hooks since they are genuinely game imports
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
// XNet status hooks — pure replacements via PatchInJump (no call-through)
// ============================================================================

static BOOL bXnAddrHookFired = FALSE;
DWORD XNetGetTitleXnAddrHook(XNCALLER_TYPE xnc, XNADDR* pxna)
{
	if (!bXnAddrHookFired) {
		XNotify(L"[DIAG] XnAddr called!");
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
		XNotify(L"[DIAG] EthLink called!");
		bEthLinkHookFired = TRUE;
	}
	return XNET_ETHERNET_LINK_ACTIVE | XNET_ETHERNET_LINK_100MBPS | XNET_ETHERNET_LINK_FULL_DUPLEX;
}

static BOOL bSigninHookFired = FALSE;
DWORD XamUserGetSigninStateHook(DWORD dwUserIndex)
{
	if (!bSigninHookFired) {
		XNotify(L"[DIAG] SignIn called!");
		bSigninHookFired = TRUE;
	}
	if (dwUserIndex == 0)
		return 2; // eXamUserSigninState_SignedInToLive
	return 0; // eXamUserSigninState_NotSignedIn
}

// ============================================================================
// Hook setup — installs all hooks
// ============================================================================

VOID SetupNetDllHooks()
{
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

	// ---- PatchInJump hooks on socket functions (system-wide) ----
	// These catch ALL callers including Quazal's internal BerkeleySocketDriver

	DWORD* pAddr;

	// NetDll_socket (ordinal 3) — diagnostic
	pAddr = (DWORD*)ResolveFunction(hXam, 3);
	if (pAddr) {
		HookState_Init(&g_hookSocket, pAddr, (DWORD)NetDll_socketPIJHook);
		LogToServer("HOOK ord3 socket OK at 0x%08X", (DWORD)pAddr);
		XNotify(L"[DIAG] Hook ord3 OK");
	} else {
		XNotify(L"[DIAG] ord3 resolve FAIL");
	}

	// NetDll_connect (ordinal 12) — redirect + diagnostic
	pAddr = (DWORD*)ResolveFunction(hXam, 12);
	if (pAddr) {
		HookState_Init(&g_hookConnect, pAddr, (DWORD)NetDll_connectPIJHook);
		LogToServer("HOOK ord12 connect OK at 0x%08X", (DWORD)pAddr);
		XNotify(L"[DIAG] Hook ord12 OK");
	} else {
		XNotify(L"[DIAG] ord12 resolve FAIL");
	}

	// NetDll_sendto (ordinal 24) — redirect + packet logging
	pAddr = (DWORD*)ResolveFunction(hXam, 24);
	if (pAddr) {
		HookState_Init(&g_hookSendto, pAddr, (DWORD)NetDll_sendtoPIJHook);
		LogToServer("HOOK ord24 sendto OK at 0x%08X", (DWORD)pAddr);
		XNotify(L"[DIAG] Hook ord24 OK");
	} else {
		XNotify(L"[DIAG] ord24 resolve FAIL");
	}

	// NetDll_recvfrom (ordinal 20) — incoming packet logging
	pAddr = (DWORD*)ResolveFunction(hXam, 20);
	if (pAddr) {
		HookState_Init(&g_hookRecvfrom, pAddr, (DWORD)NetDll_recvfromPIJHook);
		LogToServer("HOOK ord20 recvfrom OK at 0x%08X", (DWORD)pAddr);
		XNotify(L"[DIAG] Hook ord20 OK");
	} else {
		XNotify(L"[DIAG] ord20 resolve FAIL");
	}

	// ---- PatchInJump hooks on XHttp functions (system-wide) ----

	// NetDll_XHttpConnect (ordinal 205) — domain redirect
	pAddr = (DWORD*)ResolveFunction(hXam, 205);
	if (pAddr) {
		HookState_Init(&g_hookXHttpConnect, pAddr, (DWORD)NetDll_XHttpConnectHook);
		LogToServer("HOOK ord205 XHttpConnect OK at 0x%08X", (DWORD)pAddr);
		XNotify(L"[DIAG] Hook ord205 OK");
	} else {
		XNotify(L"[DIAG] ord205 resolve FAIL");
	}

	// NetDll_XHttpOpenRequest (ordinal 207) — log HTTP verbs/paths
	pAddr = (DWORD*)ResolveFunction(hXam, 207);
	if (pAddr) {
		HookState_Init(&g_hookXHttpOpenReq, pAddr, (DWORD)NetDll_XHttpOpenRequestHook);
		LogToServer("HOOK ord207 XHttpOpenRequest OK at 0x%08X", (DWORD)pAddr);
		XNotify(L"[DIAG] Hook ord207 OK");
	} else {
		XNotify(L"[DIAG] ord207 resolve FAIL");
	}

	// NetDll_XHttpSendRequest (ordinal 209) — log request headers/body
	pAddr = (DWORD*)ResolveFunction(hXam, 209);
	if (pAddr) {
		HookState_Init(&g_hookXHttpSendReq, pAddr, (DWORD)NetDll_XHttpSendRequestHook);
		LogToServer("HOOK ord209 XHttpSendRequest OK at 0x%08X", (DWORD)pAddr);
		XNotify(L"[DIAG] Hook ord209 OK");
	} else {
		XNotify(L"[DIAG] ord209 resolve FAIL");
	}

	// ---- Pure-replacement PatchInJump hooks (no call-through needed) ----

	// XNetGetTitleXnAddr (ordinal 73)
	pAddr = (DWORD*)ResolveFunction(hXam, 73);
	if (pAddr) {
		PatchInJump(pAddr, (DWORD)XNetGetTitleXnAddrHook, FALSE);
		LogToServer("HOOK ord73 XnAddr OK at 0x%08X", (DWORD)pAddr);
	}

	// XNetGetEthernetLinkStatus (ordinal 75)
	pAddr = (DWORD*)ResolveFunction(hXam, 75);
	if (pAddr) {
		PatchInJump(pAddr, (DWORD)XNetGetEthernetLinkStatusHook, FALSE);
		LogToServer("HOOK ord75 EthLink OK at 0x%08X", (DWORD)pAddr);
	}

	// XamUserGetSigninState (ordinal 528)
	pAddr = (DWORD*)ResolveFunction(hXam, 528);
	if (pAddr) {
		PatchInJump(pAddr, (DWORD)XamUserGetSigninStateHook, FALSE);
		LogToServer("HOOK ord528 SignIn OK at 0x%08X", (DWORD)pAddr);
	}

	// ---- Import table hooks (game imports only — privilege + enumerator) ----

	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 530, (DWORD)XamUserCheckPrivilegeHook);
	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 590, (DWORD)XamCreateEnumeratorHandleHook);
	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 592, (DWORD)XamEnumerateHook);
	LogToServer("HOOK imports (530,590,592) patched");

	LogToServer("INIT SetupNetDllHooks complete - all hooks installed");
	XNotify(L"[DIAG] All hooks done!");
}
