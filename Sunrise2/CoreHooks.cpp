#include "stdafx.h"
#include "Sunrise2.h"
#include "Utilities.h"

XTITLE_SERVER_INFO activeServer;
WORD activeServerPort;
HANDLE lsp_enum_handle;
int enumeration_index;

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
	// Force privilege check to return true to bypass Xbox Live Gold requirements
	if (pfResult != NULL) {
		*pfResult = TRUE;
	}
	return 0; // ERROR_SUCCESS
}

int XamCreateEnumeratorHandleHook(DWORD user_index, HXAMAPP app_id, DWORD open_message, DWORD close_message, DWORD extra_size, DWORD item_count, DWORD flags, PHANDLE out_handle)
{
    int result = XamCreateEnumeratorHandle(user_index, app_id, open_message, close_message, extra_size, item_count, flags, out_handle);
    
    // Intercept for Halo (0x58039) or any Ubisoft Title ID (0x5553XXXX)
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

VOID SetupNetDllHooks()
{
	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 12, (DWORD)NetDll_connectHook);
	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 24, (DWORD)NetDll_sendtoHook);
	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 25, (DWORD)NetDll_WSASendToHook);
	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 530, (DWORD)XamUserCheckPrivilegeHook);
	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 590, (DWORD)XamCreateEnumeratorHandleHook);
	PatchModuleImport((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle, "xam.xex", 592, (DWORD)XamEnumerateHook);
}