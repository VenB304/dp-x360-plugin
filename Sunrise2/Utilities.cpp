#include "stdafx.h"
#include "Utilities.h"
#include "SimpleIni.h"
#include "Sunrise2.h"

FARPROC ResolveFunction(HMODULE hHandle, DWORD Ordinal) {
	return (hHandle == NULL) ? NULL : GetProcAddress(hHandle, (LPCSTR)Ordinal);
}

VOID PatchInJump(DWORD* addr, DWORD dest, BOOL linked) {
	DWORD temp[4];
	if (dest & 0x8000) temp[0] = 0x3D600000 + (((dest >> 16) & 0xFFFF) + 1);
	else temp[0] = 0x3D600000 + ((dest >> 16) & 0xFFFF);
	temp[1] = 0x396B0000 + (dest & 0xFFFF);
	temp[2] = 0x7D6903A6;
	temp[3] = linked ? 0x4E800421 : 0x4E800420;
	memcpy(addr, temp, 0x10);
	__dcbst(0, addr);
	__sync();
	__isync();
}

DWORD PatchModuleImport(PLDR_DATA_TABLE_ENTRY Module, CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress) {
	DWORD address = (DWORD)GetProcAddress(GetModuleHandle(ImportedModuleName), (LPCSTR)Ordinal);
	if (address == NULL) return S_FALSE;
	PXEX_IMPORT_DESCRIPTOR importDesc = (PXEX_IMPORT_DESCRIPTOR)RtlImageXexHeaderField(Module->XexHeaderBase, 0x000103FF);
	if (importDesc == NULL) return S_FALSE;
	XEX_IMPORT_TABLE_ORG* importTable = (XEX_IMPORT_TABLE_ORG*)((BYTE*)(importDesc + 1) + importDesc->NameTableSize);
	for (DWORD x = 0; x < importDesc->ModuleCount; x++) {
		DWORD* importAdd = (DWORD*)(importTable + 1);
		for (DWORD y = 0; y < importTable->ImportTable.ImportCount; y++) {
			if (*((DWORD*)importAdd[y]) == address) {
				memcpy((DWORD*)importAdd[y], &PatchAddress, 4);
				return S_OK;
			}
		}
		importTable = (XEX_IMPORT_TABLE_ORG*)(((BYTE*)importTable) + importTable->TableSize);
	}
	return S_FALSE;
}

BOOL IsTrayOpen() {
	unsigned char msg[0x10], resp[0x10];
	memset(msg, 0, 0x10); msg[0] = 0xA;
	HalSendSMCMessage(msg, resp);
	return (resp[1] == 0x60);
}

VOID XNotify(LPCWSTR pwszStringParam) {
	if (!bIsDevkit) XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, (PWCHAR)pwszStringParam, NULL);
}

VOID ThreadMe(LPTHREAD_START_ROUTINE lpStartAddress) {
	HANDLE handle; DWORD lpThreadId;
	ExCreateThread(&handle, 0, &lpThreadId, (PVOID)XapiThreadStartup, lpStartAddress, NULL, 0x2 | CREATE_SUSPENDED);
	XSetThreadProcessor(handle, 4);
	ResumeThread(handle);
}

DWORD MountPath(PCHAR Drive, PCHAR Device) {
	ANSI_STRING LinkName, DeviceName;
	RtlInitAnsiString(&LinkName, Drive);
	RtlInitAnsiString(&DeviceName, Device);
	ObDeleteSymbolicLink(&LinkName);
	return (DWORD)ObCreateSymbolicLink(&LinkName, &DeviceName);
}

PCHAR GetMountPath() {
	static char path[MAX_PATH];
	PLDR_DATA_TABLE_ENTRY TableEntry;
	XexPcToFileHeader((PVOID)BASE_ADDR, &TableEntry);
	wcstombs(path, TableEntry->FullDllName.Buffer, MAX_PATH);
	return path;
}

VOID Sunrise_Print(const CHAR* fmt, ...) {
	va_list args; va_start(args, fmt); vfprintf(stdout, fmt, args); va_end(args);
}

BYTE INIDATA[] = { 0x5B, 0x4F, 0x50, 0x54, 0x49, 0x4F, 0x4E, 0x53, 0x5D, 0x0D, 0x0A, 0x41, 0x6C, 0x6C, 0x6F, 0x77, 0x52, 0x65, 0x74, 0x61, 0x69, 0x6C, 0x50, 0x6C, 0x61, 0x79, 0x65, 0x72, 0x73, 0x20, 0x3D, 0x20, 0x74, 0x72, 0x75, 0x65 };

VOID Writeini(BOOL GenerateNew) {
	CSimpleIniA ini;
	if (GenerateNew) {
		HANDLE f = CreateFile(PATH_INI, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
		DWORD b; WriteFile(f, INIDATA, sizeof(INIDATA), &b, NULL); CloseHandle(f);
	}
}

VOID Readini() {
	CSimpleIniA ini;
	if (ini.LoadFile(PATH_INI)) Writeini(TRUE);
}