#pragma once

#ifndef COREHOOKS_H
#define COREHOOKS_H
#include "stdafx.h"

// ============================================================================
// HOOK_STATE — PatchInJump unhook-call-rehook infrastructure
// ============================================================================

typedef struct _HOOK_STATE {
	DWORD* pFunction;      // Address of the function in xam.xex
	DWORD  origCode[4];    // Saved original 16 bytes (4 PowerPC instructions)
	DWORD  hookTarget;     // Our hook function address
	BOOL   installed;      // Whether the hook is currently active
} HOOK_STATE;

VOID HookState_Init(HOOK_STATE* hs, DWORD* pFunc, DWORD hookFn);
VOID HookState_Unhook(HOOK_STATE* hs);
VOID HookState_Rehook(HOOK_STATE* hs);

// ============================================================================
// Public API
// ============================================================================

VOID RegisterActiveServer(in_addr address, WORD port, const char description[XTITLE_SERVER_MAX_SERVER_INFO_LEN]);
VOID SetupNetDllHooks();
VOID TeardownNetDllHooks();
VOID RegisterHaloLogger(DWORD Address);
VOID SetupXUserReadStatsHook(DWORD Address);

#endif
