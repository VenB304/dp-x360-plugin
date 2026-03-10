#include "stdafx.h"
#include "CoreHooks.h"
#include "Utilities.h"

const char* SunriseVers = "2.1.0";
const char* PluginVersion = "1.0.0-DPLegacy";

in_addr sunrise_ip = { 174, 136, 231, 17 };
INT sunrise_port = 8000;

in_addr jd_ip = { 185, 14, 92, 137 };
INT jd_port = 19030;

const char sunrise_description[XTITLE_SERVER_MAX_SERVER_INFO_LEN] = "required,mass_storage,other,ttl,usr,shr,web,dbg,upl,prs,std";
// Updated description based on rdata analysis
const char jd_description[XTITLE_SERVER_MAX_SERVER_INFO_LEN] = "RV,RVSec,SBMGMT,NAT,SessionDiscovery,NATEcho,Routing,IsKeepAliveInfinite";

HANDLE hXam;
BOOL bRunContinuous = TRUE;
BOOL bLoopHasComplete = FALSE;
BOOL bIsDevkit; 
DWORD LastTitleId;

DWORD Halo3InternalBeta = 0x4D53883A;
DWORD Halo3ExternalBeta = 0x4D53880C;
DWORD Halo3 = 0x4D5307E6;
DWORD Halo3ODST = 0x4D530877;
DWORD HaloReach = 0x4D53085B;
DWORD JustDance2014 = 0x555308B5;
DWORD JustDance2015 = 0x555308CD;
DWORD JustDance2016 = 0x555308D6;
DWORD JustDance2017 = 0x555308D9;
DWORD JustDance2018 = 0x555308DF;

BOOL bAllowRetailPlayers = TRUE;
BOOL bIgnoreTrueskill = FALSE;

VOID Initialise()
{
	hXam = GetModuleHandle(MODULE_XAM);

	if (MountPath(MOUNT_POINT, GetMountPath()) != 0)
	{
		Sunrise_Dbg("Failed to set mount point!");
		return;
	}

	while (bRunContinuous)
	{
		DWORD TitleID = XamGetCurrentTitleId();

		if (TitleID != LastTitleId)
		{
			LastTitleId = TitleID; 

			if (TitleID == Halo3 || TitleID == Halo3ExternalBeta || TitleID == Halo3InternalBeta) 
			{
				RegisterActiveServer(sunrise_ip, sunrise_port, sunrise_description);
				Readini();
				SetupNetDllHooks();
				XNotify(L"Halo Sunrise Initialised!");
			}
			else if (TitleID == JustDance2014 || TitleID == JustDance2015 || TitleID == JustDance2016 || TitleID == JustDance2017 || TitleID == JustDance2018) {
				RegisterActiveServer(jd_ip, jd_port, jd_description);
				SetupNetDllHooks();
				XNotify(L"DanceParty Enabled!");
			}
		}
		Sleep(500);
	}
	bLoopHasComplete = TRUE;
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		if (IsTrayOpen())
		{
			Sunrise_Dbg("Plugin load aborted! Disc tray is open");
			return FALSE;
		}

		bIsDevkit = *(DWORD*)0x8E038610 & 0x8000 ? FALSE : TRUE;
		Sunrise_Dbg("v%s loaded! Running on %s kernel", SunriseVers, bIsDevkit ? "Devkit" : "Retail");
		ThreadMe((LPTHREAD_START_ROUTINE)Initialise);
		break;
	case DLL_PROCESS_DETACH:
		bRunContinuous = FALSE;
		while (!bLoopHasComplete) Sleep(100);
		break;
	}
	return TRUE;
}