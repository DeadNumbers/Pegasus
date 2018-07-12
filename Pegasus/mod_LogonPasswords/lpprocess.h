/*
	lpprocess.h
*/

#pragma once
#include <Windows.h>
#include "LogonPasswords.h"

/*
typedef struct _KIWI_VERY_BASIC_MODULEENTRY
{
	BYTE  * modBaseAddr;        // Base address of module in th32ProcessID's context
	DWORD   modBaseSize;        // Size in bytes of module starting at modBaseAddr
	LPWSTR	wszModule;
} KIWI_VERY_BASIC_MODULEENTRY, *PKIWI_VERY_BASIC_MODULEENTRY;
*/

// callback definition to be called on each received full data chunk
typedef BOOL(CALLBACK* MODULE_INFO_CALLBACK)(KIWI_VERY_BASIC_MODULEENTRY *, LPVOID);

LPWSTR lp_getUnicodeStringOfProcess(UNICODE_STRING * ptrString, HANDLE process, PLSA_PROTECT_MEMORY unProtectFunction = NULL);
bool lp_getVeryBasicModulesListForProcess(MODULE_INFO_CALLBACK miCallback, LPVOID pCallbackParam, HANDLE processHandle);