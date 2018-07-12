/*
	CryptRoutines.h
*/

#pragma once

#include <windows.h>
#include "MyStreams.h"

// internal global structure holding crypt keys
typedef struct _CRYPT_CONTEXT {

	BOOL bInited;	// flag indicating if init was performed

	HCRYPTPROV hProvider;	// crypto api provider used in routines
	HCRYPTKEY hKey;			// key handle used in encryption/decryption routines

} CRYPT_CONTEXT, *PCRYPT_CONTEXT;

BOOL cryptCalcHashSHA(PVOID pData, SIZE_T ulSize, PBYTE pbResultBuffer, PULONG pulBufferLen);
BOOL cryptEncryptStream(MY_STREAM *mStream);
BOOL cryptDecryptBuffer(LPVOID pCrypted, DWORD dwCryptedLen, LPVOID *pDecrypted, DWORD *dwDecryptedLen);