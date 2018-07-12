/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by-nc-sa/3.0/
	This file  : http://creativecommons.org/licenses/by/3.0/
*/
#pragma once
#include "..\LogonPasswords.h"


	typedef struct _KIWI_WDIGEST_LIST_ENTRY {
		struct _KIWI_WDIGEST_LIST_ENTRY *Flink;
		struct _KIWI_WDIGEST_LIST_ENTRY *Blink;
		DWORD	UsageCount;
		struct _KIWI_WDIGEST_LIST_ENTRY *This;
		LUID LocallyUniqueIdentifier;
	} KIWI_WDIGEST_LIST_ENTRY, *PKIWI_WDIGEST_LIST_ENTRY;


	// internal context structure
	typedef struct _WDIGEST_MODULE_CONTEXT {
		PKIWI_WDIGEST_LIST_ENTRY l_LogSessList;
		long offsetWDigestPrimary;
	} WDIGEST_MODULE_CONTEXT, *PWDIGEST_MODULE_CONTEXT;



	VOID wdig_InitGlobals();
	bool searchWDigestEntryList(LP_MODULE_CONTEXT *pContext);
	bool WINAPI getWDigestLogonData(LP_MODULE_CONTEXT *pContext, __in PLUID logId);
