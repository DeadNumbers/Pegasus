/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by-nc-sa/3.0/
	This file  : http://creativecommons.org/licenses/by/3.0/
*/
#pragma once
#include "..\LogonPasswords.h"


	typedef struct _KIWI_SSP_CREDENTIAL_LIST_ENTRY {
		struct _KIWI_SSP_CREDENTIAL_LIST_ENTRY *Flink;
		struct _KIWI_SSP_CREDENTIAL_LIST_ENTRY *Blink;
		ULONG References;
		ULONG CredentialReferences;
		LUID LogonId;
		ULONG unk0;
		ULONG unk1;
		ULONG unk2;
		KIWI_GENERIC_PRIMARY_CREDENTIAL credentials;
	} KIWI_SSP_CREDENTIAL_LIST_ENTRY, *PKIWI_SSP_CREDENTIAL_LIST_ENTRY;

	


	VOID ssp_InitGlobals();
	bool searchSSPEntryList(LP_MODULE_CONTEXT *pContext);
	bool WINAPI getSSPLogonData(LP_MODULE_CONTEXT *pContext, __in PLUID logId);

