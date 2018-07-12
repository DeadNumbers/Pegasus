/*
	APIHook.c
	Generic api-hooking routines
*/

#include <windows.h>

#include "..\inc\mem.h"
#include "..\inc\dbg.h"
#include "ldasm.h"

#include "APIHook.h"


// WriteProcessMemory replacement for local process
BOOL llWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
{
	BOOL bRes = FALSE;

	__try {

		//DbgPrint("to=%04Xh from=%04Xh len=%u p_written=%u", lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

		if (hProcess!=(HANDLE)-1) { DbgPrint("WARNWARN: not self process, hProcess=%04Xh", hProcess); }

		memcpy(lpBaseAddress, lpBuffer, nSize);

		if (!IsBadWritePtr(lpNumberOfBytesWritten, sizeof(SIZE_T))) { *lpNumberOfBytesWritten = nSize; }

		bRes = TRUE;

	} __except(1) { DbgPrint("WARN: exception"); }

	return bRes;
}


/* Patch given function 
	stub_len will contain amount of bytes placed into stub
*/
void patch_function(LPVOID address, unsigned char *stub, unsigned char *hook, DWORD *stub_len) 
{
	DWORD				protect;
	SIZE_T 				bytes, written;
	MEMORY_BASIC_INFORMATION	mbi_thunk;

	LPVOID pPtr = address;
	DWORD dwDisasmLen = 0;

	ldasm_data ld;	// ldasm() func res

	/*
	 * Most native x32 NT functions begin with stub like this:
	 *
	 * 00000000  B82B000000        mov eax,0x2b         ; syscall
	 * 00000005  8D542404          lea edx,[esp+0x4]    ; arguments
	 * 00000009  CD2E              int 0x2e             ; interrupt
	 *
	 * In offset 0, the actual system call is saved in eax. Syscall
	 * is 32 bit number (!) so we can assume 5 bytes of preamble size
	 * for each function.. If there's need to hook other functions,
	 * a complete disassembler is needed for preamble size counting.
	 *
	 */

	/*
		NB: to support usermode hooked functions, it is ESSENTIAL to make length disasm here.
		We need at least 5 bytes, max is HOOK_STUB_MAXLEN-5 (5 is length of jmp abs instruction, for x32)

	for x64 stub variants
	 via addr to rax from mem ptr:
		0000 (10) 48b8 0102030405060708 MOV RAX, 0x807060504030201
		000a (02) ffe0 JMP RAX

     call saving rax:
		(01) 50						push rax
		(10) 48b8 0102030405060708	mov rax, 0x807060504030201
		(04) 48870424				xchg rax, [rsp]
		(01) c3						ret	

	*/
//	DbgPrint("entered: address=%04Xh stub %04Xh hook addr %04Xh res len place %04Xh", address, stub, hook, stub_len);

	// get at least needed bytes count
	bytes = 0;
	while (bytes < MIN_STUB_LEN) {
		dwDisasmLen = 0;
#if defined(_M_X64)
		dwDisasmLen = ldasm(pPtr, &ld, 1);	// x64 disasm
#else
		dwDisasmLen = ldasm(pPtr, &ld, 0);	// x32 disasm
#endif

		//DbgPrint("step dwDisasmLen=%u", dwDisasmLen);
		bytes += dwDisasmLen;
		pPtr = (LPVOID)( (SIZE_T)pPtr + (SIZE_T)dwDisasmLen );
	}

	// save stub len
//	DbgPrint("res stub len is %u", bytes);
	*stub_len = (DWORD)bytes;

	/* Create the stub */
	llWriteProcessMemory((HANDLE)-1, stub, (char *)address, bytes, &written);		// copy needed bytes of function into stub place
#if defined(_M_X64)
	// x64 stub
	*(PWORD)((SIZE_T)stub + bytes) = 0xb848;
	*(PUINT64)((SIZE_T)stub + bytes + 2) = (UINT64)address; 
	*(PWORD)((SIZE_T)stub + bytes + 10) = 0xe0ff;

#else
	// x32 stub
	*(PBYTE)(stub + bytes) = 0xE9;	// jmp abs opcode at the end of the stub
	*(DWORD *)(stub + bytes + 1) = (DWORD)address - ((DWORD)stub + 5);	
#endif

	/* Patch original function */

	/* Fix protection */
	VirtualQuery((char *)address, &mbi_thunk, sizeof(MEMORY_BASIC_INFORMATION));
	VirtualProtect(mbi_thunk.BaseAddress, mbi_thunk.RegionSize, PAGE_EXECUTE_READWRITE, &mbi_thunk.Protect);
		
	/* Insert jump */
#if defined(_M_X64)
	// x64 stub
	*(PWORD)((SIZE_T)address ) = 0xb848;
	*(PUINT64)((SIZE_T)address + 2) = (UINT64)hook; 
	*(PWORD)((SIZE_T)address + 10) = 0xe0ff;

	// set all left with nops for debugging
	if (bytes<12) { memset((LPVOID)((SIZE_T)address + 5), 0x90,  bytes - 12); }
#else
	// x32 stub
	*(PBYTE)address = 0xE9;	// jmp abs opcode
	*(DWORD *)( (SIZE_T)address + 1) = (SIZE_T)hook - ((SIZE_T)address + 5);	
#endif

	/* Restore protection */
	VirtualProtect(mbi_thunk.BaseAddress, mbi_thunk.RegionSize, mbi_thunk.Protect, &protect);
	FlushInstructionCache((HANDLE)-1, mbi_thunk.BaseAddress, mbi_thunk.RegionSize);


}



/*
	Wrapper for patch_function() which query target api by name
	hModule & wszFunctionName - target function
	pHook - function to be called before the target (i.e. hook function)
	pStub - RWE buffer to hold some bytes from the start of original function plus jmp opcode
	*pToCallOrig - where to place ptr for calling original func directly, actually set to pStub value

*/
BOOL hkHook(HMODULE hModule, LPSTR szFunctionName, LPVOID pHook, LPVOID pStub, LPVOID *pToCallOrig)
{
	LPVOID pFunc = NULL;	// target function
	DWORD dwStubLen = 0;	// not used outside, as we do not need to remove our hooks

	pFunc = GetProcAddress(hModule, szFunctionName);
	if (!pFunc) { DbgPrint("ERR: func [%s] not found at hmodule %04Xh", szFunctionName, hModule); return FALSE; }

	// call main func
	patch_function(pFunc, (unsigned char *)pStub, (unsigned char *)pHook, &dwStubLen);

	// assign result
	*pToCallOrig = pStub;
	//DbgPrint("orig stub placed at %04Xh and saved to global var at %04Xh", pStub, pToCallOrig);

	return TRUE;

}