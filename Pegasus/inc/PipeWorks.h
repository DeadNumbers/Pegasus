/*
	PipeWorks.h
*/
#pragma once

#include <windows.h>

#include "DataCallbackManager.h"

#ifdef ROUTINES_BY_PTR
#ifndef NO_TRANSPORT_ENVELOPE
#define ROUTINES_BY_PTR_ALLOWED
#endif
#endif

// less than 10k to allow connectionless remote send
#define PIPE_BUFFER_SIZE 4096

// NET_MESSAGE_ENVELOPE.bMessageId, specified in header
typedef enum ENUM_PIPE_MESSAGE_ID {
	PMI_NONE = 0,	// nothing defined
	PMI_SEND_QUERY,	// issued when remote client needs to send some data chunk to network control center. Server should return id to check that query status later via PMI_CHECK_STATUS_QUERY
	PMI_CHECK_STATUS_QUERY,	// after PMI_SEND_QUERY, client may periodically poll server to detect send status of a chunk

	PMI_TERMINATE_HOST_PROCESS___,	// used by wdd to terminate other hosts with pipe running, to replace with a new version // DEPRECATED, not used from now
	PMI_TERMINATE_HOST_PROCESS_IF_LOWER_VERSION,	// replacement for PMI_TERMINATE_HOST_PROCESS, which checks version of caller and target, so a lower version will be terminated (to prevent downgrades)

	PMI_MAXVAL = MAXBYTE	// max value to fit into byte
};

// define functions for import-export, used in both compilation modes
typedef struct _PipeWorks_ptrs {

	DWORD (WINAPI *fnpwInitPipeServer)(LPVOID pParameter);
	void (*fnpwInitPipeServerAsync)(CLIENTDISPATCHERFUNC cdCallback);
	BOOL(*fnpwIsRemotePipeWorkingTimeout)(LPWSTR wszTargetMachineName, DWORD dwTimeoutMsec, DWORD dwRecheckIntervalMsec);
	BOOL(*fn_pwRemotePipeCheckSend)(LPWSTR wszTargetMachineName, DWORD dwTimeoutMsec, DWORD dwRecheckIntervalMsec, LPVOID pSendBuffer, DWORD lSendBufferLen, LPVOID *pAnswer, DWORD *pdwAnswerLen, BYTE *pbPipeMessageId);

} PipeWorks_ptrs, *PPipeWorks_ptrs;

// params sent to dispatcher thread
typedef struct _DISPATCHER_THREAD_PARAMS {

	HANDLE hPipe;	// pipe with client connected
	CRITICAL_SECTION *csDispatcherCall;	// cs to guard calls to dispatcher proc to avoid mt problems
	CLIENTDISPATCHERFUNC cdCallback;	// function to be called for ready combined data buffer

} DISPATCHER_THREAD_PARAMS, *PDISPATCHER_THREAD_PARAMS;

#ifdef ROUTINES_BY_PTR_ALLOWED

	#pragma message(__FILE__": ROUTINES_BY_PTR compilation mode")

	// global var definition to be visible by all modules which use this one
	extern PipeWorks_ptrs PipeWorks_apis;

	// transparent code replacements
	#define pwInitPipeServer PipeWorks_apis.fnpwInitPipeServer
	#define pwInitPipeServerAsync PipeWorks_apis.fnpwInitPipeServerAsync
	#define pwIsRemotePipeWorkingTimeout PipeWorks_apis.fnpwIsRemotePipeWorkingTimeout
	#define _pwRemotePipeCheckSend PipeWorks_apis.fn_pwRemotePipeCheckSend

	VOID PipeWorks_resolve(PipeWorks_ptrs *apis);

#else

DWORD WINAPI pwInitPipeServer(LPVOID pParameter);
void pwInitPipeServerAsync(CLIENTDISPATCHERFUNC cdCallback);
BOOL pwIsRemotePipeWorkingTimeout(LPWSTR wszTargetMachineName, DWORD dwTimeoutMsec, DWORD dwRecheckIntervalMsec);
BOOL _pwRemotePipeCheckSend(LPWSTR wszTargetMachineName, DWORD dwTimeoutMsec, DWORD dwRecheckIntervalMsec, LPVOID pSendBuffer, DWORD lSendBufferLen, LPVOID *pAnswer, DWORD *pdwAnswerLen, BYTE *pbPipeMessageId);

VOID PipeWorks_imports(PipeWorks_ptrs *apis);

#endif