/*
	ceGeneric.h
*/
#pragma once

#include <Windows.h>

// param at cmdDiskExec
typedef enum ENUM_EXECUTE_METHOD {
	EEM_CREATEPROCESS,
	EEM_SHELLEXECUTE
};

// errors returned by _cmdSafeExec()
typedef enum EXEC_ERROR_CODE {
	ERR_EXEC_OK = 0,	// no error, ok
	ERR_EXEC_HUNGED = 1000,
	ERR_EXEC_FAILURE
};

// params to be passed to a CreateProcessSafe() function
typedef struct _CREATEPROCESS_PARAMS {

	ENUM_EXECUTE_METHOD emExecMethod;	// type of exec method to be used

	// std handles for process & controller. Should be NULL if not used
	HANDLE hStdInRead, hStdInWrite, hStdOutRead, hStdOutWrite;// , hStdErrRead, hStdErrWrite;

	// params for CreateProcess()/EEM_CREATEPROCESS
	LPWSTR wszApplication;
	LPWSTR wszCmdline;

	PROCESS_INFORMATION pi; // result in case of CreateProcess()/EEM_CREATEPROCESS

	BOOL bExecResult;	// TRUE in case of exec api was ok
	DWORD dwLastError;	// GetLastError() result after api call 

	// internals
	HANDLE hExecThread;	// handle of a thread used to execute CreateProcess/... apis
	BOOL bNeedTerminateExecThread;	// set by caller if it needs to perform termination of hExecThread thread
	BOOL bTerminationStarted;		// set by thread when it copied all necessary data and it's safe to free input params ptr

} CREATEPROCESS_PARAMS, *PCREATEPROCESS_PARAMS;





#pragma pack(push)
#pragma pack(1)

// sent with CER_ERR_SPECIFIC_ERROR result code
typedef struct _CMDEXEC_SPECIFIC_ERROR {

	DWORD dwSpecificErrCode;		// internal id of place where an error was catched
	DWORD dwLastError;				// GetLastError() result

} CMDEXEC_SPECIFIC_ERROR, *PCMDEXEC_SPECIFIC_ERROR;

#pragma pack(pop)

VOID cmFormAnswer(DISPATCHER_CALLBACK_PARAMS *dcp, WORD wResult, LPVOID pPayload, DWORD dwPayloadLen);
VOID cmFormAnswerSpecificErr(DISPATCHER_CALLBACK_PARAMS *dcp, DWORD dwSpecificErrCode, DWORD dwLastError);
BOOL _cmdCreateStdPipes(CREATEPROCESS_PARAMS *cpParams);
VOID _cmdFreeStdPipes(CREATEPROCESS_PARAMS *cpParams);
DWORD WINAPI thrSafeExec(LPVOID lpParameter);
BOOL _cmdSafeExec(CREATEPROCESS_PARAMS *cpParams, EXEC_ERROR_CODE *seError);
