/*
	SCM.h
*/

#include <windows.h>

// params passed from _drRemoteServiceAsync() to it's child thread _drthrRemoteService()
typedef struct _REMSRV_THREAD_PARAMS
{
	// input params
	LPWSTR wszTargetMachine;
	LPWSTR wszRemoteFilename;

	// sync object
	HANDLE hThreadStarted;		// event object signalled when thread's init done and it's safe to wait for hSyncObject
	HANDLE hSyncObject;			// event signalled when caller may exit, indicating remote file is possibly running or some error occured. Cleanup is done by thread internally anyway
	HANDLE hCallerExited;	// set by caller when it terminates and thread may dispose params structure safely

	// result output
	BOOL bResult;

} REMSRV_THREAD_PARAMS, *PREMSRV_THREAD_PARAMS;

BOOL scmStartRemoteFileAsServiceAsync(LPWSTR wszTargetMachine, LPWSTR wszRemoteFilename);