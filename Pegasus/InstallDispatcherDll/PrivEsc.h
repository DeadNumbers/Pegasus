/*
	PrivEsc.h
*/

#include <windows.h>

typedef BOOL(NTAPI *SHELL_ENTRY_PROC)(ULONG ulTargetPID);

// structure to pass params and received result from runner thread
typedef struct _PE_THREAD_PARAMS
{
	SHELL_ENTRY_PROC sepExploitExec;	// ptr to exploit entry function

	BOOL bExecResult;		// exec result, returned by exploit

} PE_THREAD_PARAMS, *PPE_THREAD_PARAMS;


VOID privescDo();