/*
	ceDllMemory.h
*/
#pragma once

#include <Windows.h>
#include "..\inc\MyStreams.h"
#include "..\inc\DataCallbackManager.h"

typedef enum DLLMEM_SPECIFIC_ERROR_CODES {
//	ERR_NOVALUE = 0,
	ERR_ALREADY_RUNNING = 1,
	ERR_EMPTY_FILE,
	ERR_PE_LOAD_FAILED,
	ERR_DLLENTRY_RETURNED_FALSE,
	ERR_DLLENTRY_EXCEPTION,

//	ERR_EXEC_ERROR = 1000,	// staring range
//	ERR_MAXVAL = MAXDWORD
};

// internal globals
typedef struct _DLLMEM_CONTEXT {

	BOOL bInited;	// set to TRUE when this context is already inited
	MY_STREAM mHashesStream;	// hashes of running modules
	CRITICAL_SECTION csHashesAccess;	// cs to guard access to mHashesStream

} DLLMEM_CONTEXT, *PDLLMEM_CONTEXT;

BOOL cmdDllMemory(DISPATCHER_CALLBACK_PARAMS *dcp);