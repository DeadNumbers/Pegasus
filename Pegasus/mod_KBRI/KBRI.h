/*
	KBRI.h
*/
#pragma once
#include <windows.h>

#include "kbriList.h"





// all globals var used by module, in a single structure
typedef struct _KBRI_GLOBALS
{
	KBRI_LIST list;	// linked list of injected processes

	DWORD dwPipeServerThreadId;	// tid of pipe server thread, needed when other version requests termination
	DWORD dwTAccsQueryThreadId;	// kbriTargetAccManager.cpp, thread to periodically issue special server request

} KBRI_GLOBALS, *PKBRI_GLOBALS;


VOID kbriStartInjMonitor();