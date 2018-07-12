/*
	kbriList.h
*/
#pragma once
#include <windows.h>

// structure describing a single item of injected process
typedef struct _INJECTED_PROCESS
{
	DWORD dwPID;	// pid of process injected (or at least attempted to)
	BOOL bScanned;	// flag used while re-enuming processes list, to remove non-existent processes after re-scan

} INJECTED_PROCESS, *PINJECTED_PROCESS;


// single chunk pointer by linked list
typedef struct _INJECTED_PROCESS_CHUNK INJECTED_PROCESS_CHUNK;
typedef struct _INJECTED_PROCESS_CHUNK
{
	INJECTED_PROCESS_CHUNK *lcNext;
	INJECTED_PROCESS er;					// NB: payload in head item is not used

} INJECTED_PROCESS_CHUNK, *PINJECTED_PROCESS_CHUNK;

typedef struct _KBRI_LIST
{
	INJECTED_PROCESS_CHUNK ipHead;	// list head for a list of injected processes
	DWORD dwipCount;				// amount of ^
	CRITICAL_SECTION csipAccess;	// cs to guard access to a list

} KBRI_LIST, *PKBRI_LIST;

VOID kbriInitList(KBRI_LIST *list);
BOOL kbriAddInjectedPid(KBRI_LIST *list, DWORD dwPID);
VOID kbriClearScannedFlag(KBRI_LIST *list);
VOID kbriRemoveNotScanned(KBRI_LIST *list);