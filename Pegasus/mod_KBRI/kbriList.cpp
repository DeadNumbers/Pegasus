/*
	kbriList.cpp
	Misc linked list - related routines
*/

#include <windows.h>

#include "..\inc\dbg.h"
#include "..\inc\mem.h"

#include "kbriList.h"

VOID kbriInitList(KBRI_LIST *list)
{
	memset(list, 0, sizeof(KBRI_LIST));
	InitializeCriticalSection(&list->csipAccess);
}

/*
	Try to add a pid to list. If pid a new - returns TRUE
	In case of duplicate pid, returns FALSE
	ALSO, adds scanned flag in case of duplicate pid
*/
BOOL kbriAddInjectedPid(KBRI_LIST *list, DWORD dwPID)
{
	BOOL bRes = TRUE;
	INJECTED_PROCESS_CHUNK *chunk;	// moving ptr with current chunk

	// scan existent items
	if (list->dwipCount) {

		EnterCriticalSection(&list->csipAccess);

		// get first item
		chunk = list->ipHead.lcNext;

		while (chunk) {

			// check contents
			if (chunk->er.dwPID == dwPID) { /* DbgPrint("pid %u already injected", dwPID); */ bRes = FALSE; chunk->er.bScanned = TRUE; break; }

			// move to next item
			chunk = chunk->lcNext;
		}

		LeaveCriticalSection(&list->csipAccess);

		// check if found pid
		if (!bRes) { return bRes; }

	} else { DbgPrint("no items yet"); } // items present

	// really add a new pid record
	chunk = (INJECTED_PROCESS_CHUNK *)my_alloc(sizeof(INJECTED_PROCESS_CHUNK));
	chunk->er.dwPID = dwPID;
	chunk->er.bScanned = TRUE;

	// link to list
	EnterCriticalSection(&list->csipAccess);
	chunk->lcNext = list->ipHead.lcNext;
	list->ipHead.lcNext = chunk;
	list->dwipCount++;
	DbgPrint("added new item, new count %u", list->dwipCount);
	LeaveCriticalSection(&list->csipAccess);

	return bRes;
}


/*
	Iterate all items and clear scanned flag
*/
VOID kbriClearScannedFlag(KBRI_LIST *list)
{
	INJECTED_PROCESS_CHUNK *chunk;	// moving ptr with current chunk

	// check for no items
	if (!list->dwipCount) { return; }

	EnterCriticalSection(&list->csipAccess);

	// get first item
	chunk = list->ipHead.lcNext;

	while (chunk) {

		// set value
		chunk->er.bScanned = FALSE;

		// move to next item
		chunk = chunk->lcNext;
	}

	LeaveCriticalSection(&list->csipAccess);
}

/*
	Iterate chunk list and remove all items where no bScanned flag currently set
*/
VOID kbriRemoveNotScanned(KBRI_LIST *list)
{
	INJECTED_PROCESS_CHUNK *chunk;	// moving ptr with current chunk
	INJECTED_PROCESS_CHUNK *chunk_prev;

	// check for no items
	if (!list->dwipCount) { return; }

	EnterCriticalSection(&list->csipAccess);

	// get first item
	chunk_prev = &list->ipHead;
	chunk = list->ipHead.lcNext;

	while (chunk) {

		// check flag
		if (!chunk->er.bScanned) {

			DbgPrint("removing pid %u as non-running", chunk->er.dwPID);

			// found not-set flag, unlink chunk
			chunk_prev->lcNext = chunk->lcNext;
			list->dwipCount--;

			// dealloc
			my_free(chunk);

			// move to next item
			chunk = chunk_prev->lcNext;

		} else {

			// move to next item
			chunk_prev = chunk_prev->lcNext;
			chunk = chunk->lcNext;

		}
	}

	LeaveCriticalSection(&list->csipAccess);


}