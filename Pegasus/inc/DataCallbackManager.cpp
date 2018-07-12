/*
	DataCallbackManager.cpp
	Routines for adding, removing and enumerating data callbacks
*/

#include <windows.h>
#include "dbg.h"
#include "DataCallbackManager.h"


#ifdef ROUTINES_BY_PTR


	DataCallbackManager_ptrs DataCallbackManager_apis;	// global var for transparent name translation into call-by-pointer	


// should be called before any other apis used to fill internal structures
VOID DataCallbackManager_resolve(DataCallbackManager_ptrs *apis)
{
#ifdef _DEBUG
	if (IsBadReadPtr(apis, sizeof(DataCallbackManager_ptrs))) { DbgPrint("DBG_ERR: bad read ptr %p len %u", apis, sizeof(DataCallbackManager_ptrs)); }
#endif
	// save to a global var
	DataCallbackManager_apis = *apis;
}

#else 

#include "mem.h"
#include "dbg.h"


/*
	Fill passed structure with ptrs to all exported functions
	Used when module compiled as code to provide ptrs to some other child code
*/
VOID DataCallbackManager_imports(DataCallbackManager_ptrs *apis)
{
	apis->fndcmInit = dcmInit;
	apis->fndcmEnterEnum = dcmEnterEnum;
	apis->fndcmLeaveEnum = dcmLeaveEnum;
	apis->fndcmAddDataCallback = dcmAddDataCallback;
	apis->fndcmRemoveDataCallback = dcmRemoveDataCallback;
	apis->fndcmCallbacksCount = dcmCallbacksCount;
	apis->fndcmDoEnum = dcmDoEnum;
	apis->fndcmGetServerCallback = dcmGetServerCallback;
}


DCM_WORK_STRUCTURE g_dcm;	// global structure used internally	

/*
	Performs init of internal structures
*/
VOID dcmInit()
{
	// wipe structure
	memset(&g_dcm, 0, sizeof(DCM_WORK_STRUCTURE));

	// init guarding cs
	InitializeCriticalSection(&g_dcm.csListAccess);


}



#ifdef _DEBUG


typedef LONG    NTSTATUS;
typedef NTSTATUS(WINAPI *pNtQIT)(HANDLE, LONG, PVOID, ULONG, PULONG);
#define STATUS_SUCCESS    ((NTSTATUS)0x00000000L)
#define ThreadBasicInformation 0

typedef struct _CLIENT_ID {
	DWORD UniqueProcess;
	DWORD UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {

	typedef PVOID KPRIORITY;
	NTSTATUS ExitStatus; 
	PVOID TebBaseAddress; 
	CLIENT_ID ClientId; 
	KAFFINITY AffinityMask; 
	KPRIORITY Priority; 
	KPRIORITY BasePriority;

} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

DWORD WINAPI myGetThreadId(HANDLE hThread)
{
	NTSTATUS ntStatus;
	HANDLE hDupHandle;
	DWORD dwStartAddress;

	THREAD_BASIC_INFORMATION ThreadInfo = { 0 };

	pNtQIT NtQueryInformationThread = (pNtQIT)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationThread");

	if (NtQueryInformationThread == NULL)
		return 0;

	HANDLE hCurrentProcess = GetCurrentProcess();
	if (!DuplicateHandle(hCurrentProcess, hThread, hCurrentProcess, &hDupHandle, THREAD_QUERY_INFORMATION, FALSE, 0)){
		SetLastError(ERROR_ACCESS_DENIED);

		return 0;
	}

	ntStatus = NtQueryInformationThread(hDupHandle, ThreadBasicInformation, &ThreadInfo, sizeof(THREAD_BASIC_INFORMATION), NULL);
	CloseHandle(hDupHandle);
	if (ntStatus != STATUS_SUCCESS)
		return 0;

	return ThreadInfo.ClientId.UniqueThread;

}

#endif





VOID dcmEnterEnum()
{
#ifdef _DEBUG
	while (!TryEnterCriticalSection(&g_dcm.csListAccess)) {

		DbgPrint("NOTE: failed to enter CS, LockCount=%u OwningThread=%u tid=%u", g_dcm.csListAccess.LockCount, g_dcm.csListAccess.OwningThread, myGetThreadId(g_dcm.csListAccess.OwningThread));
		Sleep(5000);

	}
#else

	EnterCriticalSection(&g_dcm.csListAccess);

#endif
}

VOID dcmLeaveEnum()
{
	LeaveCriticalSection(&g_dcm.csListAccess);
}

/*
	Adds a callback to internal list
*/
BOOL CALLBACK dcmAddDataCallback(CLIENTDISPATCHERFUNC pfnClientCallback)
{
	BOOL bRes = FALSE;	// function res
	DCM_CALLBACKS_LIST_CHUNK *pNew;	// new chunk to be added

	// alloc mem for a new chunk
	pNew = (DCM_CALLBACKS_LIST_CHUNK *)my_alloc(sizeof(DCM_CALLBACKS_LIST_CHUNK));
	if (!pNew) { return bRes; }

	// fill it
	pNew->pCallback = (LPVOID)pfnClientCallback;

	// lock list access
	dcmEnterEnum();

	// link to list and inc count
	pNew->lcNext = g_dcm.lHead.lcNext;
	g_dcm.lHead.lcNext = pNew;
	g_dcm.dwItemsCount++;

	// free lock
	dcmLeaveEnum();

	bRes = TRUE;

	return bRes;
}


BOOL CALLBACK dcmRemoveDataCallback(CLIENTDISPATCHERFUNC pfnClientCallback)
{
	BOOL bRes = FALSE;	// function res

	DCM_CALLBACKS_LIST_CHUNK *pRemove = NULL;	// chunk to be removed
	DCM_CALLBACKS_LIST_CHUNK *pPtr;	// current enum ptr
	DCM_CALLBACKS_LIST_CHUNK *pPrev;	// ptr to prev item

	// lock list access
	dcmEnterEnum();

	if (!g_dcm.dwItemsCount) { DbgPrint("WARN: no items in the list"); return bRes; }

	//  init starting ptrs
	pPtr = g_dcm.lHead.lcNext;
	pPrev = &g_dcm.lHead;

	// do enum until list end or pRemove found
	while (pPtr) {

		// check if item matches search criteria
		if (pPtr->pCallback == (LPVOID)pfnClientCallback) { pRemove = pPtr; break; }

		// no luck, go to next item
		pPrev = pPtr;
		pPtr = pPtr->lcNext;

	}

	// check if item was found
	if (pRemove) {

		// unlink item from the chain
		pPrev->lcNext = pRemove->lcNext;

		// dec total count
		g_dcm.dwItemsCount--;

		// free item
		DbgPrint("removing item at %04Xh with CB to %04Xh", pRemove, pRemove->pCallback);
		my_free(pRemove);

	} else { DbgPrint("ERR: search criteria was not found"); }

	// free lock
	dcmLeaveEnum();

	return bRes;
}

DWORD dcmCallbacksCount()
{
	return g_dcm.dwItemsCount;
}

/*
	Do enum of callbacks list, starting from ponted item.
	pStartingItem points to a prev result of this function, or NULL to start from the beginning
	pCallback is a ptr to get a callback value of, or NULL if no data left
	Result: next(pStartingItem+1) enum item to be passed on a next call of this function, or NULL if enum ended
*/
LPVOID dcmDoEnum(LPVOID pStartingItem, LPVOID *pCallback)
{
	DCM_CALLBACKS_LIST_CHUNK *pPtr = (DCM_CALLBACKS_LIST_CHUNK *)pStartingItem;

	// check for params
	if (!pCallback) { DbgPrint("ERR: no output param passed"); return NULL; }
	if (!g_dcm.dwItemsCount) { DbgPrint("no items in the list"); return NULL; }
	if (!pPtr) { pPtr = g_dcm.lHead.lcNext; }	// corrent NULL to a first item in the list

	// set resulting data
	*pCallback = pPtr->pCallback;

	// return ptr to next item to be used
	return pPtr->lcNext;
}

/*
	Main callback (server-callback) used by transports to send data to all subscribed clients. 
	Enums and executes all other data in/out callbacks
	NB: thread safe using internal lock
*/
BOOL CALLBACK cdDataCallbacksCaller(DISPATCHER_CALLBACK_PARAMS *dcp)
{
	LPVOID pEnumPtr = NULL;	// param to be passed to enum function to continue enumeration (i.e. enum handle)
	LPVOID pCallbackPtr = NULL;	// resulting found callback ptr
	CLIENTDISPATCHERFUNC pfnCallback = NULL;	// callback function casted ^

	// check if we have any data processing callbacks (fast)
	if (!dcmCallbacksCount()) { DbgPrint("no cb registered, throwing away data"); return FALSE; }

	// call generic data parser which will form dcp->pParserContext
	// this routine attempt to perform a basic decryption, recognition of inner container, etc
	// all results are in pParserContext only
//	dpParseData(dcp);

	// else, enter processing loop
	dcmEnterEnum();
	__try {

		// enum until enumer returns end of items
		do {
			// get next item
			pEnumPtr = dcmDoEnum(pEnumPtr, &pCallbackPtr);

			// check if item is callable
			if (!IsBadReadPtr(pCallbackPtr, sizeof(LPVOID))) {

				// enumed ok, cast and call callback
				pfnCallback = (CLIENTDISPATCHERFUNC)pCallbackPtr;

				// check if callback processed data (returned TRUE), so no need to do enum anymore
				if (pfnCallback(dcp)) { /*DbgPrint("CB(%04Xh) processed and asked to stop calling other cbs", pCallbackPtr);*/ break; }

			}
			else { DbgPrint("ERR: cb addr %04Xh is not readable", pCallbackPtr); }

		} while (pEnumPtr);

	}
	__except (1) { DbgPrint("ERR: exception catched"); }
	dcmLeaveEnum();

	// free any mem allocated at pParserContext
//	dpFreeParseResults(dcp);

	// simply return TRUE, no meaning for this call as a single callback
	return TRUE;
}

// used to query a ptr to internal server callback, used by transport to send data to all subscribers
CLIENTDISPATCHERFUNC dcmGetServerCallback()
{
	return cdDataCallbacksCaller;
}

#endif