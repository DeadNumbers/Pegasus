/*
	mem.c
	General memory allocation functions, with chunks tagging in debug version
	VirtualAlloc/GlobalAlloc according to GLOBAL_ALLOC definition
*/

#include <windows.h>
#include "dbg.h"
#include "mem.h"

#ifdef _DEBUG
//#if defined(_M_IX86)
#define ALLOW_DBGMEM
#define DO_MEMALLOC_LIST_CHECK
//#endif
#endif



#ifndef ALLOW_DBGMEM 

// ######################################################################################################
// ##  RELEASE MEM FUNCTIONS
// ######################################################################################################


/*
	Allocates a memory buffer
*/
LPVOID my_alloc(SIZE_T lMemSize)
{
	LPVOID pAllocated = NULL;

// check size for a sane value
	if (lMemSize) {

	#ifndef GLOBAL_ALLOC
		return VirtualAlloc(NULL, lMemSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	#else
		pAllocated = GlobalAlloc(GPTR, lMemSize);
		if (!pAllocated) { DbgPrint("ERR: failed to alloc size %u", (DWORD)lMemSize);}
		
	#endif

	} 
	return pAllocated;
}


/*
	Deallocates buffer from my_alloc
*/
VOID my_free(PVOID pMemBuff)
{

	if (pMemBuff) {

		#ifndef GLOBAL_ALLOC
			if (!VirtualFree(pMemBuff, 0, MEM_RELEASE)) { DbgPrint("my_free: WARN: VirtualFree failed for %p", pMemBuff); }
		#else
			if (GlobalFree(pMemBuff)) {  DbgPrint("my_free: WARN: GlobalFree failed at %p", (DWORD)pMemBuff);  }
		#endif

	}  else { DbgPrint("ERR: attempt to free NULL ptr"); }
}




#else

// ######################################################################################################
// ##  DEBUG MEM FUNCTIONS, including pool tagging
// ######################################################################################################

#ifdef DO_MEMALLOC_LIST_CHECK

DWORD g_mFirstAllocationTicks = 0;	// timestamp when first call by my_alloc() was initiated, also used as init flag for g_mmList
CRITICAL_SECTION g_mmList;		// cs to guard access to memory ptrs list
LIST_CHUNK g_lHead;				// head of linked list
SIZE_T g_ListItemsCount;


VOID __mem_dbg_checkinit(LPSTR szCaller)
{
	// check if g_mFirstAllocationTicks should be filled and some other init
	if (!g_mFirstAllocationTicks) {
		g_mFirstAllocationTicks = GetTickCount();
		InitializeCriticalSection(&g_mmList);
		memset(&g_lHead, 0, sizeof(LIST_CHUNK));
		g_ListItemsCount = 0;
		DbgPrint("performed dbg init from [%s]", szCaller);
	}
}



/*
	removes a specified item from list
*/
BOOL mmRemoveFromList(LPSTR szCaller, LPVOID pPtr, LPSTR szAllocatorStr)
{
	BOOL bRes = FALSE;	// func result
	LIST_CHUNK *lPrevChunk;	// previous chunk	
	LIST_CHUNK *lChunk;		// current chunk

	__mem_dbg_checkinit(szCaller);

	EnterCriticalSection(&g_mmList);

	// check if we have any chunks
	if (g_lHead.lcNext) {

		lPrevChunk = NULL;
		lChunk = g_lHead.lcNext;

		while ((lChunk->pChunkPtr != pPtr) && (lChunk->lcNext)) {

			// move ptrs
			lPrevChunk = lChunk;
			lChunk = lChunk->lcNext;

		} // while !found & !list_end

		// check exit reason
		if (lChunk->pChunkPtr == pPtr) {

			//DbgPrint("deallocating at %p for %s, allocated by [%s]", pPtr, szCaller, szAllocatorStr);

			// remove it from list, if not first item
			if (lPrevChunk) { lPrevChunk->lcNext = lChunk->lcNext; } else { g_lHead.lcNext = lChunk->lcNext; }
			GlobalFree(lChunk);
			g_ListItemsCount--;
			bRes = TRUE;

			

		} // found chunk

	} else { DbgPrint("ERR: empty list for internal dealloc"); }

	LeaveCriticalSection(&g_mmList);

	return bRes;
}

/*
	Adds a link to list of an allocated memory region ptr
*/
VOID mmAddToList(LPSTR szCaller, LPVOID pPtr)
{
	LIST_CHUNK *lNewChunk;	// newly allocated item

	__mem_dbg_checkinit(szCaller);

	EnterCriticalSection(&g_mmList);

	// check and remove if passed ptr is already exists to prevent bogus behaviour
	if (mmRemoveFromList("int", pPtr, "int")) { /*DbgPrint("NOTE: removed a duplicating record about ptr %p", pPtr);*/ }

	// allocate new chunk
	lNewChunk = (LIST_CHUNK *)GlobalAlloc(GPTR, sizeof(LIST_CHUNK));
	lNewChunk->pChunkPtr = pPtr;

	// set next item for this chunk, if not first item
	lNewChunk->lcNext = g_lHead.lcNext;

	// add to head
	g_lHead.lcNext = lNewChunk;

	// inc counter 
	g_ListItemsCount++;

	LeaveCriticalSection(&g_mmList);
}

#endif

/*
	Allocates a memory buffer
*/
LPVOID my_alloc_int(LPSTR szCaller, SIZE_T lMemSize)
{
	LPVOID pAllocated = NULL;
	MEM_CHUNK_TAG mct;	// mem tag to be incorporated to a linked list
	DWORD lCallerLen;	// len of string passed
	DWORD dwOld;

#ifdef DO_MEMALLOC_LIST_CHECK
	__mem_dbg_checkinit(szCaller);
#endif

// check size for a sane value
	if (lMemSize) {

		

	#ifndef GLOBAL_ALLOC
		pAllocated = VirtualAlloc(NULL, lMemSize + sizeof(MEM_CHUNK_TAG) + (2 * GUARD_PAGE_SIZE), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	#else
		pAllocated = GlobalAlloc(GPTR, lMemSize + sizeof(MEM_CHUNK_TAG) + (2 * GUARD_PAGE_SIZE));
	#endif

		if (!pAllocated) { DbgPrint("my_alloc: WARNWARNWARN: failed to alloc size %u", (DWORD)lMemSize); return NULL; }

		// prepare mem tag
		memset(&mct, 0, sizeof(MEM_CHUNK_TAG));
		mct.dwSignature = MEM_CHUNK_SIGNATURE;
		mct.dwAllocatedStamp = GetTickCount();
		mct.wLen = sizeof(MEM_CHUNK_TAG);
		mct.dwAllocatedSize = lMemSize + sizeof(MEM_CHUNK_TAG);
		lCallerLen = lstrlenA(szCaller); if (lCallerLen > 127) { lCallerLen = 127; }
		memcpy(&mct.bCallerString[0], szCaller, lCallerLen);

		// copy to the start of allocated region
		memcpy(pAllocated, &mct, sizeof(MEM_CHUNK_TAG));

		// make guard pages, after tag
		memset( (LPVOID)((SIZE_T)pAllocated + sizeof(MEM_CHUNK_TAG)), 0x0a, GUARD_PAGE_SIZE);

		// after data
		memset((LPVOID)((SIZE_T)pAllocated + sizeof(MEM_CHUNK_TAG) + GUARD_PAGE_SIZE + lMemSize), 0x0b, GUARD_PAGE_SIZE);


		// set no-access
		//VirtualProtect((LPVOID)((SIZE_T)pAllocated + sizeof(MEM_CHUNK_TAG)), GUARD_PAGE_SIZE, PAGE_READONLY, &dwOld);
		//VirtualProtect((LPVOID)((SIZE_T)pAllocated + sizeof(MEM_CHUNK_TAG) + GUARD_PAGE_SIZE + lMemSize), GUARD_PAGE_SIZE, PAGE_READONLY, &dwOld);
		

#ifdef DO_MEMALLOC_LIST_CHECK
		// insert ptr to global linked list
		mmAddToList(szCaller, pAllocated);
#endif

		//DbgPrint("allocated at %p for %s", pAllocated, szCaller);

		return (LPVOID)((SIZE_T)pAllocated + sizeof(MEM_CHUNK_TAG) + GUARD_PAGE_SIZE);

	} else { DbgPrint("WARN: attempt to allocate 0 buffer"); return NULL; }

}

// returns amount of modified bytes if guard page contains some modifications
SIZE_T _memCheckGuardPage(LPVOID pGuard, SIZE_T lLen, BYTE bPattern)
{
	SIZE_T lRes = 0;
	BYTE *pb = (BYTE *)pGuard;
	SIZE_T lCount = lLen;

	while (lCount) {

		if (*pb != bPattern) { lRes++; }

		lCount--;
		pb++;
	}

	return lRes;
}


/*
	Deallocates buffer from my_alloc
*/
VOID my_free_int(LPSTR szCaller, PVOID pMemBuff_in)
{
	LPVOID pRealPtr = (LPVOID)((SIZE_T)pMemBuff_in - sizeof(MEM_CHUNK_TAG) - GUARD_PAGE_SIZE);
	MEM_CHUNK_TAG *mct = (MEM_CHUNK_TAG *)pRealPtr;

	SIZE_T lTamperCount = 0;	// amount of bytes tampered

	if (pMemBuff_in) {

		// check if this allocation was registered
		if (IsBadWritePtr(pRealPtr, sizeof(MEM_CHUNK_TAG)+1)) { DbgPrint("from[%s]:ERR: not writable chunk specified, possibly WRONG PTR", szCaller); return; }

		// check for tag header's signature
		if ((mct->dwSignature != MEM_CHUNK_SIGNATURE)||(mct->wLen != sizeof(MEM_CHUNK_TAG))) { DbgPrint("from[%s]:ERR: invalid signature in mem chunk", szCaller); return; }

		// check guard pages
		if (lTamperCount = _memCheckGuardPage((LPVOID)((SIZE_T)pMemBuff_in - GUARD_PAGE_SIZE), GUARD_PAGE_SIZE, 0x0a)) { DbgPrint("from[%s]:ERR: pre-data guard page tampered %u bytes", szCaller, lTamperCount); return; }
		if (lTamperCount = _memCheckGuardPage((LPVOID)((SIZE_T)pMemBuff_in + mct->dwAllocatedSize - sizeof(MEM_CHUNK_TAG)), GUARD_PAGE_SIZE, 0x0b)) { DbgPrint("from[%s]:ERR: post-data guard page tampered %u bytes", szCaller, lTamperCount); return; }

#ifdef DO_MEMALLOC_LIST_CHECK
		if (!mmRemoveFromList(szCaller, pRealPtr, (LPSTR)&mct->bCallerString)) { /*DbgPrint("from[%s]:WARN: list item not found for ptr %p, orig src is [%s]", szCaller, (DWORD)pRealPtr, &mct->bCallerString);*/ }
#endif

		#ifndef GLOBAL_ALLOC
			if (!VirtualFree(pRealPtr, 0, MEM_RELEASE)) { DbgPrint("from[%s]:my_free: WARN: VirtualFree failed for %04Xh", szCaller, pRealPtr); }
		#else
			if (GlobalFree(pRealPtr)) { 
				DbgPrint("from[%s]:WARN: GlobalFree failed at %p with code %04Xh", szCaller, (DWORD)pRealPtr, GetLastError()); 
			}
		#endif


	} else { DbgPrint("from[%s]:WARN: attempt to free NULL ptr", szCaller); } // pMemBuff
}


#ifdef DO_MEMALLOC_LIST_CHECK

VOID memDumpChunks()
{
	BOOL bRes = FALSE;	// func result
	LIST_CHUNK *lChunk;		// current chunk
	MEM_CHUNK_TAG *mct;

	__mem_dbg_checkinit("int");

	EnterCriticalSection(&g_mmList);

	// check if we have any chunks
	if (g_lHead.lcNext) {

		lChunk = g_lHead.lcNext;

		DbgPrint("-------------------  totally %u chunks", g_ListItemsCount);

		do  {

			// dump single line
			mct = (MEM_CHUNK_TAG *)lChunk->pChunkPtr;

			if (!IsBadWritePtr(lChunk->pChunkPtr, sizeof(MEM_CHUNK_TAG))) {

				if ((mct->dwSignature != MEM_CHUNK_SIGNATURE) || (mct->wLen != sizeof(MEM_CHUNK_TAG))) { DbgPrint("ERR: invalid mem chunk %p", lChunk); }

				DbgPrint("chunk=%p [%s] len %u al_st %p live %u sec", lChunk, &mct->bCallerString, mct->dwAllocatedSize, mct->dwAllocatedStamp, (DWORD)((mct->dwAllocatedStamp - g_mFirstAllocationTicks) / 1000));

			} else { DbgPrint("ERR: bad write ptr %p, stopping enum", lChunk->pChunkPtr); break; }

			// move ptr
			lChunk = lChunk->lcNext;

		} while (lChunk); // while have more chunks

		DbgPrint("======================================");
	}

	LeaveCriticalSection(&g_mmList);


}

/*
	Prints current allocation list to dbgout. Should be called after some time to catch
	memory leaks. 
	List contains allocation source (filename+line number), timestamp delta from current ticks, memory amount
	line by line.

	dwParam is some param to be displayed in msgbox header
*/
DWORD WINAPI memPrintAllocationListDialog(LPVOID dwParam)
{
	LPSTR szMsgHeader;

#if defined(DBG_MODULENAME)
	LPSTR szdbgModuleName = QUOTE(DBG_MODULENAME);
#else
	#pragma message("WARN: DBG_MODULENAME not defined, use C/C++ > Command Line > Additional options, like /DDBG_MODULENAME=\"name_of_module\"")
	LPSTR szdbgModuleName = "_unk_mod_";
#endif

	// prepare szMsgHeader
	szMsgHeader = (LPSTR)GlobalAlloc(GPTR, 10240);
	wsprintfA(szMsgHeader, "%s %u", szdbgModuleName, dwParam);

	while (TRUE) {

		MessageBoxA(NULL, "OK to dump allocation chunks", szMsgHeader, MB_OK);

		memDumpChunks();

	}

}

#endif


#endif