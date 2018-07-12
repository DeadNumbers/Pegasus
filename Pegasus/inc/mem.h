/*
	mem.h
	Headers file
*/

#pragma once
#include <windows.h>

#ifdef _DEBUG
//#if defined(_M_IX86)
#define ALLOW_DBGMEM
#define DO_MEMALLOC_LIST_CHECK
//#endif
#endif

#define MEM_CHUNK_SIGNATURE 0x0BBBBBBBB
#define GUARD_PAGE_SIZE 4096*4

/*
	Used in debug mode to tag every
*/
typedef struct _MEM_CHUNK_TAG
{
	DWORD dwSignature;	// special signature
	WORD wLen;			// len of this structure
	DWORD dwAllocatedStamp;	// ticks count when this chunk was allocated
	BYTE bCallerString[128];	// buffer with caller name string
	DWORD dwAllocatedSize;	// total size of allocated buffer, including this tag
} MEM_CHUNK_TAG, *PMEM_CHUNK_TAG;

// single chunk pointer by linked list
typedef struct _LIST_CHUNK LIST_CHUNK;
typedef struct _LIST_CHUNK
{
	LIST_CHUNK *lcNext;
	LPVOID pChunkPtr;

} LIST_CHUNK, *PLIST_CHUNK;


#ifdef ALLOW_DBGMEM
	// in debug mode, each my_alloc() is a special macro which sends source code sign
	// to be added to memory chunk
	#define QUOTE_(WHAT) #WHAT
	#define QUOTE(WHAT) QUOTE_(WHAT)
	#define my_alloc(lMemSize) my_alloc_int(__FUNCTION__"@"QUOTE(__LINE__), lMemSize)  
	#define my_free(pMemBuff_in) my_free_int(__FUNCTION__"@"QUOTE(__LINE__), pMemBuff_in)  
#ifdef __cplusplus
extern "C" {
#endif
	LPVOID my_alloc_int(LPSTR szCaller, SIZE_T lMemSize);
	VOID my_free_int(LPSTR szCaller, PVOID pMemBuff_in);
#ifdef DO_MEMALLOC_LIST_CHECK
	DWORD WINAPI memPrintAllocationListDialog(LPVOID dwParam);
#endif
#ifdef __cplusplus
}
#endif

#else


// release mode functions

#ifdef __cplusplus
extern "C" {
#endif
	LPVOID my_alloc(SIZE_T lMemSize);
	VOID my_free(PVOID pMemBuff);
#ifdef __cplusplus
}
#endif

#endif



#define GLOBAL_ALLOC	// if not defined, VirtualAlloc will be used
