/*
	DynImports.h
 Headers file
*/


#include <windows.h>

#include <winternl.h>

// Redefine PEB structures. The structure definitions in winternl.h are incomplete.
// copy from shellcode version

typedef struct _MY_PEB {
  BYTE InheritedAddressSpace;
  BYTE ReadImageFileExecOptions;
  BYTE BeingDebugged;
  BYTE Spare;
  LPVOID Mutant;
  LPVOID ImageBaseAddress;
  LPVOID LoaderData;
  LPVOID ProcessParameters;
  LPVOID SubSystemData;
  LPVOID ProcessHeap;
  LPVOID FastPebLock;
  LPVOID FastPebLockRoutine;
  LPVOID FastPebUnlockRoutine;
  LPVOID EnvironmentUpdateCount;
  LPVOID KernelCallbackTable;
  LPVOID SystemReserved;
  LPVOID AtlThunkSListPtr32;
} MY_PEB, *PMY_PEB;


typedef struct _MY_PEB_LDR_DATA {
    ULONG Length;
	BOOL Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY
{
	 LIST_ENTRY InLoadOrderLinks;
	 LIST_ENTRY InMemoryOrderLinks;
	 LIST_ENTRY InInitializationOrderLinks;
	 PVOID DllBase;
	 PVOID EntryPoint;
	 ULONG SizeOfImage;
	 UNICODE_STRING FullDllName;
	 UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;


// global internal struct
typedef struct _diLibsState
{
	WORD wStructSize;	// size of structure

	// dlls directory path
	LPWSTR wszSystemDllPath;	// like 'c:\windows\system32\'
	LPWSTR wszSystemDllSeekMask; // like 'c:\windows\system32\*.*'

	// guard cs 
	CRITICAL_SECTION csGuard;

	// already found records (libraries, apis)
	// in a form of linked list
	// ...

} diLibsState, *PdiLibsState;


// definition of enum func for diEnumExports()
typedef BOOL (__stdcall *PDI_ENUM_EXPORTS_CALLBACK)( LPSTR szExportName, LPVOID pFuncAddr, LPVOID pParameter );	// should return FALSE to stop enum
typedef PDI_ENUM_EXPORTS_CALLBACK LPDI_ENUM_EXPORTS_CALLBACK;


// declarations
#ifdef __cplusplus
extern "C" {
#endif
	HMODULE LoadLibraryByHash(UINT64 i64Hash, BOOL bMemLoadDependencies, BOOL bCallDllMain);
	BOOL LoadAPIs(HMODULE hLib, PUINT64 pi64HashesArray, UINT iElementsCount, LPVOID pStorePtrsArray);
	UINT64 diHashName(LPWSTR wszNameToHashIn);
	BOOL diLoadAPI(HMODULE hLib, UINT64 i64Hash, LPVOID *pStorePlace);
	LPWSTR diGetSystemDllsPath();
	BOOL diEnumExports(HMODULE hLib, PDI_ENUM_EXPORTS_CALLBACK pEnumFunc, LPVOID pParameter);
	HMODULE GetModuleHandleByHash(UINT64 i64Hash);
#ifdef __cplusplus
}
#endif