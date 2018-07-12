/*
	shellcode.h
*/

#pragma once

#include <windows.h>
#include <winternl.h>

// generic dll entrypoint definition
typedef  BOOL (WINAPI *DLLEntryPoint) (HINSTANCE, DWORD, LPVOID);

// shellcode's entrypoint definition - used by installer for direct calls
typedef VOID(WINAPI *ShellcodeEntryPoint) (LPVOID);

// signature at SHELLCODE_CONTEXT structure, used to search for structure's start (to be removed)
//#define SHELLCODE_CONTEXT_SIGNATURE 0xB3B4B6B8

// communication structure describing fields passed after shellcode
// used at initial run when executed via pipe chunk and when remapped by injection module(s)
#pragma pack(push)
#pragma pack(1)

// NB: prel* ptrs are RELATIVE to this structure's start
typedef struct _SHELLCODE_CONTEXT
{
//	DWORD dwSignature;	// should be SHELLCODE_CONTEXT_SIGNATURE in order shellcode be able to find this structure	(?: possibly for removal)
	DWORD dwStructureLen;	// len of structure itself, to prevent from errors when working with different versions

	DWORD dwShellcodeLen;	// len of shellcode itself, so some callers may get ptr to the shellcode residing before this structure and copy for usage in other processes
	DWORD dwFullChunkLen;	// full length of structure + all appended binary buffers (INCLUDING SHELLCODE), used when need to copy it to some other process
	DWORD dwShellcodeEntrypointOffset;	// offset to shellcode's entry, for it's reusage later

	BYTE bNoReturnFromShellcode;	// set to TRUE when shellcode is used for injection in other process, to prevent problems

	// *** NB: relative ptrs should be recalculated to platform-native absolute ptr ***

	// IDD & WDD ptrs, used to modify execution target when copying binpack between different targets
	DWORD prelIDD;	// NB: rel ptr
	DWORD dwIDDLen;

	DWORD prelWDD; // NB: rel ptr. NB2: binpack with all modules is appended after WDD
	DWORD dwWDDLen;

	// rel ptr to dll to be executed in this binpack (may be changed to IDD or WDD)
	DWORD prelExecDll;	// NB: rel ptr
	DWORD dwExecDllLen;

	BYTE bRemoveFilePath[MAX_PATH * 2];		// source file to be removed, set at injection stage, performed by WDD

} SHELLCODE_CONTEXT, *PSHELLCODE_CONTEXT;

#pragma pack(pop)



// Redefine PEB structures. The structure definitions in winternl.h are incomplete.

// x32 & x64 ok
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

/*
// msdn
typedef struct _MY_PEB_LDR_DATA {
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

// msdn
typedef struct _MY_LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID EntryPoint;
	PVOID Reserved3;
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	};
	ULONG TimeDateStamp;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

*/

