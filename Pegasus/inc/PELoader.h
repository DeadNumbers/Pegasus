/*
	PELoader.h
 Headers file

*/

#pragma once

#include <windows.h>

#define		PeSupGetImagePeHeader(Image)	(PIMAGE_NT_HEADERS *)(##Image+*(DWORD *)(##Image+0x3C));

#define		PeSupGetOptionalField(PeHeader, Field)												\
	(FIELD_OFFSET(IMAGE_OPTIONAL_HEADER32, ##Field) != FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, ##Field) && \
	((PIMAGE_NT_HEADERS32)PeHeader)->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ?	\
	((PIMAGE_NT_HEADERS64)PeHeader)->OptionalHeader.##Field :								\
	((PIMAGE_NT_HEADERS32)PeHeader)->OptionalHeader.##Field)

#define		PeSupGetDirectoryEntryPtr(PeHeader, Entry)												\
	(((PIMAGE_NT_HEADERS32)PeHeader)->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ?		\
	&((PIMAGE_NT_HEADERS64)PeHeader)->OptionalHeader.DataDirectory[##Entry] :					\
	&((PIMAGE_NT_HEADERS32)PeHeader)->OptionalHeader.DataDirectory[##Entry])

#define		PeSupGetOptionalField(PeHeader, Field)												\
	(FIELD_OFFSET(IMAGE_OPTIONAL_HEADER32, ##Field) != FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, ##Field) && \
	((PIMAGE_NT_HEADERS32)PeHeader)->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ?	\
	((PIMAGE_NT_HEADERS64)PeHeader)->OptionalHeader.##Field :								\
	((PIMAGE_NT_HEADERS32)PeHeader)->OptionalHeader.##Field)

#ifndef IMAGE_SIZEOF_BASE_RELOCATION
#define IMAGE_SIZEOF_BASE_RELOCATION 8
#endif

#define IMAGE_REL_BASED_SHIFT 12
#define IMAGE_REL_BASED_MASK 0xFFF

typedef struct _IMAGE_BASE_RELOCATION_EX {
	DWORD   VirtualAddress;
	DWORD   SizeOfBlock;
	WORD    TypeOffset[1];
} IMAGE_BASE_RELOCATION_EX;
typedef IMAGE_BASE_RELOCATION_EX UNALIGNED * PIMAGE_BASE_RELOCATION_EX;

#define RVATOVA( base, offset )(((SIZE_T)(base) + (SIZE_T)(offset)))


typedef  int (_stdcall *EntryPoint)(HANDLE, DWORD, LPVOID);





#ifndef SHELLCODE_MODE
	// usual style
	BOOL PELoad(LPVOID pPE, LPVOID *pImage, SIZE_T *lImageSize, LPVOID *pEntryPoint );


#else

	// apis to be passed by shellcode startup code
	typedef struct _SHELLCODE_APIS
	{
		BYTE bSize;	// verification field

		// apis from kernel32.dll
		LPVOID (WINAPI *p_VirtualAlloc) (LPVOID pAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
		BOOL (WINAPI *p_VirtualFree) (LPVOID pAddress, SIZE_T dwSize, DWORD dwFreeType);
		FARPROC (WINAPI *p_GetProcAddress) (HMODULE hModule, LPCSTR lpProcName);
		HMODULE (WINAPI *p_LoadLibraryA) (LPCSTR lpFileName);
		VOID (WINAPI *p_ExitProcess) (UINT uExitCode);
		VOID (WINAPI *p_Sleep) (DWORD dwMilliseconds);

		// dbg-only
		//VOID(WINAPI *p_OutputDebugStringA)(LPCSTR szDbgString);

	} SHELLCODE_APIS, *PSHELLCODE_APIS;


	// shellcode style
	BOOL PELoad(SHELLCODE_APIS *pAPIs, LPVOID pPE, LPVOID *pImage, SIZE_T *lImageSize, LPVOID *pEntryPoint );

#endif