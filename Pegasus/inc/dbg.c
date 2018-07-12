/*
	dbg.c
 Misc debug-related routines. Used only in case of debug build

	Added support of module name in dbg out, which should be defined in
	C/C++ > Command Line > Additional options like
	/DDBG_MODULENAME="name_of_module"

 */


#include <windows.h>
#include "dbg.h"



#ifdef _DEBUG

/*
	NB: All procs here are compiled only in DEBUG mode


*/

#pragma message("WARN: DEBUG TOOLS COMPILED")

// dumps data into filename specified
VOID _dbgDumpToFile(PWCHAR wszTargetFName, PVOID pData, DWORD dwLen)
{
	HANDLE hFile;
	DWORD dwWritten;

	hFile = CreateFileW(wszTargetFName, GENERIC_READ + GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile!=INVALID_HANDLE_VALUE) {
		WriteFile(hFile, pData, dwLen, &dwWritten, 0);
		CloseHandle(hFile);
	}

}



// overhead for OutputDebugStringA adding misc extra information
VOID  _dbgOutString(LPSTR szDbgMsg)
{

	__try {

	LPSTR szBuff;	// target buffer for final string
	LPSTR szModuleName;

	LPSTR szEndLine = "\r\n";

#if defined(_M_X64)
	LPSTR szPlatform = "x64";
#elif defined(_M_IX86)
	LPSTR szPlatform = "x32";
#else
	LPSTR szPlatform = "xUNK";
#endif

	// source code name definition
#if defined(DBG_MODULENAME)
	LPSTR szdbgModuleName = QUOTE(DBG_MODULENAME);
#else
	#pragma message("WARN: DBG_MODULENAME not defined, use C/C++ > Command Line > Additional options, like /DDBG_MODULENAME=\"name_of_module\"")
	LPSTR szdbgModuleName = "_";
#endif

	LPSTR szLogFile;	// filename to log into
	HANDLE hFile = 0;	// file handle
	DWORD dwWritten;	// amount of bytes written by WriteFile, actually not used

	szBuff = (LPSTR)GlobalAlloc(GPTR, 12000);
	szModuleName = (LPSTR)GlobalAlloc(GPTR, 1024);
	szLogFile = (LPSTR)GlobalAlloc(GPTR, 1024);

	// query self module name
	GetModuleFileNameA(0, szModuleName, MAX_PATH + 1);
	lstrcpyA(szLogFile, szModuleName);
	lstrcatA(szLogFile, ".tlog");

	wsprintfA(szBuff, "%s(%04Xh:%u/%u)[%s %s]: %s", szModuleName, GetTickCount(), GetCurrentProcessId(), GetCurrentThreadId(), szdbgModuleName, szPlatform, szDbgMsg );



	// check if last 2 chars are \r\n
	if (lstrlenA(szBuff)>2) {

		// cut last 2 chars
		if (lstrcmpA( (LPSTR)( (SIZE_T)szBuff + lstrlenA(szBuff) - 2 ), szEndLine)) {

			// not equal, add newline
			lstrcatA(szBuff, szEndLine);

		} // compare last chars

	} // strlen check


	// output string
	OutputDebugStringA(szBuff);



	// dump to a logfile too
	hFile=CreateFileA(szLogFile, GENERIC_READ + GENERIC_WRITE, FILE_SHARE_READ + FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile!=INVALID_HANDLE_VALUE) {
		SetFilePointer(hFile, 0, NULL, FILE_END);
		WriteFile(hFile, szBuff, lstrlenA(szBuff), &dwWritten, NULL);
		CloseHandle(hFile);
	}


	// free some used mem
	GlobalFree(szBuff);
	GlobalFree(szModuleName);
	GlobalFree(szLogFile);

	} __except(1) { __try { OutputDebugStringA("dbg exception\r\n"); } __except(1) {} }

}




#endif
