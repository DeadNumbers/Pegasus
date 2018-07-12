/*
	dbg.h
 Debug logging and output functions
*/
#pragma once
#include <windows.h>

#ifdef _DEBUG

// debug version


#ifdef __cplusplus
extern "C" {
#endif
	VOID _dbgDumpToFile(PWCHAR wszTargetFName, PVOID pData, DWORD dwLen);
	VOID  _dbgOutString(LPSTR szDbgMsg);
#ifdef __cplusplus
}
#endif


// new dbg
#define QUOTE_(WHAT) #WHAT
#define QUOTE(WHAT) QUOTE_(WHAT)

#pragma warning(disable:4996) // 'sprintf': This function or variable may be unsafe.
#define  DbgPrint(fmt, ...) \
		{ LPSTR buff = (LPSTR)GlobalAlloc(GPTR, 0x10000); \
			wsprintfA(buff, "%s: "fmt, __FILE__"@"__FUNCTION__"@"QUOTE(__LINE__), ## __VA_ARGS__); \
			_dbgOutString(buff); \
		  GlobalFree(buff); } 

#define _return DbgPrint("this would cause proc to exit, ignoring due to debug mode")

#else

// release version
// all macro are assumed to be null

#define  DbgPrint(args, ...) 
#define  _dbgDumpToFile(args, ...) 

#define _return return


#endif

