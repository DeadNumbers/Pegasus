/*
	WOW64Detect.h
 Headers file

*/

#include <windows.h>

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL); // api definition

BOOL IsX64Windows();