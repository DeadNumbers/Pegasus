/*
	WOW64Detect.cpp
 Routines to detect x64 OS while running from x32 (or x64) binary

*/

#include <windows.h>

#include "dbg.h"
#include "mem.h"
#include "CryptoStrings.h"


#include "WOW64Detect.h"


/*
	Check if we are running on x64 OS
	http://msdn.microsoft.com/en-us/library/windows/desktop/ms684139%28v=vs.85%29.aspx
*/
BOOL IsX64Windows()
{
#if defined(_M_X64)
	// in case of x64 targer, just return TRUE, essential for server request
	return TRUE;
#elif defined(_M_IX86)
	BOOL bRes = FALSE;	// func res
	LPWSTR wszS;
	LPSTR szS;
	LPFN_ISWOW64PROCESS fnIsWow64Process;
	HMODULE hKernel32;

	__try {

		// get kernel32 handle
		wszS = CRSTRW("kernel32", "\xff\x1f\x19\x0c\xf7\x1f\x12\x01\xfd\x09\xfc\xe8\x5c\xb5\x60");
		hKernel32 = GetModuleHandle(wszS);
		my_free(wszS);
		if (hKernel32) {

			// query IsWow64Process api
			szS = CRSTRA("IsWow64Process", "\xff\xbf\x47\x0c\xf1\xbf\x6e\x17\xd8\xa8\xb0\xb2\x5b\x77\x95\xcb\x2c\x62\xf4\xb7\x10\x41\x13");
			fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(hKernel32, szS);
			my_free(szS);
			if (NULL != fnIsWow64Process) {

				if (!fnIsWow64Process(GetCurrentProcess(),&bRes)) {
					// handle error
					DbgPrint("WARN: fnIsWow64Process returned failure");
					bRes = FALSE;
				}
			} // fnIsWow64Process


		} // got kernel32 handle


	} __except(1) { DbgPrint("WARN: exception"); }

	DbgPrint("res=%u", bRes);
	return bRes;
#endif
}