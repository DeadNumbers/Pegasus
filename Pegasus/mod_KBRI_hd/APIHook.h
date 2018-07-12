/*
	APIHook.h
	Headers file
*/

#include <windows.h>


// max size of stub code in bytes
#if defined(_M_X64)
	// x64
	#define HOOK_STUB_MAXLEN 45	
	#define MIN_STUB_LEN 12
#else
	// x32
	#define HOOK_STUB_MAXLEN 20	
	#define MIN_STUB_LEN 5
#endif



void patch_function(LPVOID address, unsigned char *stub, unsigned char *hook, DWORD *stub_len);
BOOL hkHook(HMODULE hModule, LPSTR szFunctionName, LPVOID pHook, LPVOID pStub, LPVOID *pToCallOrig);