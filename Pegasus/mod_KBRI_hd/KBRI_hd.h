/*
	KBRI_hd.h
*/

#include <windows.h>

// description of hooked functions
typedef BOOL(WINAPI *f_MoveFileExW)(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, DWORD dwFlags);

// global vars structure
typedef struct _KHD_GLOBALS
{
	LPVOID pStubs;	// buffer to hold all the stubs. Ptrs to call orig funcs will point here

	// hook stubs to call original function, ptrs to some place at pStubs
	f_MoveFileExW p_MoveFileExW;	

} KHD_GLOBALS, *PKHD_GLOBALS;




VOID khdSetHooks();