/*
	RegFuncs.cpp
	Misc simple registry-related function

*/

#include <windows.h>


#include "mem.h"
#include "dbg.h"
#include "MyStringRoutines.h"

#include "RegFuncs.h"

#pragma comment (lib, "crypt32.lib")

/*
	Checks/creates a full reg path, assuming more than 1 subkey may be missed in
	a standart query
	hRootKey - usually HKEY_CURRENT_USER
	wszRegPath - registry path to check/create (NB: 32 is max deep)
	Returns:
	ERROR_SUCCESS if creation was ok, or some error code from last RegCreateKeyEx call
*/
LSTATUS RegCreatePath(HKEY hRootKey, LPCWSTR wszRegPath)
{
	HKEY hPrevKey, hCurrentKey;	// handle of reg subkeys being opened
	LPWSTR wszRegPathLocal;		// local buffer for reg path
	LPWSTR wszRPL_Pos;			// ptr to string at ^
	LPWSTR wszTmpStr;			// tmp string to hold every chunks of input string
	SIZE_T lBuffLen;			// calculated buffer's len
	LSTATUS lRes = ERROR_SUCCESS;				// RegCreateKeyEx result, func's initial result

		// create local copy of input data
		lBuffLen = (lstrlen(wszRegPath) * 2) + 1024;
		wszRegPathLocal = (LPWSTR)my_alloc(lBuffLen);
		wszTmpStr = (LPWSTR)my_alloc(lBuffLen);

		// copy string
		lstrcpy(wszRegPathLocal, wszRegPath);

		// replace all '\' with null terminator
		sr_replacechar(wszRegPathLocal, '\\', 0x00);

		// init pos ptr
		wszRPL_Pos = wszRegPathLocal;

		// init hPrevKey
		hPrevKey = hRootKey; // ???

		// perform loop
		while (lstrlen(wszRPL_Pos)) {

			DbgPrint("checking [%ws]", wszRPL_Pos);

			// try to open first. This is essential due to OS restriction on creating some root subkeys
			if (ERROR_SUCCESS != RegOpenKeyExW(hPrevKey, wszRPL_Pos, 0, KEY_READ + KEY_WRITE, &hCurrentKey)) {

				// read+write open failed, attempt read only
				if (ERROR_SUCCESS != RegOpenKeyExW(hPrevKey, wszRPL_Pos, 0, KEY_READ, &hCurrentKey)) {

					// even read failed, attempt to create this time
					lRes = RegCreateKeyExW(hPrevKey, wszRPL_Pos, 0, NULL, 0, KEY_READ + KEY_WRITE, NULL, &hCurrentKey, NULL);
					if (ERROR_SUCCESS != lRes) {

						DbgPrint("failed at [%ws] with code %04Xh(%u)", wszRPL_Pos, lRes, lRes);
						//return lRes;
						break;	// exit while loop to allow cleanup routines

					} // failed to create key

				} // open with read

			} // open with read+write

			// close unneeded handle
			if (hPrevKey != hRootKey) { RegCloseKey(hPrevKey); }

			// exchange handles
			hPrevKey = hCurrentKey;


			// move to next position using dirty pointer manipulation trick
			wszRPL_Pos = (LPWSTR)((SIZE_T)wszRPL_Pos + (SIZE_T)((lstrlen(wszRPL_Pos) + 1) * 2));


		} // loop iteration


		// free used mem
		my_free(wszRegPathLocal);
		my_free(wszTmpStr);


	return lRes;
}


/*
	Attempts to set reg DWORD value at HKEY_CURRENT_USER
*/
BOOL RegWriteDWORD(LPCWSTR wszRegPath, LPCWSTR wszKeyName, DWORD dwValueToSet)
{
	BOOL bRes = FALSE;	// function's result
	HKEY hKey;

	DbgPrint("wszRegPath=[%ws] wszKeyName=[%ws] dwValueToSet=%u", wszRegPath, wszKeyName, dwValueToSet);



		if (ERROR_SUCCESS == RegCreateKeyExW(HKEY_CURRENT_USER, wszRegPath, 0, NULL, 0, KEY_READ | KEY_WRITE, NULL, &hKey, NULL)) {

			//DbgPrint("key opened for write");

			if (ERROR_SUCCESS == RegSetValueExW(hKey, wszKeyName, 0, REG_DWORD, (PBYTE)&dwValueToSet, 4)) {

				//DbgPrint("value was set");
				bRes = TRUE;

			} // reg write ok

			// close reg
			RegFlushKey(hKey);
			RegCloseKey(hKey);
		} // reg key opened for write



	DbgPrint("func res %u", bRes);
	return bRes;
}


// removes specified value
BOOL RegRemoveValue(HKEY hRootKey, LPCWSTR wszRegPath, LPCWSTR wszRegKeyname)
{
	BOOL bResult = FALSE;	// function's result
	HKEY hKey;	// internal reg handle


		// try to open registry at specified path
		if (ERROR_SUCCESS != RegOpenKeyExW(hRootKey, wszRegPath, 0, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, &hKey)) { DbgPrint("RegOpenKeyEx failed"); return bResult; }

		// query param to determine needed buffer's len
		if (ERROR_SUCCESS != RegDeleteValueW(hKey, wszRegKeyname)) { /*DbgPrint("RegDeleteValue failed");*/ return bResult; }

		// essential to keep changes in case of sudden reboot
		RegFlushKey(hKey);

		RegCloseKey(hKey);

		// assign result
		bResult = TRUE;


	return bResult;

}

BOOL RegRemoveKey(HKEY hRootKey, LPCWSTR wszRegPath)
{

	if (ERROR_SUCCESS != RegDeleteKey(hRootKey, wszRegPath)) { DbgPrint("RegDeleteKey failed, le %p", GetLastError()); return FALSE; }

	return TRUE;
}