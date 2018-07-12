/*

	machineid.cpp
	Compatible machine id calculation

*/


#include <windows.h>

#include "mem.h"
#include "dbg.h"
#include "CryptoStrings.h"

#include "machineid.h"


// perform rol operation on 32-bit argument
static DWORD rol(DWORD dwArg, BYTE bPlaces)
{
    return ( (dwArg<<bPlaces)|(dwArg>>(32-bPlaces)) );
}

// make dword hash from string
DWORD _myHashStringW(LPWSTR wszString) 
{
    DWORD dwResult = 0;	// output result, temp hash value
    BYTE b_cr = 0;	// cr shift value
    ULONG i = 0;	// counter
	WORD *pwChar = (WORD *)wszString;

    // loop passed string
	while (*pwChar) {

        // make step's shift value, normalized to 4-byte shift (31 max)
		b_cr = (b_cr ^ (BYTE)(*pwChar)) & 0x1F;

        // xor hash with current char and rol hash, cr
		dwResult = rol(dwResult ^ (BYTE)(*pwChar), b_cr);

		pwChar++;

    }	// while !null char


    // output result
    return dwResult;
}

/*
	internal func
	Calculates hash for name of first physical disk
	HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Disk\Enum, value name "0"
*/
DWORD _hwsFirstVolumeModelHash()
{
	DWORD dwRes = 0;	// func res
	HKEY hKey = NULL;	// RegOpenKeyEx() res
	LPWSTR wszSubkey, wszParamName;	// decrypt string buff
	DWORD dwDataLen = 0;	// key len
	LPWSTR wszBuff = NULL;	// key buff

	wszSubkey = CRSTRW("SYSTEM\\CurrentControlSet\\services\\Disk\\Enum", "\xfd\x3f\x14\x05\xd6\x3f\x27\x34\xde\x13\xd1\xc0\x31\xe4\xc1\xdf\x3f\xe2\xba\xb9\x6e\x88\x9a\x99\x7f\xa8\x78\x5e\x88\x53\x68\x5e\xa8\x75\x22\x24\xce\x02\x07\x31\xc9\x2e\xe7\xe6\x31\xe2\xda\xd8\x20\x30\xe4");
	wszParamName = CRSTRW("0", "\x00\xc0\x92\x0e\x01\xc0\xc2");

	do {	// not a loop

		if (ERROR_SUCCESS != RegOpenKeyEx(HKEY_LOCAL_MACHINE, wszSubkey, 0, KEY_READ, &hKey)) { DbgPrint("ERR: RegOpenKeyEx() failed %04Xh", GetLastError()); break; }

		// key opened ok, query value
		if (ERROR_SUCCESS != RegQueryValueEx(hKey, wszParamName, NULL, NULL, NULL, &dwDataLen)) { DbgPrint("ERR: RegQueryValueEx() failed %04Xh", GetLastError()); break; }

		// alloc buff
		if (!(wszBuff = (LPWSTR)my_alloc((dwDataLen + 1) * 2))) { DbgPrint("ERR: failed to alloc %u bytes", ((dwDataLen + 1) * 2) ); break; }
		
		if (ERROR_SUCCESS != RegQueryValueEx(hKey, wszParamName, NULL, NULL, (LPBYTE)wszBuff, &dwDataLen)) { DbgPrint("ERR: RegQueryValueEx() failed %04Xh", GetLastError()); break; }

		// calc hash and store it
		dwRes = _myHashStringW(wszBuff);

	} while (FALSE);	// not a loop

	if (wszBuff) { my_free(wszBuff); }
	if (hKey) { RegCloseKey(hKey); }

	my_free(wszParamName);
	my_free(wszSubkey);

	return dwRes;
}

// main magic is done here
UINT64 i64MakeMachineID()
{
	ULONG iBufferSize = MAX_COMPUTERNAME_LENGTH + 1;

    LPWSTR wszCompName;	// buffer for computer's name
    DWORD dwHash2;

    // and part2 using Computer name
	wszCompName = (LPWSTR)my_alloc(iBufferSize * 2);
		GetComputerName(wszCompName, &iBufferSize);
		dwHash2 = _myHashStringW(wszCompName);
	my_free(wszCompName);


    // dwHash1 & dwHash2 now contain the resulting parts of machine id hash
    return (UINT64)( ((UINT64)_hwsFirstVolumeModelHash() << 32) | (UINT64)dwHash2 );

} // func end

