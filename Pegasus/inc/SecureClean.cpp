/*
	SecureClean.cpp
	Secure cleaning functions, used by misc modules from wdd's api
*/

#include <windows.h>

#include "dbg.h"
#include "mem.h"	
#include "RandomGen.h"
#include "MyStringRoutines.h"

#include "SecureClean.h"

/*
	Fills buffer with random data, size may not be dword-aligned.
	rg assumed to be already initialized
*/
BOOL scFillRandom(RndClass *rg, LPVOID pBuffer, SIZE_T lBufferLen)
{
	BOOL bRes = FALSE;
	SIZE_T lCounter = lBufferLen;
	DWORD *pdw = (DWORD *)pBuffer;
	BYTE *pb = NULL;

	while (lCounter > sizeof(DWORD)) {

		*pdw = rg->rgGetRndDWORD(rg);

		pdw++;
		lCounter -= sizeof(DWORD);

	} // dword steps

	// second part - byte steps
	pb = (BYTE *)pdw;
	while (lCounter) {

		*pb = (BYTE)rg->rgGetRndDWORD(rg);

		pb++;
		lCounter--;

	} // byte steps

	bRes = TRUE;

	return bRes;
}

/*
	Writes data from pWipeBuffer into already opened file.
	Positioning is done internally.
	File length should be specified at i64FileLen
*/
BOOL scOverwriteFile(HANDLE hFile, LPVOID pWipeBuffer, SIZE_T lWipeBufferLen, UINT64 i64FileLen)
{
	BOOL bRes = FALSE;

	UINT64 i64Size = i64FileLen;

	DWORD dwWritten = 0;

	do {	// not a loop

		// do wipeover
		if (INVALID_SET_FILE_POINTER == SetFilePointer(hFile, 0, NULL, FILE_BEGIN)) { DbgPrint("ERR: SetFilePointer() failed, code %u", GetLastError()); break; }

		while (i64Size) {

			// write buffer contents
			DbgPrint("writing %u of %u", lWipeBufferLen, i64Size);

			if (!WriteFile(hFile, pWipeBuffer, lWipeBufferLen, &dwWritten, NULL)) { DbgPrint("WARN: err %u while wiping", GetLastError()); break; }
			if (!FlushFileBuffers(hFile)) { DbgPrint("WARN: err %u while flushing", GetLastError()); break; }

			// adjust counters
			i64Size -= dwWritten;

		} // while i64Size

		bRes = TRUE;

	} while (FALSE);	// not a loop

	return bRes;
}


/*
	Renames file to some dummy pattern and deletes it after it
	NB: we may receive network filepath here
	Should not fail if file rename failed. 
	Should delete both file (orig and destination), to protect from some errors
	wszFilename max length is 10240 bytes, length is NOT checked
*/
BOOL scRenameDeleteFile(LPWSTR wszFilename, RndClass *rg)
{
	BOOL bRes = FALSE;

	LPWSTR wszTarget = NULL;	// target filename
	LPWSTR wszNameAtTarget = NULL;	// some ptr at ^ pointing to a file's name

	DbgPrint("entered for [%ws]", wszFilename);

	do {	// not a loop

		// alloc a new buffer
		wszTarget = (LPWSTR)my_alloc(10240);
		lstrcpy(wszTarget, wszFilename);

		// find last '\', if any, to be used as filename's start
		wszNameAtTarget = sr_findlastchar(wszTarget, '\\');
		if (!wszNameAtTarget) { wszNameAtTarget = wszTarget; } 
		DbgPrint("name only found [%ws]", wszNameAtTarget);

		// gen target rnd name
		memset(wszNameAtTarget, 0, 9);
		sr_genRandomCharsRG(rg, 1, 8, wszNameAtTarget);
		DbgPrint("target name [%ws]", wszNameAtTarget);

		// try to rename
		if (!MoveFileEx(wszFilename, wszTarget, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) { DbgPrint("WARN: failed to move file from [%ws] to [%ws], le %u", wszFilename, wszTarget, GetLastError()); }

		// delete both files
		if (!DeleteFile(wszTarget)) { DbgPrint("WARN: failed to remove [%ws] le %u", wszTarget, GetLastError()); } else { bRes = TRUE; }
		DeleteFile(wszFilename);

	} while (FALSE);	// not a loop

	return bRes;
}


/*
	Checks if passed file has read-only attrs and attempts to remove it
*/
VOID scChkRemoveReadOnly(LPWSTR wszFilename)
{
	DWORD dwAttrs = INVALID_FILE_ATTRIBUTES;

	do {	// not a loop

		dwAttrs = GetFileAttributes(wszFilename);
		if (dwAttrs == INVALID_FILE_ATTRIBUTES) { DbgPrint("le %u attempting to query attribs for [%ws]", GetLastError(), wszFilename); break; }

		// check for read-only flag
		if (dwAttrs & FILE_ATTRIBUTE_READONLY) {

			DbgPrint("NOTE: [%ws] has RO attr, attempting to remove it", wszFilename);

			if (!SetFileAttributes(wszFilename, dwAttrs & ~FILE_ATTRIBUTE_READONLY)) { DbgPrint("ERR: failed to remove RO attr, le %u", GetLastError()); break; }

		}

	} while (FALSE);	// not a loop

}


/*
	Securely delete contents of a file on remote or local storage, identified by wszFilename
*/
#define SC_WRITE_BUFFER_LEN 1024768
BOOL scSecureDeleteFile(LPWSTR wszFilename)
{
	BOOL bRes = FALSE;

	HANDLE hFile = INVALID_HANDLE_VALUE;	// target file's handle
	DWORD dwLE = ERROR_SUCCESS;	// last error stamp, to be returned to client

	DWORD dwFilesizeHigh = 0;
	UINT64 i64Size = 0;	// file size, full length

	LPVOID pWipeData = NULL;	// buffer with wipe data to be written to file
	SIZE_T lWipeDataLen = 0;	// len of data in ^ buffer

	RndClass rg = { 0 };	// random gen class



	do {	// not a loop

		// try to open file to rewrite it's contents
		hFile = CreateFile(wszFilename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (INVALID_HANDLE_VALUE == hFile) { dwLE = GetLastError(); DbgPrint("ERR: failed to open [%ws] for write, le %u", wszFilename, dwLE); scChkRemoveReadOnly(wszFilename); break; }

		// query full file size
		i64Size = GetFileSize(hFile, &dwFilesizeHigh);
		i64Size += ((UINT64)dwFilesizeHigh << 32);

		if (i64Size) {

			DbgPrint("asked to wipe file of (%u) %u len", dwFilesizeHigh, (DWORD)i64Size);

			// select wipe buffer length
			lWipeDataLen = SC_WRITE_BUFFER_LEN;
			if (i64Size < lWipeDataLen) { lWipeDataLen = (SIZE_T)i64Size; }
			DbgPrint("selected wipe buffer len %u", lWipeDataLen);

			// allocate resulting buffer
			pWipeData = my_alloc(lWipeDataLen);

			// fill it with rnd data
			rgNew(&rg);
			rg.rgInitSeedFromTime(&rg);	
			scFillRandom(&rg, pWipeData, lWipeDataLen);

			// do wipe
			if (!scOverwriteFile(hFile, pWipeData, lWipeDataLen, i64Size)) { DbgPrint("ERR: initial wipe failed"); break; }

			// make buffer clean
			memset(pWipeData, 0, lWipeDataLen);

			// do second wipe with empty buffer
			if (!scOverwriteFile(hFile, pWipeData, lWipeDataLen, i64Size)) { DbgPrint("ERR: second wipe failed"); break; }

			// close handle
			CloseHandle(hFile);
			hFile = INVALID_HANDLE_VALUE;

			// now rename file and do deletion
			bRes = scRenameDeleteFile(wszFilename, &rg);

		} else { DbgPrint("WARN: file is empty"); }


	} while (FALSE);	// not a loop

	// cleanup, if needed
	if (hFile != INVALID_HANDLE_VALUE) { CloseHandle(hFile); }

	SetLastError(dwLE);
	return bRes;
}