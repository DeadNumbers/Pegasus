/*
	NetMessageEnvelope.cpp
	Function to encoding and decoding messages circulating in local network via different transports (pipes, mailslots, etc)
*/

#include <windows.h>

#include "mem.h"
#include "dbg.h"
//#include "CryptoStrings.h"
#include "RandomGen.h"
//#include "MyStringRoutines.h"
//#include "HashedStrings.h"
//#include "DomainListMachines.h"
//#include "DataCallbackManager.h"
//#include "HashDeriveFuncs.h"
#include "CryptRoutines.h"



#include "NetMessageEnvelope.h"


/*
	Performs xor with key shift over passed buffer
*/
VOID nmeXorBuffer(LPVOID pBuffer, DWORD dwBufferLen, DWORD dwKeyIn)
{
	BYTE *pb = (BYTE *)pBuffer;
	DWORD dwCounter = dwBufferLen;
	DWORD dwKey = dwKeyIn;

	while (dwCounter) {

		*pb ^= (BYTE)dwKey;

		dwKey = (dwKey >> 5) | (dwKey << (32 - 5));

		pb++; dwCounter--;
	}

}


/*
	Adds a special envelope over binary data.
	It is used to check message integrity and transfer id (class) of message
*/
VOID nmeMakeEnvelope(LPVOID pBuffer, DWORD dwBufferLen, BYTE bMessageId, LPVOID *pEnveloped, DWORD *dwEnvelopedLen)
{
	NET_MESSAGE_ENVELOPE *pmEnvelope;	// to cast ptr to newly allocated buffer
	RndClass rg = { 0 };
	BYTE bHash[20] = { 0 };	// buffer to hold hash results
	ULONG ulBufferLen = 20;	// len of ^ buffer

	// *pEnveloped except first DWORD with random key
	LPVOID pVolatilePart;
	DWORD dwVolatilePartLen;

	// calc target buffer len
	*dwEnvelopedLen = sizeof(NET_MESSAGE_ENVELOPE) + dwBufferLen;
	*pEnveloped = my_alloc(*dwEnvelopedLen);

	// append original data
	memcpy((LPVOID)((SIZE_T)*pEnveloped + sizeof(NET_MESSAGE_ENVELOPE)), pBuffer, dwBufferLen);

	// cast ptr to fill values
	pmEnvelope = (NET_MESSAGE_ENVELOPE *)*pEnveloped;
	pmEnvelope->bMessageId = bMessageId;

	// fill random encode value
	rgNew(&rg);
	pmEnvelope->dwRandomKey = rg.rgGetRndDWORD(&rg);

	// prepare shifted ptrs
	pVolatilePart = (LPVOID)((SIZE_T)*pEnveloped + sizeof(DWORD));
	dwVolatilePartLen = *dwEnvelopedLen - sizeof(DWORD);

	// calc sha hash into temporary buffer
	if (!cryptCalcHashSHA(pVolatilePart, dwVolatilePartLen, (BYTE *)&bHash, &ulBufferLen)) { DbgPrint("ERR: failed to calc hash, packet will be unusable"); }

	// copy hash to resulting buffer
	memcpy(&pmEnvelope->bMessageHash, &bHash, 20);

	// make overall packet mangling using pmEnvelope->dwRandomKey
	nmeXorBuffer(pVolatilePart, dwVolatilePartLen, pmEnvelope->dwRandomKey);

}


/*
	Verify and decode network message. Returns TRUE on success.
	Modify original buffer, returns offset to real data start, caller should adjust buffer's len if needed
	Until all checks are done ok, no data modification performed
	NB: source buffer is not touched until full verification done ok
*/
BOOL nmeCheckRemoveEnvelope(LPVOID pBufferIn, DWORD *dwBufferLen, BYTE *bMessageId)
{
	BOOL bRes = FALSE;	// function result

	LPVOID pBufferLocal = NULL;	// local copy of input buffer

	NET_MESSAGE_ENVELOPE *pmEnvelope; // casted copy of input buffer

	LPVOID pVolative;
	DWORD dwVolatileLen = *dwBufferLen - sizeof(DWORD);

	BYTE bHash[20] = { 0 };	// buffer to hold hash from decoded input
	BYTE bHashCalculated[20];	// calculated hash value of source data with hash field nulled
	ULONG ulBufferLen = 20;	// len of ^ buffer

	do {	// not a loop

		// check for sane len
		if (*dwBufferLen < sizeof(NET_MESSAGE_ENVELOPE) + 1) { DbgPrint("ERR: too small message received (%u), min len %u", *dwBufferLen, sizeof(NET_MESSAGE_ENVELOPE) + 1); break; }

		// copy into local buffer
		pBufferLocal = my_alloc(*dwBufferLen);
		memcpy(pBufferLocal, pBufferIn, *dwBufferLen);

		// assign local ptrs
		pmEnvelope = (NET_MESSAGE_ENVELOPE *)pBufferLocal;
		pVolative = (LPVOID)((SIZE_T)pBufferLocal + sizeof(DWORD));

		// decode buffer
		nmeXorBuffer(pVolative, dwVolatileLen, pmEnvelope->dwRandomKey);

		// save hash to local
		memcpy(&bHash, &pmEnvelope->bMessageHash, 20);

		// wipe hash from input for proper calculation
		memset(&pmEnvelope->bMessageHash, 0, 20);

		// calc hash into tmp buffer
		if (!cryptCalcHashSHA(pVolative, dwVolatileLen, (BYTE *)&bHashCalculated, &ulBufferLen)) { DbgPrint("ERR: failed to calc hash, check failed"); break; }

		// compare hashes
		if (!memcmp(&bHash, &bHashCalculated, 20)) {

			//DbgPrint("hash check OK");

			// save results
			*dwBufferLen = *dwBufferLen - sizeof(NET_MESSAGE_ENVELOPE);
			*bMessageId = pmEnvelope->bMessageId;

			// overwrite mem contents via tmp buffer
			memcpy(pBufferIn, (LPVOID)((SIZE_T)pBufferLocal + sizeof(NET_MESSAGE_ENVELOPE)), *dwBufferLen);
			memset((LPVOID)((SIZE_T)pBufferIn + *dwBufferLen), 0, sizeof(NET_MESSAGE_ENVELOPE));	// wipe original contents

			// done ok
			bRes = TRUE;

		} else { DbgPrint("ERR: hash check failed, invalid packet"); break; }


	} while (FALSE);	// not a loop


	if (pBufferLocal) { my_free(pBufferLocal); }

	return bRes;
}