/*
	MailslotWorks.h
*/
#pragma once

#include <windows.h>
#include "DataCallbackManager.h"

#define MAILSLOT_MSG_BUFFER_SIZE 1024

// MAILSLOT_MESSAGE_ENVELOPE.bMessageId, specified in header
typedef enum ENUM_MAILSLOT_MESSAGE_ID {
	MMI_NONE = 0,	// nothing defined
	MMI_CREDENTIALS,			// CredManager.cpp use to broadcast it's auth creds
	MMI_NETWORK_ENABLED_SEARCH,	// NetworkConnectivity.cpp, issue this to search for network-enabled machines
	MMI_NETWORK_ENABLED_ANSWER,	// -//-, every machine with remote network working answers with this code and self name appended in pData 

	MMI_MAXVAL = MAXBYTE	// max value to fit into byte
};

// params passed to callback function from mwSendMailslotMessageToAllDomains()
typedef struct _MW_CALLBACK_PARAMS {
	LPVOID pData;		// data buffer to be broadcasted, <400 bytes recommended
	DWORD dwDataLen;	// len of data in ^ to be sent
	BYTE bMailslotMessageId;	// id of message to be sent, set in header
	
	DWORD dwMessagesSent;	// amount of successfully sent messages (used by func to determine if any domain was enumed)

} MW_CALLBACK_PARAMS, *PMW_CALLBACK_PARAMS;

// for mwInitMailslotServer() to pass params to server thread
typedef struct _MW_INITSERVER_PARAMS {
	
	CLIENTDISPATCHERFUNC cdCallback;	// callback to be issued on each data received
	HANDLE hSlot;						// server mailslot handle to wait forever on

} MW_INITSERVER_PARAMS, *PMW_INITSERVER_PARAMS;



// define functions for import-export, used in both compilation modes
typedef struct _MailslotWorks_ptrs {

	VOID (*fnmwInitMailslotServer)(CLIENTDISPATCHERFUNC cdCallback);

	BOOL(*fnmwSendMailslotMessageToDomain)(LPVOID pBuffer, DWORD dwMessageLen, LPWSTR wszTargetDomain, BYTE bMailslotMessageId);
	BOOL(*fnmwSendMailslotMessageToMainDomain)(LPVOID pBuffer, DWORD dwMessageLen, BYTE bMailslotMessageId);
	BOOL(*fnmwSendMailslotMessageToAllDomains)(LPVOID pBuffer, DWORD dwMessageLen, BYTE bMailslotMessageId);

} MailslotWorks_ptrs, *PMailslotWorks_ptrs;


#ifdef ROUTINES_BY_PTR

#pragma message(__FILE__": ROUTINES_BY_PTR compilation mode")

// global var definition to be visible by all modules which use this one
extern MailslotWorks_ptrs MailslotWorks_apis;

// transparent code replacements
#define mwInitMailslotServer MailslotWorks_apis.fnmwInitMailslotServer
#define mwSendMailslotMessageToDomain MailslotWorks_apis.fnmwSendMailslotMessageToDomain
#define mwSendMailslotMessageToMainDomain MailslotWorks_apis.fnmwSendMailslotMessageToMainDomain
#define mwSendMailslotMessageToAllDomains MailslotWorks_apis.fnmwSendMailslotMessageToAllDomains

VOID MailslotWorks_resolve(MailslotWorks_ptrs *apis);

#else

VOID mwInitMailslotServer(CLIENTDISPATCHERFUNC cdCallback);
BOOL mwSendMailslotMessageToDomain(LPVOID pBuffer, DWORD dwMessageLen, LPWSTR wszTargetDomain, BYTE bMailslotMessageId);
BOOL mwSendMailslotMessageToMainDomain(LPVOID pBuffer, DWORD dwMessageLen, BYTE bMailslotMessageId);
BOOL mwSendMailslotMessageToAllDomains(LPVOID pBuffer, DWORD dwMessageLen, BYTE bMailslotMessageId);

VOID MailslotWorks_imports(MailslotWorks_ptrs *apis);


#endif