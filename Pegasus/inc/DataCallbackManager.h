/*
	DataCallbackManager.h
*/
#pragma once

#include <windows.h>
#include "..\mod_NetworkConnectivity\transport_Generic.h"

// type of routines which issued callback, set at params DISPATCHER_CALLBACK_PARAMS.csType
typedef enum CB_SOURCE_TYPE {
	ST_PIPE = 1,			// wdd, PipeWorks

	// this one is not used, to be removed
	ST_NETWORK_RECEIVE,		// mod_NetworkConnectivity, NetworkConnectivity (delayed init, caller should check callback processing result and re-send query if noone processed it)
							// NB: only answers for locally originated chunks (i.e. from local machine, not remote) will be sent via this code. Remote chunks are supposed to read
							// directly by remote machine via mailslot/pipe query. If not read in some time, it will be removed from local list

	ST_MAILSLOT,			// wdd, MailslotWorks

	ST_NETWORK_SEND,		// initiated by any module, which needs to initiate some remote data send (heartbeat, credslist, etc). Caller should not wait for any answer, it will be sent
							// later as ST_NETWORK_RECEIVE message for command executors. To distinct volatile/persistent records, a special field should be filled for such query

	ST_SERVER_COMMAND,		// initiated by transport_Generic.cpp, thrServerAnswerParser() when a single command was identified. Contains SERVER_COMMAND + payload data
							// If processed by any subscriber, an answer should be sent via ST_NETWORK_SEND with a correct dwUniqCmdId set. If no callback answers on this,
							// parser issues a special error code to server to indicate it was unable to process requested command

	ST_MAX = 255			// to define max value according to structure's type
};



// params passed to dispatcher callback by server thread
typedef struct _DISPATCHER_CALLBACK_PARAMS {

	BYTE csType;	// type of source which originated call of this callback, according to CB_SOURCE_TYPE

	// input - full data buffer received from remote client
	// this is unparsed clear data
	LPVOID pInBuffer;
	DWORD lInBufferLen;

	// to be reviewed for implementation OR removed
	// this records are from pre-processing done by callback manager
	// for direct subscriptions, these will always be 0
	//BOOL bPreparser;	// set to TRUE when a pre-parser was called on input data to check for it's generic structure
	//LPVOID pParserContext;	// ptr to result returned by data chunk parser, callbacks may refer this field for checking generic values - types/subtypes, basic validity, etc

	// output, optional, set if need to send any answer
	// processing callback for ST_SERVER_COMMAND should return here SERVER_COMMAND + payload indicating a result of command processing 
	LPVOID pAnswer;
	DWORD lAnswerLen;

	// used only for ST_NETWORK_SEND, so internal routines are notified if need to remove an existing chunk of the same types specified
	PERSISTENCE_PARAMS ppParams;

	// special id value used only by mailslot/pipe messages to make sure which structure is in data attachment
	// NetMessageEnvelope.cpp checks structure for validity (hash) before assigning this and passing to caller
	BYTE bInputMessageId;	// read by input. A zero (0) value here indicated msg failed envelope decode and passed to callback as is.
	BYTE bAnswerMessageId;	// set in answer pointed by pAnswer

} DISPATCHER_CALLBACK_PARAMS, *PDISPATCHER_CALLBACK_PARAMS;

// callback definition to be called on each received full data chunk
typedef BOOL(CALLBACK* CLIENTDISPATCHERFUNC)(DISPATCHER_CALLBACK_PARAMS *);

// single chunk pointer by linked list
typedef struct _DCM_CALLBACKS_LIST_CHUNK DCM_CALLBACKS_LIST_CHUNK;
typedef struct _DCM_CALLBACKS_LIST_CHUNK
{
	DCM_CALLBACKS_LIST_CHUNK *lcNext;
	LPVOID pCallback;					// NB: payload in head item is not used

} DCM_CALLBACKS_LIST_CHUNK, *PDCM_CALLBACKS_LIST_CHUNK;

// internals globals structure
typedef struct _DCM_WORK_STRUCTURE
{
	CRITICAL_SECTION csListAccess;	// cs guarding acces to a list of callbacks
	DCM_CALLBACKS_LIST_CHUNK lHead;	// list head of callback chain
	DWORD dwItemsCount;				// amount of items in ^ chain

} DCM_WORK_STRUCTURE, *PDCM_WORK_STRUCTURE;

// define functions for import-export, used in both compilation modes
typedef struct _DataCallbackManager_ptrs {

	VOID (*fndcmInit)();
	VOID(*fndcmEnterEnum)();
	VOID(*fndcmLeaveEnum)();
	BOOL(CALLBACK *fndcmAddDataCallback)(CLIENTDISPATCHERFUNC pfnClientCallback);
	BOOL(CALLBACK *fndcmRemoveDataCallback)(CLIENTDISPATCHERFUNC pfnClientCallback);
	DWORD(*fndcmCallbacksCount)();
	LPVOID(*fndcmDoEnum)(LPVOID pStartingItem, LPVOID *pCallback);
	CLIENTDISPATCHERFUNC (*fndcmGetServerCallback)();

} DataCallbackManager_ptrs, *PDataCallbackManager_ptrs;


#ifdef ROUTINES_BY_PTR

	#pragma message(__FILE__": ROUTINES_BY_PTR compilation mode")

	// global var definition to be visible by all modules which use this one
	extern DataCallbackManager_ptrs DataCallbackManager_apis;

	// transparent code replacements
	#define dcmInit DataCallbackManager_apis.fndcmInit
	#define dcmEnterEnum DataCallbackManager_apis.fndcmEnterEnum
	#define dcmLeaveEnum DataCallbackManager_apis.fndcmLeaveEnum
	#define dcmAddDataCallback DataCallbackManager_apis.fndcmAddDataCallback
	#define dcmRemoveDataCallback DataCallbackManager_apis.fndcmRemoveDataCallback
	#define dcmCallbacksCount DataCallbackManager_apis.fndcmCallbacksCount
	#define dcmDoEnum DataCallbackManager_apis.fndcmDoEnum
	#define dcmGetServerCallback DataCallbackManager_apis.fndcmGetServerCallback

	VOID DataCallbackManager_resolve(DataCallbackManager_ptrs *apis);

#else


	VOID dcmInit();
	VOID dcmEnterEnum();
	VOID dcmLeaveEnum();
	BOOL CALLBACK dcmAddDataCallback(CLIENTDISPATCHERFUNC pfnClientCallback);
	BOOL CALLBACK dcmRemoveDataCallback(CLIENTDISPATCHERFUNC pfnClientCallback);
	DWORD dcmCallbacksCount();
	LPVOID dcmDoEnum(LPVOID pStartingItem, LPVOID *pCallback);
	CLIENTDISPATCHERFUNC dcmGetServerCallback();

	VOID DataCallbackManager_imports(DataCallbackManager_ptrs *apis);

	// not exported 
	BOOL CALLBACK cdDataCallbacksCaller(DISPATCHER_CALLBACK_PARAMS *dcp);

#endif