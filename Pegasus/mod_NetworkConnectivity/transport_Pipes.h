/*
	transport_Pipes.h
*/

#pragma once

#include <Windows.h>

#include "transport_Generic.h"

// definition of internal context structure to be used 
// while this transport is active
typedef struct _TSPIPES_INTERNAL_CONTEXT {

	LPWSTR wszPipeProxyServer;	// name of machine with working pipe proxy server. To be disposed at transport shutdown

} TSPIPES_INTERNAL_CONTEXT, *PTSPIPES_INTERNAL_CONTEXT;

PTRANSPORT_HANDLE tspipesInitTransport();