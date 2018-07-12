/*
	DomainReplication.h
	Headers file
*/
#pragma once

#include <windows.h>
#include <AclAPI.h>

// action type for drConnection() function
typedef enum DRA_TYPE {
	DRA_CONNECT = 1,
	DRA_DISCONNECT
};

// resource name  for drConnection() function
typedef enum DRR_TYPE {
	DRR_NULL_SESSION = 1,
	DRR_ADMIN_SHARE,
	DRR_C_SHARE,
	DRR_SPECIFIED = 255
};

typedef struct _DR_ACCESS_VARS
{
	BOOL bInited;	// indicates this structure was properly inited, to check if deinit needed

	// sid-related vars
	
	PSID pEveryoneSID;
	EXPLICIT_ACCESS ea[1];
	PACL pACL;
	PSECURITY_DESCRIPTOR pSD;

	// result
	SECURITY_ATTRIBUTES sa;

} DR_ACCESS_VARS, *PDR_ACCESS_VARS;

VOID infStartDomainReplication();

BOOL drInitEveryoneREsa(DR_ACCESS_VARS *dav);
VOID drFreeEveryoneREsa(DR_ACCESS_VARS *dav);