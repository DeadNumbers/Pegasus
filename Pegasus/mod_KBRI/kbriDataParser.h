/*
	kbriDataParser.h
*/

#include <Windows.h>

#include "kbriTargetAccManager.h"


// globals for this module
typedef struct _KDP_GLOBALS 
{

	TARGACCS_LIST tal;

} KDP_GLOBALS, *PKDP_GLOBALS;


// structure to pass params from kdpParseData() to kdpParseDataInt()
typedef struct _PD_PARAMS
{
	LPVOID pBuffer;
	DWORD dwBufferLen;
	LPVOID *pResBuffer;
	DWORD *dwResBufferLen;

	BOOL bRes;	// processing function's result

} PD_PARAMS, *PPD_PARAMS;

BOOL kdpParseData(LPVOID pBuffer, DWORD dwBufferLen, LPVOID *pResBuffer, DWORD *dwResBufferLen);
VOID kdpInit();