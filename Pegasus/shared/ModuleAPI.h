/*
	ModuleAPI.h 
	Headers with core<->modules api structures
*/
#pragma once

#include <windows.h>

#include "..\inc\HashedStrings.h"
#include "..\inc\MyStringRoutines.h"
#include "..\inc\CryptoStrings.h"
#include "..\inc\RandomGen.h"

#include "..\inc\PipeWorks.h"
#include "..\inc\DomainListMachines.h"
#include "..\inc\CredManager.h"
#include "..\inc\EmbeddedResources.h"
#include "..\inc\MailslotWorks.h"
#include "..\shared\CommStructures.h"

#include "..\inc\DataCallbackManager.h"



// definition of a core APIs available to modules
typedef struct _CORE_APIS_v10
{
	// version code to use correct structure definition by modules
	WORD wCoreVersion;

	// api definitions of all funcs from libs, which may be used by modules

	// generic libraries
	HashedStrings_ptrs		*HashedStrings_apis;
	MyStringRoutines_ptrs	*MyStringRoutines_apis;
	CryptoStrings_ptrs		*CryptoStrings_apis;
	RndClass_ptrs			*RndClass_apis;

	// more specific libs
	PipeWorks_ptrs			*PipeWorks_apis;
	DomainListMachines_ptrs *DomainListMachines_apis;
	CredManager_ptrs		*CredManager_apis;
	EmbeddedResources_ptrs	*EmbeddedResources_apis;
	MailslotWorks_ptrs		*MailslotWorks_apis;

	// WDD - specific libs with exported functions
	DataCallbackManager_ptrs *DataCallbackManager_apis; // data callbacks management as a result of some network/pipe communication

	// functions to generate/manage common structures
	CommStructures_ptrs *CommStructures_apis;	


} CORE_API_v10, *PCORE_APIS_v10;

// definition of a current apis version
#define CORE_APIS CORE_API_v10
