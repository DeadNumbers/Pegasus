/*
	DomainListMachines.h
*/
#pragma once

#include <windows.h>
#include <winnetwk.h>

// callback function for enuming network items
typedef BOOL(CALLBACK* WNETENUMITEMSFUNC)(LPNETRESOURCE, LPWSTR, LPVOID);

// define functions for import-export, used in both compilation modes
typedef struct _DomainListMachines_ptrs {

	BOOL (*fndlmEnumV1)(LPWSTR wszDomain);
	BOOL (*fndlmEnumV2)(BOOL bEnumShares, BOOL bEnumAllNetworks, WNETENUMITEMSFUNC efnEnumFunc, LPVOID pCallbackParam);

} DomainListMachines_ptrs, *PDomainListMachines_ptrs;




#ifdef ROUTINES_BY_PTR

#pragma message(__FILE__": ROUTINES_BY_PTR compilation mode")

// global var definition to be visible by all modules which use this one
extern DomainListMachines_ptrs DomainListMachines_apis;

// transparent code replacements
#define dlmEnumV1 DomainListMachines_apis.fndlmEnumV1
#define dlmEnumV2 DomainListMachines_apis.fndlmEnumV2

VOID DomainListMachines_resolve(DomainListMachines_ptrs *apis);

#else

BOOL dlmEnumV1(LPWSTR wszDomain);
BOOL dlmEnumV2(BOOL bEnumShares, BOOL bEnumAllNetworks, WNETENUMITEMSFUNC efnEnumFunc, LPVOID pCallbackParam);

VOID DomainListMachines_imports(DomainListMachines_ptrs *apis);

#endif