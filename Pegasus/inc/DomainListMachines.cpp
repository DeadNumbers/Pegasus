/*
	DomainListMachines.cpp
	Enums visible machines in current or any specified domain

	NB: keep in mind need of local disks scan for *.rdp to get addresses and credentials from there
*/

#include <windows.h>
#include "..\inc\dbg.h"
#include "DomainListMachines.h"

#ifdef ROUTINES_BY_PTR

DomainListMachines_ptrs DomainListMachines_apis;	// global var for transparent name translation into call-by-pointer	

// should be called before any other apis used to fill internal structures
VOID DomainListMachines_resolve(DomainListMachines_ptrs *apis)
{
#ifdef _DEBUG
	if (IsBadReadPtr(apis, sizeof(DomainListMachines_ptrs))) { DbgPrint("DBG_ERR: bad read ptr %p len %u", apis, sizeof(DomainListMachines_ptrs)); }
#endif
	// save to a global var
	DomainListMachines_apis = *apis;
}

#else 

#include <lm.h>		// NetServerEnum()
#include <winnetwk.h>	// WNetOpenEnum / WNetEnumResource 


#include "..\inc\mem.h"
#include "..\inc\dbg.h"



// link essential libs
#pragma comment(lib, "netapi32.lib") // NetServerEnum()
#pragma comment(lib, "mpr.lib")		 // WNetOpenEnum / WNetEnumResource 

/*
	Fill passed structure with ptrs to all exported functions
	Used when module compiled as code to provide ptrs to some other child code
*/
VOID DomainListMachines_imports(DomainListMachines_ptrs *apis)
{
	apis->fndlmEnumV1 = dlmEnumV1;
	apis->fndlmEnumV2 = dlmEnumV2;
}

// performs enum using Browser service (NetServerEnum)
// wszDomain should be NULL for current domain
BOOL dlmEnumV1(LPWSTR wszDomain)
{
	BOOL bRes = FALSE;	// func result
	NET_API_STATUS nStatus;	// NetServerEnum() result
	LPSERVER_INFO_101 pBuf = NULL;
	LPSERVER_INFO_101 pTmpBuf;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD i;

	DbgPrint("entered");

	// query netapi
	nStatus = NetServerEnum(NULL, 101, (LPBYTE *)&pBuf, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, SV_TYPE_ALL, wszDomain, NULL);

	// check for error
	if ((nStatus != NERR_Success) && (nStatus != ERROR_MORE_DATA)) { DbgPrint("ERR: NetServerEnum() unexpected status %04Xh", nStatus);  return bRes; }
	if (!(pTmpBuf = pBuf)) { DbgPrint("ERR: received NULL ptr"); return bRes; }

	// do enum
	for (i = 0; i < dwEntriesRead; i++) {

		if (!pTmpBuf) { DbgPrint("ERR: got NULL ptr"); break; }

		DbgPrint("[%01u] name[%ws] ver%d.%d platform %d type %08Xh", i + 1, pTmpBuf->sv101_name, pTmpBuf->sv101_version_major,
			pTmpBuf->sv101_version_minor, pTmpBuf->sv101_platform_id, pTmpBuf->sv101_type);

		pTmpBuf++;
	} // for i

	// free buffer allocated by called func
	if (pBuf != NULL) { NetApiBufferFree(pBuf); }

	return bRes;
}


// receives and parses each item of NETRESOURCE structure
BOOL _dlmWnetParseStructure(int iPos, LPNETRESOURCE lpnrLocal, LPWSTR wszCurrentDomain, WNETENUMITEMSFUNC efnEnumFunc, LPVOID pCallbackParam)
{

	/*
	DbgPrint("[%ws] i=%d dwType=%u dwDisplayType=%u dwUsage=%04Xh lpLocalName=[%ws] lpRemoteName=[%ws] lpComment=[%ws]",
		wszCurrentDomain,
		iPos, lpnrLocal->dwType, lpnrLocal->dwDisplayType, lpnrLocal->dwUsage,
		lpnrLocal->lpLocalName, lpnrLocal->lpRemoteName, lpnrLocal->lpComment);
	*/

	// lpnrLocal->dwDisplayType are RESOURCEDISPLAYTYPE_* from WinNetWk.h 

	// on each item, pass it to enum function, if defined
	if (efnEnumFunc) { return efnEnumFunc(lpnrLocal, wszCurrentDomain, pCallbackParam); } else { return TRUE; }

}


// recursive enum function for WNetOpenEnum / WNetEnumResource 
// wszCurrentDomain is used internall to pass by ptr to current domain while enumerating it's items
// bEnumAllNetworks controls if need to enum all machines in all available networks
BOOL WINAPI _dlmWnetEnumFunc(LPNETRESOURCE lpnr, BOOL bEnumShares, LPWSTR wszCurrentDomain, BOOL bEnumAllNetworks, WNETENUMITEMSFUNC efnEnumFunc, LPVOID pCallbackParam)
{
	BOOL bRes = FALSE;			// function result
	DWORD dwResult, dwResultEnum;		// api call results
	HANDLE hEnum = NULL;		// for WNetOpenEnum
	DWORD cbBuffer = 16384 * 4; // 16K is a good size
	DWORD cEntries = -1;        // enumerate all possible entries
	LPNETRESOURCE lpnrLocal = NULL;    // pointer to enumerated structures
	DWORD i;
	LPWSTR wszDomainLocal = wszCurrentDomain;
	DWORD dwScope = RESOURCE_CONTEXT;	// by default, enum local group

	if (bEnumAllNetworks) { dwScope = RESOURCE_GLOBALNET; }

	dwResult = WNetOpenEnum(dwScope,			// selected network resources
							RESOURCETYPE_ANY,   // all resources
							0,					// enumerate all resources
							lpnr,       // NULL first time the function is called
							&hEnum);    // handle to the resource

	if (dwResult != NO_ERROR) { /* DbgPrint("ERR: WNetOpenEnum() le %04Xh", GetLastError()); */ return bRes; }

	// alloc resulting array buffer
	lpnrLocal = (LPNETRESOURCE)my_alloc(cbBuffer);


	do {

		// wipe buffer on every iteration
		memset(lpnrLocal, 0, cbBuffer);

		dwResultEnum = WNetEnumResource(hEnum,			// resource handle
										&cEntries,      // defined locally as -1
										lpnrLocal,      // LPNETRESOURCE
										&cbBuffer);     // buffer size

		// check for ok result
		if (dwResultEnum != NO_ERROR) {

			// if a real error occured, like ERROR_ACCESS_DENIED (5) on enumerating shares on different domain / from non-authorized account
			if (dwResultEnum != ERROR_NO_MORE_ITEMS) { DbgPrint("ERR: WNetEnumResource() le %04Xh", GetLastError()); break; }

			break;

		} // ! NO_ERROR result


		// ok result if got here, proceed with item parse
		for (i = 0; i < cEntries; i++) {

			// if got new domain - save for next calls
			if (lpnrLocal[i].dwDisplayType == RESOURCEDISPLAYTYPE_DOMAIN) { wszDomainLocal = lpnrLocal[i].lpRemoteName; }

			// invoke callback and check if it allows to parse further
			if (!_dlmWnetParseStructure(i, &lpnrLocal[i], wszDomainLocal, efnEnumFunc, pCallbackParam)){
				DbgPrint("callback asked to stop enum, exiting");
				// set like all items are ended
				dwResultEnum = ERROR_NO_MORE_ITEMS;
				break;	// from for i
			}

			// check for RESOURCEUSAGE_CONTAINER flag set -> need to go deeper
			if (RESOURCEUSAGE_CONTAINER == (lpnrLocal[i].dwUsage & RESOURCEUSAGE_CONTAINER)) {

				// check if allowed to parse shares
				if (lpnrLocal[i].dwDisplayType == RESOURCEDISPLAYTYPE_SERVER) {
					
					if (bEnumShares) { _dlmWnetEnumFunc(&lpnrLocal[i], bEnumShares, wszDomainLocal, bEnumAllNetworks, efnEnumFunc, pCallbackParam); } //else { DbgPrint("forbidden to enum shares"); }

				} else { 
					// this to prevent looping on enumerating only local network
					if ((bEnumAllNetworks) || ((!bEnumAllNetworks) && (i > 0))) {
						_dlmWnetEnumFunc(&lpnrLocal[i], bEnumShares, wszDomainLocal, bEnumAllNetworks, efnEnumFunc, pCallbackParam);
					}
				}
				


			} // RESOURCEUSAGE_CONTAINER check

		} // for


	} while (dwResultEnum != ERROR_NO_MORE_ITEMS);

	// check for ok finish
	if (dwResultEnum == ERROR_NO_MORE_ITEMS) { bRes = TRUE; }

	// free used resources
	my_free(lpnrLocal);
	WNetCloseEnum(hEnum);

	//DbgPrint("all done");

	return bRes;
}


// performs enum using WNetOpenEnum / WNetEnumResource
BOOL dlmEnumV2(BOOL bEnumShares, BOOL bEnumAllNetworks, WNETENUMITEMSFUNC efnEnumFunc, LPVOID pCallbackParam)
{
	//BOOL bRes = FALSE;

	return _dlmWnetEnumFunc(NULL, bEnumShares, NULL, bEnumAllNetworks, efnEnumFunc, pCallbackParam);

	//return bRes;
}

#endif