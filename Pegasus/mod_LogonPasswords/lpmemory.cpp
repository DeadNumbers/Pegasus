/*
	lpmemory.cpp
	mod_memory procedure style module
*/

#include <Windows.h>
#include <Psapi.h>

#include "..\inc\mem.h"
#include "..\inc\dbg.h"

#include "lpmemory.h"

// new/delete operators
void * __cdecl operator new(size_t iLen)
{
	return my_alloc(iLen);
}

void __cdecl operator delete(void *p)
{
	my_free(p);
}

bool lp_readMemory(const void * adresseBase, void * adresseDestination, size_t longueur, HANDLE handleProcess)
{
	bool bRes = FALSE;

	if (handleProcess == INVALID_HANDLE_VALUE)
	{
		//return (memcpy_s(adresseDestination, longueur, adresseBase, longueur) == 0);
		memcpy(adresseDestination, adresseBase, longueur);
		return TRUE;
	} else {
		SIZE_T dwBytesRead = 0;
		bRes = ((ReadProcessMemory(handleProcess, adresseBase, adresseDestination, longueur, &dwBytesRead) != 0) && (dwBytesRead == longueur));

	//	if (!bRes) { DbgPrint("ERR: remote mem read error: from %p into local ptr %p targ_len %u dwBytesRead %u le %u", adresseBase, adresseDestination, longueur, dwBytesRead, GetLastError()); }

		return bRes;
	}
}

bool lp_searchMemory(const PBYTE adresseBase, const PBYTE adresseMaxMin, const PBYTE pattern, PBYTE * addressePattern, size_t longueur, bool enAvant, HANDLE handleProcess)
{
	BYTE * monTab = new BYTE[longueur];
	*addressePattern = adresseBase;
	bool succesLecture = true;
	bool succesPattern = false;

	while ((!adresseMaxMin || (enAvant ? (*addressePattern + longueur) <= adresseMaxMin : (*addressePattern - longueur) >= adresseMaxMin)) && succesLecture && !succesPattern)
	{
		if (succesLecture = lp_readMemory(*addressePattern, monTab, longueur, handleProcess))
		{
			if (!(succesPattern = (memcmp(monTab, pattern, longueur) == 0)))
			{
				*addressePattern += (enAvant ? 1 : -1);
			}
		}
	}
	delete[] monTab;

	if (!succesPattern)
		*addressePattern = NULL;

	return succesPattern;
}

bool lp_searchMemory(const PBYTE adresseBase, const long offsetMaxMin, const PBYTE pattern, long * offsetPattern, size_t longueur, bool enAvant, HANDLE handleProcess)
{
	PBYTE addressePattern = NULL;
	bool resultat = lp_searchMemory(adresseBase, (offsetMaxMin != 0 ? (adresseBase + offsetMaxMin) : NULL), pattern, &addressePattern, longueur, enAvant, handleProcess);
	// calc offset from imgbase, it should not exceed DWORD size
	*offsetPattern = addressePattern - adresseBase;
	return resultat;
}

bool lp_genericPatternSearch(PBYTE * thePtr, wchar_t * moduleName, BYTE pattern[], ULONG taillePattern, LONG offSetToPtr, char * startFunc, bool enAvant, bool noPtr)
{
	bool resultat = false;
	if (thePtr && pattern && taillePattern)
	{
		if (HMODULE monModule = GetModuleHandle(moduleName))
		{
			MODULEINFO mesInfos;
			if (GetModuleInformation(GetCurrentProcess(), monModule, &mesInfos, sizeof(MODULEINFO)))
			{
				PBYTE addrMonModule = reinterpret_cast<PBYTE>(mesInfos.lpBaseOfDll);

				if (PBYTE addrDebut = startFunc ? reinterpret_cast<PBYTE>(GetProcAddress(monModule, startFunc)) : addrMonModule)
				{
					if (resultat = lp_searchMemory(addrDebut, enAvant ? (addrMonModule + mesInfos.SizeOfImage) : reinterpret_cast<PBYTE>(mesInfos.lpBaseOfDll), pattern, thePtr, taillePattern, enAvant))
					{
						*thePtr += offSetToPtr;
						if (!noPtr)
						{
#ifdef _M_X64
							*thePtr += sizeof(long) + *reinterpret_cast<long *>(*thePtr);
#elif defined _M_IX86
							*thePtr = *reinterpret_cast<PBYTE *>(*thePtr);
#endif
						}
					}
					else *thePtr = NULL;
				}
			}
		}
	}
	return resultat;
}