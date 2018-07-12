/*
	lpmemory.h
*/

#pragma once
#include <Windows.h>

void * __cdecl operator new(size_t iLen);
void __cdecl operator delete(void *p);

bool lp_readMemory(const void * adresseBase, void * adresseDestination, size_t longueur = 1, HANDLE handleProcess = INVALID_HANDLE_VALUE);
bool lp_searchMemory(const PBYTE adresseBase, const PBYTE adresseMaxMin, const PBYTE pattern, PBYTE * addressePattern, size_t longueur = 1, bool enAvant = true, HANDLE handleProcess = INVALID_HANDLE_VALUE);
bool lp_searchMemory(const PBYTE adresseBase, const long offsetMaxMin, const PBYTE pattern, long * offsetPattern, size_t longueur = 1, bool enAvant = true, HANDLE handleProcess = INVALID_HANDLE_VALUE);
bool lp_genericPatternSearch(PBYTE * thePtr, wchar_t * moduleName, BYTE pattern[], ULONG taillePattern, LONG offSetToPtr, char * startFunc = NULL, bool enAvant = true, bool noPtr = false);
