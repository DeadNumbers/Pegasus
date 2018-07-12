/*
	HashedStrings.h
 Misc routines and macro definition for hashed string usage
 ROUTINES_BY_PTR supported
 NB: uses per-build unique HASHSTR_RND_XOR value, take care when using compiled (not by reference) versions
 between different projects!

 NB: assumed to be used via source-code parser, which recalculates values of:

	HASHSTR(<string>, 0x0BADF00D)	- hash pseudo-macro
	STRHASH_ALGID(n)	- which algo (possibly bitfields) is used in this build
	STRHASH_PARAM(n)	- algo's param to be used for extra randomness

*/

#pragma once

#include <windows.h>

// define per-build hash randomization
// NB: take care about passing hashes between differently compiled modules, to prevent problems
// this value is changed on each build
#define HASHSTR_RND_XOR STRHASH_PARAM(0x16ca75882606765a)

// define hash pseudo macros
// NB: these are without = sign, so parser should not touch them
#define HASHSTR(original_string, i64Hash) i64Hash ^ HASHSTR_RND_XOR
#define HASHSTR_CONST(original_string, i64Hash) i64Hash
#define STRHASH_ALGID(alg_id) alg_id
#define STRHASH_PARAM(alg_param) alg_param

// define functions for import-export, used in both compilation modes
typedef struct _HashedStrings_ptrs {

//	WORD wFunctionCount;	// to distinct between different versions

	UINT64(*fnHashStringA)(LPCSTR szStringToHash);
	UINT64(*fnHashStringW)(LPCWSTR wszStringToHash);
	UINT64(*fnHashStringA_const)(LPCSTR szStringToHash);
	UINT64(*fnHashStringW_const)(LPCWSTR wszStringToHash);
	UINT64(*fnHashBin)(LPVOID pBin, DWORD dwBinLen);
	UINT64(*fnHashBin_const)(LPVOID pBin, DWORD dwBinLen);

} HashedStrings_ptrs, *PHashedStrings_ptrs;

#ifdef ROUTINES_BY_PTR

#pragma message(__FILE__": ROUTINES_BY_PTR compilation mode")

	// global var definition to be visible by all modules which use this one
	extern HashedStrings_ptrs HashedStrings_apis;

	// transparent code replacements
	#define HashStringA HashedStrings_apis.fnHashStringA
	#define HashStringW HashedStrings_apis.fnHashStringW
	#define HashStringA_const HashedStrings_apis.fnHashStringA_const
	#define HashStringW_const HashedStrings_apis.fnHashStringW_const
	#define HashBin HashedStrings_apis.fnHashBin
	#define HashBin_const HashedStrings_apis.fnHashBin_const

	VOID HashedStrings_resolve(HashedStrings_ptrs *apis);

#else

	// declarations - compile as code
	UINT64 HashStringA(LPCSTR szStringToHash);
	UINT64 HashStringW(LPCWSTR wszStringToHash);
	UINT64 HashStringA_const(LPCSTR szStringToHash);
	UINT64 HashStringW_const(LPCWSTR wszStringToHash);
	UINT64 HashBin(LPVOID pBin, DWORD dwBinLen);
	UINT64 HashBin_const(LPVOID pBin, DWORD dwBinLen);

	VOID HashedStrings_imports(HashedStrings_ptrs *apis);

#endif