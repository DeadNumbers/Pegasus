/*
	HashedStrings.c
 Routines to support the search using hashed strings

 NB: using space in hash str is partially fixed here

 */

#include <windows.h>

#include "dbg.h"

#include "HashedStrings.h"

// parser's settings defs
#define STRHASH_ALGID(n) n
#define STRHASH_PARAM(n) n



#ifdef ROUTINES_BY_PTR

	HashedStrings_ptrs HashedStrings_apis;	// global var for transparent name translation into call-by-pointer	

	// should be called before any other apis used to fill internal structures
	VOID HashedStrings_resolve(HashedStrings_ptrs *apis)
	{

#ifdef _DEBUG
		if (IsBadReadPtr(apis, sizeof(HashedStrings_ptrs))) { DbgPrint("DBG_ERR: bad read ptr %p len %u", apis, sizeof(HashedStrings_ptrs)); }
#endif

		// save to a global var
		HashedStrings_apis = *apis;
	}

#else 

/*
	Fill passed structure with ptrs to all exported functions
	Used when module compiled as code to provide ptrs to some other child code
*/
VOID HashedStrings_imports(HashedStrings_ptrs *apis)
{
	apis->fnHashStringA = HashStringA;
	apis->fnHashStringW = HashStringW;
	apis->fnHashStringA_const = HashStringA_const;
	apis->fnHashStringW_const = HashStringW_const;
	apis->fnHashBin = HashBin;
	apis->fnHashBin_const = HashBin_const;
}

// internal macro / inline definitions // NB: this implementation invokes _allshl, _aullshr from ntdll due to >32 shifts, in x32 only
// it can be used in x64 mode
#if defined(_M_X64)
	#define ROTL64(x,r) (x << r) | (x >> (64 - r));
#else
	// implement rol of 64 int by using it's parts
	//#define LROL32(x, r) (x >> r) | (x << (32 - r));
	#define LROL32(x, r) (x >> r) 

	UINT64 ROTL64(UINT64 iVal, BYTE bShift)
	{
		ULARGE_INTEGER iRes;
		
		DWORD in_HighPart = (DWORD) ( iVal >> 32 );
		DWORD in_LowPart = (DWORD)iVal;


		  if (bShift <= 32) {
			iRes.LowPart  =	 (in_LowPart << bShift)  ^ (in_HighPart >> (32 - bShift)) ;
			iRes.HighPart =  (in_HighPart << bShift) ^ (in_LowPart >> (32 - bShift) );
		  } else {
			iRes.LowPart = (in_HighPart  << (bShift-32) )  ^ (in_LowPart >> (32 - (bShift-32))) ;
			iRes.HighPart =  (in_LowPart << (bShift-32) )  ^ (in_HighPart >>  (32 - (bShift-32))) ;
		  }

		  //DbgPrint("%08X %08X xROL %u -> %08X %08X", (DWORD) ( iVal >> 32 ), (DWORD)iVal, bShift, iRes.HighPart, iRes.LowPart);

		  return iRes.QuadPart;
	}

#endif

// hash calculating func
UINT64 HashStringA_const(LPCSTR szStringToHash)
{
	UINT64 i64Result = 0; // func res
	BYTE *pStr = (BYTE *)szStringToHash;
	SIZE_T lCounter = 0;
	BYTE bShift;

	//__try {

		// scan input string until 0x00 char
		while (*pStr != 0x00) {

			// use source byte
			i64Result ^= *pStr ;
			bShift = (((BYTE)*pStr + (BYTE)lCounter ) & 0x3F);
			if ((bShift)&&(bShift != 32)) { i64Result ^= ROTL64(i64Result, bShift ); } // 0x3F mask to limit iRol to 63

			//DbgPrint("step_hash=%08x %08x h\r\n", (DWORD)(i64Result >> 32), (DWORD)(i64Result));

			// inc counter
			pStr++; lCounter++;

		} // while ! 0x00 char

		// finalization pass
		// ...

		// dbg res out
		//DbgPrint("szStringToHash=[%s] hash=%08x%08x h\r\n", szStringToHash, (DWORD)(i64Result >> 32), (DWORD)(i64Result));

	//} __except(1) { DbgPrint("WARN: exception catched\r\n");  }



	return i64Result;
}

// same as HashStringA_const, but for binary data
UINT64 HashBin_const(LPVOID pBin, DWORD dwBinLen)
{
	UINT64 i64Result = 0; // func res
	BYTE *pStr = (BYTE *)pBin;
	SIZE_T lCounter = dwBinLen;
	BYTE bShift;

	// scan input string until 0x00 char
	while (lCounter) {

		// use source byte
		i64Result ^= *pStr ;
		bShift = (((BYTE)*pStr + (BYTE)lCounter ) & 0x3F);
		if ((bShift)&&(bShift != 32)) { i64Result ^= ROTL64(i64Result, bShift ); } // 0x3F mask to limit iRol to 63

		// inc counter
		pStr++; lCounter--;

	} // while ! 0x00 char

	return i64Result;
}

UINT64 HashBin(LPVOID pBin, DWORD dwBinLen)
{
	return HashBin_const(pBin, dwBinLen) ^ HASHSTR_RND_XOR;
}


UINT64 HashStringA(LPCSTR szStringToHash)
{
	return HashStringA_const(szStringToHash) ^ HASHSTR_RND_XOR;
}


UINT64 HashStringW_const(LPCWSTR wszStringToHash)
{
	UINT64 i64Result = 0; // func res
	WORD *pStr = (WORD *)wszStringToHash;
	SIZE_T lCounter = 0;
	BYTE bShift;

	//__try {

		// scan input string until 0x00 char
		while (*pStr != 0x00) {

			// use source byte
			i64Result ^= (BYTE)*pStr ;
			bShift = (((BYTE)*pStr + (BYTE)lCounter ) & 0x3F);
			if ((bShift)&&(bShift != 32)) { i64Result ^= ROTL64(i64Result, bShift ); } // 0x3F mask to limit iRol to 63

			//DbgPrint("step_hash=%08x %08x h param %u \r\n", (DWORD)(i64Result >> 32), (DWORD)(i64Result), ((BYTE)*pStr & 0x3F) );

			// inc counter
			pStr++; lCounter++;

		} // while ! 0x00 char

		// finalization pass
		// ...

		// dbg res out
		//DbgPrint("StringToHash=[%ws] hash=%08x%08x h\r\n", wszStringToHash, (DWORD)(i64Result >> 32), (DWORD)(i64Result));

	//} __except(1) { DbgPrint("WARN: exception catched\r\n");  }

	return i64Result;
}

UINT64 HashStringW(LPCWSTR wszStringToHash)
{
	return HashStringW_const(wszStringToHash) ^ HASHSTR_RND_XOR;
}

#endif