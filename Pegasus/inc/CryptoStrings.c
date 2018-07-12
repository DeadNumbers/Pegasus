/*
	CryptoStrings.c
 Misc routines to implement seamless string encryption
 with preparser's support.

 */

#include <windows.h>
#include "dbg.h"
#include "CryptoStrings.h"

#ifdef ROUTINES_BY_PTR

extern "C" {
	CryptoStrings_ptrs CryptoStrings_apis;	// global var for transparent name translation into call-by-pointer	
}

// should be called before any other apis used to fill internal structures
VOID CryptoStrings_resolve(CryptoStrings_ptrs *apis)
{
#ifdef _DEBUG
	if (IsBadReadPtr(apis, sizeof(CryptoStrings_ptrs))) { DbgPrint("DBG_ERR: bad read ptr %p len %u", apis, sizeof(CryptoStrings_ptrs)); }
#endif
	// save to a global var
	CryptoStrings_apis = *apis;
}

#else 


#include "mem.h"
#include "dbg.h"

/*
	Fill passed structure with ptrs to all exported functions
	Used when module compiled as code to provide ptrs to some other child code
*/
VOID CryptoStrings_imports(CryptoStrings_ptrs *apis)
{
	apis->fn__CRSTRDecrypt = __CRSTRDecrypt;
	apis->fn__cs_AtoW = __cs_AtoW;
}

/*
	Xors memory passed at pDest with len lLen bytes with DWORD xor key dwXorKey
*/
VOID __cs_dexor_buff(VOID *pDest, SIZE_T lLen, DWORD dwXorKey)
{
	SIZE_T lCounter = lLen;				// internal loop counter
	DWORD *pdwDest = (DWORD *)pDest;	// cast target buffer as dword array
	DWORD dwTmp;	// tmp value to hold xor result

	//DbgPrint("__cs_dexor_buff: pDest=%04Xh lLen=%u dwXorKey=%08Xh\n\n", pDest, lLen, dwXorKey);

	__try {

	// loop while have more data
	//while (lCounter>0) {
	while (TRUE) {

		dwTmp = *pdwDest ^ dwXorKey;
		*pdwDest = dwTmp;

		// dec counter properly
		if (lCounter<4) { break; }
		lCounter-=4; 
		pdwDest++;

	}

	} __except(1) { DbgPrint("__cs_dexor_buff: EXCEPTION: pDest=%04Xh lLen=%u dwXorKey=%08Xh\n\n", pDest, lLen, dwXorKey);  }

}

/*
	Copies the memory from pSrc to pDest until zero terminator in pSrc found
 NB: zero byte is actually not copied, target buffer assumed to be zero-initialized already
 Returns amount of bytes copied
*/
SIZE_T __cs_memcpyz(VOID *pDest, const VOID *pSrc)
{
	// internal adjustable pointers 
	BYTE *pbSrc = (BYTE *)pSrc;
	BYTE *pbDest = (BYTE *)pDest;
	SIZE_T iCnt = 0;

	//DbgPrint("__cs_memcpyz: pDest=%04Xh pSrc=%04Xh\r\n", pDest, pSrc);

	__try {

	// do the copy till zero terminator found
	while (( *pbSrc!=0 )) {

		*pbDest = *pbSrc;

		pbDest++;
		pbSrc++;
		iCnt++;
		if (iCnt > 512) { break; }

	}

	//DbgPrint("__cs_memcpyz: finised pbDest=%04Xh pbSrc=%04Xh r_len=%u\r\n", pbDest, pbSrc, (SIZE_T)((SIZE_T)pbDest - (SIZE_T)pDest) );

	} __except(1) { DbgPrint("__cs_memcpyz: EXCEPTION: pDest=%04Xh pSrc=%04Xh\r\n", pDest, pSrc) }

	// output result
	return (SIZE_T)((SIZE_T)pbDest - (SIZE_T)pDest);
}

/*
	Generates xor byte for step2 decoding, according to passed char's pos and dwXorKey
 wChrPos should go from 0 to strlen-1
*/
BYTE __cs_gen_xor_byte(DWORD dwXorKey, WORD wChrPos)
{
	return (BYTE) ( 0x05F + (BYTE)(wChrPos << 3) + 1 );
}

/*
	Performs step2 decryption on <BYTE encoded chars> from {encoded_chunk} = <WORD strLen><BYTE encoded chars>
 Places decoded data into pDest. No result defined
*/
VOID __cs_decrypt_step2(const VOID *pSrc, VOID *pDest, WORD wLen, DWORD dwXorKey)
{
	// make local adjustable pointers
	BYTE *pbSrc = (BYTE *)pSrc;
	BYTE *pbDest = (BYTE *)pDest;
	WORD wCounter = 0;	// local counter of processed byte, to generate xor byte on each step
//	BYTE bTmp;	// tmp buffer value, possibly may be removed

	__try {

	// do iterations until strlen end
	while (wCounter<wLen) {

		// parse one byte
		*pbDest = *pbSrc ^ __cs_gen_xor_byte(dwXorKey, wCounter);

		// adjust pointers
		wCounter++;
		pbSrc++;
		pbDest++;

	}	// while

	} __except(1) { DbgPrint("EXCEPTION");  }

}

/*
	This func is called to process CRSTR macro in cryptostrings mode
 	Encoding scheme:
  <DWORD dwRandomValue>{encoded_chunk xored using dwRandomValue}
  {encoded_chunk} = <WORD strLen><BYTE encoded chars>
*/
LPSTR __CRSTRDecrypt(const BYTE *pIn)
{
	//PVOID pIntBuff;	// internal decryption buffer when real string size is not found yet
	BYTE bIntBuff[256];
	DWORD dwEncKey;		// encoding key, first dword of passed data
	WORD wStrLen;		// string's len
	SIZE_T lMemCopied;	// amount of mem copied from crypt source until null terminator was found
	PBYTE pOutString = NULL; // output buff with a decoded string, the least possible size, instead of pIntBuff


	__try {

	// alloc string buffer big enought for most strings
	//pIntBuff = (PVOID)my_alloc( 512 );

	// get dwEncKey (in some strange legacy-like manner)
	//dwEncKey = (DWORD)pIn[0] + ((DWORD)pIn[1] << 8 ) + ((DWORD)pIn[2] << 16 ) + ((DWORD)pIn[3] << 24 );
	dwEncKey = *(DWORD *)pIn;

	// copy all left data into szOutBuff
	//lMemCopied = __cs_memcpyz(pIntBuff, (PVOID)((SIZE_T)pIn + sizeof(DWORD)) );
	lMemCopied = __cs_memcpyz(&bIntBuff[0], &pIn[4]);

	// dexor data using read value
	__cs_dexor_buff(&bIntBuff[0], lMemCopied, dwEncKey);

	// get real string len according to dexored stream
	wStrLen = *(PWORD)&bIntBuff[0];

		// check for a sane value in a tricky manner
		if (wStrLen > 512) {
			
			DbgPrint("\r\n__CRSTRDecrypt: *** ERR: MALFORMED STRING, wStrLen=%u ***\r\n\r\n", wStrLen);
		
		} else {

			// alloc output buffer to be passed to caller, with null byte added to strlen
			pOutString = (PBYTE)my_alloc( wStrLen + 1);

			// perform step 2 decryption, left extra 2 bytes with string len
			__cs_decrypt_step2((PVOID)((SIZE_T)&bIntBuff[0] + sizeof(WORD)), (PVOID)pOutString, wStrLen, dwEncKey );


			//DbgPrint("__CRSTRDecrypt: dwEncKey=%08Xh wStrLen=%u\r\n",  dwEncKey, wStrLen);


		} // ! wStrLen > 1024

	// free used internal buff
	//my_free(pIntBuff);

	} __except(1) { DbgPrint("EXCEPTION");  }

	return (LPSTR)pOutString;

}


/*
	Used for CRSTRW macro. Converts ANSI string into UNICODE
 Input string buffer is deallocated.
 NB: only output from __CRSTRDecrypt is assumed to be used here
*/
LPWSTR __cs_AtoW(LPSTR szAnsiString)
{
	LPWSTR wszOut;	// output buffer

	__try {

	// alloc mem for result
	wszOut = (LPWSTR)my_alloc( 2048);

	// convert using standart api
	MultiByteToWideChar(CP_ACP, 0, (LPCSTR)szAnsiString, -1, wszOut, 2048);

	// dealloc previous buffer
	my_free(szAnsiString);

	} __except(1) { DbgPrint("EXCEPTION");  } 

	return wszOut;
}

#endif