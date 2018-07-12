/*
	CryptRoutines.cpp
	CryptoAPI related routines for hashing and encryption/decryption 
*/

#include <windows.h>
#include <wincrypt.h>

#include "mem.h"
#include "dbg.h"
#include "CryptoStrings.h"
#include "MyStreams.h"
#include "RandomGen.h"
#include "HashedStrings.h"
#include "..\shared\config.h"

#include "CryptRoutines.h"

CRYPT_CONTEXT gCryptContext;	// internal context with prepared key and provider handles

/*
	Calculates SHA binary hash of passed data buffer
*/
BOOL cryptCalcHashSHA(PVOID pData, SIZE_T ulSize, PBYTE pbResultBuffer, PULONG pulBufferLen)
{
	BOOL bRes = FALSE;	// function's result

	HCRYPTPROV hCProv = 0;	// cryptoprovider handle
	HCRYPTHASH hHash = 0;	// cryptoprovider's hash object's handle 
	LPWSTR wszProviderName = 0; //L"Microsoft Base Cryptographic Provider v1.0";	// name of cryptoprovider
	ULONG ulHashLen, ulBuffLen;

	// check inputs
	if (!pData || !ulSize || !pbResultBuffer || !pulBufferLen) { DbgPrint("ERR: invalid input params"); return bRes; }

	do {	// not a loop

		// decrypt provider's name
		wszProviderName = CRSTRW("Microsoft Base Cryptographic Provider v1.0", "\x00\xa0\x81\x0f\x2a\xa0\xac\x0e\x13\xaa\x6e\xf4\xff\x5e\x55\x87\xf2\x79\x32\xa2\xf0\x3b\x13\x9e\x80\x2c\xee\x60\x62\xd9\xd1\x4f\x59\xfb\xe1\x17\x22\x97\x97\x0e\x14\xbd\x73\xa7\xe6\x09\x0f\x97\xd1\x66\x4c");

		// get provider context
		if (!CryptAcquireContext(&hCProv, NULL, wszProviderName, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) { DbgPrint("ERR: CryptAcquireContext() err %04Xh", GetLastError()); break; }

		// create hash object
		if (!CryptCreateHash(hCProv, CALG_SHA, 0, 0, &hHash)) { DbgPrint("ERR: CryptCreateHash() err %04Xh", GetLastError()); break; }

		// do the hashing
		if (!CryptHashData(hHash, (BYTE *)pData, (DWORD)ulSize, 0)) { DbgPrint("ERR: CryptHashData() err %04Xh", GetLastError()); break; }

		// query binary hash size
		ulBuffLen = sizeof(ulHashLen);
		if (!CryptGetHashParam(hHash, HP_HASHSIZE, (PBYTE)&ulHashLen, &ulBuffLen, 0)) { DbgPrint("ERR: CryptGetHashParam() err %04Xh", GetLastError()); break; }
		if (ulHashLen > *pulBufferLen) { DbgPrint("ERR: received hash len %u more than buffer space %u bytes", ulHashLen, *pulBufferLen); break; }

		//DbgPrint("ok: hash len is %u", ulHashLen);

		// get binary hash contents
		if (!CryptGetHashParam(hHash, HP_HASHVAL, pbResultBuffer, pulBufferLen, 0)) { DbgPrint("ERR: CryptGetHashParam() err %04Xh", GetLastError()); break; }

		// done ok
		bRes = TRUE;

	} while (FALSE);

	// safe free mem
	if (wszProviderName) { my_free(wszProviderName); }

	// free handles, if any
	if (hHash) { CryptDestroyHash(hHash); }
	if (hCProv) { CryptReleaseContext(hCProv, 0); }

	return bRes;
}



/*
	Prepares global encryption/decryption context, if needed
*/
BOOL _cryptCheckInitContext(CRYPT_CONTEXT *Context)
{
	BOOL bRes = FALSE;

	LPWSTR wszProviderName = NULL; // decrypt buffer with name of cryptoprovider
	DWORD dwValue = 0;		// value buffer for CryptSetKeyParam() 

	HCRYPTHASH hHash = NULL;	// cryptoprovider's hash object's handle 

	// rnd chars generated to be used as encryption key
	LPVOID pKey = NULL;
	DWORD lKeySize = 164;	// len of generated binary string to be used as password

	RndClass rg = { 0 };	// rnd generator


	if (Context->bInited) { return TRUE; }

	do { // not a loop

		DbgPrint("initializing crypt context");

		// decrypt provider's name
		wszProviderName = CRSTRW("Microsoft Base Cryptographic Provider v1.0", "\xfd\xdf\x33\x06\xd7\xdf\x1e\x07\xee\xd5\xdc\xfd\x02\x21\xe7\x8e\x0f\x06\x80\xab\x0d\x44\xa1\x97\x7d\x53\x5c\x69\x9f\xa6\x63\x46\xa4\x84\x53\x1e\xdf\xe8\x25\x07\xe9\xc2\xc1\xae\x1b\x76\xbd\x9e\xc6\xf2\xae");

		// get provider's context
		if (!CryptAcquireContext(&Context->hProvider, NULL, wszProviderName, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) { DbgPrint("ERR: CryptAcquireContext() failed, le=%p", GetLastError()); break; }

		// create hash object
		if (!CryptCreateHash(Context->hProvider, CALG_SHA, 0, 0, &hHash)) { DbgPrint("ERR: CryptCreateHash() failed, le=%p", GetLastError()); break; }

		// prepare and generate constant pseudo-random feed
		rgNew(&rg);
		rg.rgInitSeed(&rg, TARGET_BUILDCHAIN_HASH);
		pKey = my_alloc(1024);
			DWORD lCount = lKeySize;
			BYTE *pb = (BYTE *)pKey;

			while (lCount) {

				*pb = (BYTE)rg.rgGetRndDWORD(&rg);
				//DbgPrint("i=%u byte=%u", lCount, *pb);

				pb++;
				lCount--;
			}

		// hash key's value, result will be used as the key
		if (!CryptHashData(hHash, (BYTE *)pKey, lKeySize, 0)) { DbgPrint("ERR: CryptHashData() failed, le=%p", GetLastError()); break; }

		// derive key from hash value
		if (!CryptDeriveKey(Context->hProvider, CALG_DES, hHash, CRYPT_EXPORTABLE, &Context->hKey)) { DbgPrint("ERR: CryptDeriveKey() failed, le=%p", GetLastError()); break; }

		// ### set misc values related to encryption/decryption processs

		/*
		// 40 bit effective key len for old win2000 compatibility
		ulValue=56; //40;
		if (!CryptSetKeyParam(hKey, KP_EFFECTIVE_KEYLEN, (PBYTE)&ulValue, 0)) { DbgPrint("\r\ncfEncryptDecryptBuffer: CryptSetKeyParam KP_EFFECTIVE_KEYLEN failed\r\n"); }
		*/

		// IV, if any
		//if (pIV) { CryptSetKeyParam(Context->hKey, KP_IV, (BYTE *)pIV, 0); }

		// encryption mode
		dwValue = CRYPT_MODE_CBC;
		CryptSetKeyParam(Context->hKey, KP_MODE, (PBYTE)&dwValue, 0);

		// padding settings
		dwValue = PKCS5_PADDING;
		CryptSetKeyParam(Context->hKey, KP_PADDING, (PBYTE)&dwValue, 0);

		// all done if got here
		DbgPrint("init ok");
		Context->bInited = TRUE;
		bRes = TRUE;

	} while (FALSE);	// not a loop

	// free used res
	if (wszProviderName) { my_free(wszProviderName); }
	if (hHash) { CryptDestroyHash(hHash); }
	if (pKey) { my_free(pKey); }

	return bRes;
}



/*
	Encrypts contents of stream passed, altering it's contents and len
*/
BOOL cryptEncryptStream(MY_STREAM *mStream)
{
	BOOL bRes = FALSE;	// default result

	LPVOID pEncrypted = NULL; // encrypted buffer
	DWORD dwEncryptedLen = 0;


	if (!_cryptCheckInitContext(&gCryptContext)) { DbgPrint("ERR: crypt context init failed"); return bRes; }

	do {

		// copy data into temp buffer
		if (!(pEncrypted = my_alloc(mStream->lDataLen + 1024))) { DbgPrint("ERR: failed to alloc %u bytes", mStream->lDataLen + 1024); break; }
		dwEncryptedLen = mStream->lDataLen;
		memcpy(pEncrypted, mStream->pData, mStream->lDataLen);
		

		// do encryption
		if (!CryptEncrypt(gCryptContext.hKey, 0, TRUE, 0, (BYTE *)pEncrypted, &dwEncryptedLen, dwEncryptedLen + 1024)) { DbgPrint("ERR: CryptEncrypt() failed, le=%p", GetLastError()); break; }

		// done ok, replace stream contents
		mStream->lDataLen = 0;
		mStream->msWriteStream(mStream, pEncrypted, dwEncryptedLen);

		bRes = TRUE;

	} while (FALSE);

	if (pEncrypted) { my_free(pEncrypted); }

	return bRes;
}


/*
	Decrypts passed buffer into newly allocated one
	NB: caller should dispose pDecrypted itself
*/
BOOL cryptDecryptBuffer(LPVOID pCrypted, DWORD dwCryptedLen, LPVOID *pDecryptedRes, DWORD *dwDecryptedResLen)
{
	BOOL bRes = FALSE;	// default result

	LPVOID pDecrypted = NULL;
	DWORD dwDecryptedLen = 0;

	if (!_cryptCheckInitContext(&gCryptContext)) { DbgPrint("ERR: crypt context init failed"); return bRes; }

	do {

		// alloc res buffer
		if (!(pDecrypted = my_alloc(dwCryptedLen))) { DbgPrint("ERR: failed to alloc %u mem", dwCryptedLen); break; }

		memcpy(pDecrypted, pCrypted, dwCryptedLen);

		// do decryption
		dwDecryptedLen = dwCryptedLen;
		if (!CryptDecrypt(gCryptContext.hKey, 0, TRUE, 0, (BYTE *)pDecrypted, &dwDecryptedLen)) { DbgPrint("ERR: CryptDecrypt() failed, le=%p", GetLastError()); my_free(pDecrypted); break; }

		// done ok, assign result
		*pDecryptedRes = pDecrypted;
		*dwDecryptedResLen = dwDecryptedLen;

		bRes = TRUE;

	} while (FALSE);

	return bRes;
}