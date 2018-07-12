/*	
	MyStreams.c
	C stream-like structures and functions
*/

#include <windows.h>

#include "dbg.h"
#include "mem.h"

#include "MyStreams.h"



/*
	deinit and free stream object
*/
VOID msFreeStream(MY_STREAM *pStream)
{
	if (!pStream) { DbgPrint("ERR: null stream ptr passed"); return; }	

	// free buffer, if any
	if ((pStream->pData) && (pStream->lMaxBufferLen)) { 
		
		//DbgPrint("deallocating buffer at %04Xh of total len %u with data len %u", pStream->pData, pStream->lMaxBufferLen, pStream->lDataLen);
	
		my_free(pStream->pData);

	} else { DbgPrint("WARN: nothing to deallocate at %04Xh (maxlen %u, data len %u)", pStream->pData, pStream->lMaxBufferLen, pStream->lDataLen); }

	// wipe out data
	// not sure if safe for call in pseudo-object mode
	//memset(pStream, 0, sizeof(MY_STREAM));
}

/*
	writes to a stream specified amount of data, expanding internal buffer, if needed
	No other access to stream should be performed while this api is in progress
*/
VOID msWriteStream(MY_STREAM *pStream, LPVOID pData, SIZE_T lDataLen)
{
	LPVOID pNewBuff;	// ptr to a newly allocated buffer for size expanding
	SIZE_T lNewBuffSize; // size of ^

	if (!pStream) { DbgPrint("ERR: null stream ptr passed"); return; }	

	//DbgPrint("pData=%04Xh lDataLen=%u", pData, lDataLen);

	// check for buffer expansion
	if ((pStream->lDataLen + lDataLen) > pStream->lMaxBufferLen) {

		//DbgPrint("need to expand stream buffer at %04Xh: current max size %u, needed %u", pStream, pStream->lMaxBufferLen, pStream->lDataLen + lDataLen);

		// alloc new buffer to hold result
		lNewBuffSize = pStream->lDataLen + lDataLen + pStream->lMaxBufferLen;
		pNewBuff = my_alloc(lNewBuffSize);

		// copy original data, if prev data exists
		if ((pStream->pData)&&(pStream->lDataLen)) {
			memcpy(pNewBuff, pStream->pData, pStream->lDataLen);

			// free previous buffer
			my_free(pStream->pData);

		} else { DbgPrint("prev buffer was empty for stream at %04Xh (pData=%04Xh lDataLen=%u)", pStream, pStream->pData, pStream->lDataLen); }

		// modify ptr, maxsize
		pStream->pData = pNewBuff;
		pStream->lMaxBufferLen = lNewBuffSize;
		//DbgPrint("expanded max buffer at %04Xh to %u", pStream, lNewBuffSize);

	} // check for buffer expansion

	// add new data
	memcpy( (LPVOID)((SIZE_T)pStream->pData + pStream->lDataLen), pData, lDataLen );
	pStream->lDataLen += lDataLen;

}

/*
	performs read from data stream into specified buffer, removing read data
	from stream
	Returns amount of bytes read into buffer
*/
SIZE_T msReadStream(MY_STREAM *pStream, LPVOID pReadBuffer, SIZE_T lReadBufferLen)
{
	SIZE_T lBytesRead = 0;	// amount of data read into specified buffer

	if (!pStream) { DbgPrint("ERR: null stream ptr passed"); return 0; }	
	if ((!pReadBuffer) || (!lReadBufferLen)) { DbgPrint("ERR: null target ptr passed"); return 0; }	

	// check if stream contains data
	if (pStream->lDataLen > 0) {

		// select how much we will read
		lBytesRead = lReadBufferLen;
		if (lBytesRead > pStream->lDataLen) { lBytesRead = pStream->lDataLen; }

		//DbgPrint("reading %u bytes from stream at %04Xh", lBytesRead, pStream);

		memcpy(pReadBuffer, pStream->pData, lBytesRead);

		// check for buffer move, if needed
		if (lBytesRead < pStream->lDataLen) {

			memcpy(pStream->pData, (LPVOID)( (SIZE_T)pStream->pData + lBytesRead ), pStream->lDataLen - lBytesRead);

		}

		// modify data len
		pStream->lDataLen -= lBytesRead;


	} else { /*DbgPrint("ERR: no data in target stream");*/ }

	// return result
	return lBytesRead;
}

/*
	initializes stream pseudo-object
	returns TRUE on success
*/
BOOL msInitStream_(MY_STREAM *pStream)
{
	if (!pStream) { DbgPrint("ERR: null stream ptr passed"); return FALSE; }

	// wipe out structure
	memset(pStream, 0, sizeof(MY_STREAM));

	// alloc and set buffers
	if (!(pStream->pData = my_alloc(MY_STREAM_INIT_SIZE))) { DbgPrint("ERR: failed to alloc %u", MY_STREAM_INIT_SIZE); return FALSE; }

	pStream->lMaxBufferLen = MY_STREAM_INIT_SIZE;

	//DbgPrint("stream at %04Xh inited to %u len", pStream, pStream->lMaxBufferLen);

	// fill method ptrs
	pStream->msFreeStream = msFreeStream;
	pStream->msReadStream = msReadStream;
	pStream->msWriteStream = msWriteStream;

	return TRUE;

}

#ifdef _DEBUG
BOOL msInitStream_dbg(LPSTR szCaller, MY_STREAM *pStream)
{
	if (!pStream) { DbgPrint("ERR: null stream ptr passed"); return FALSE; }

	// wipe out structure
	memset(pStream, 0, sizeof(MY_STREAM));

	// alloc and set buffers
	if (!(pStream->pData = my_alloc_int(szCaller, MY_STREAM_INIT_SIZE))) { DbgPrint("ERR: failed to alloc %u", MY_STREAM_INIT_SIZE); return FALSE; }

	pStream->lMaxBufferLen = MY_STREAM_INIT_SIZE;

	//DbgPrint("stream at %04Xh inited to %u len", pStream, pStream->lMaxBufferLen);

	// fill method ptrs
	pStream->msFreeStream = msFreeStream;
	pStream->msReadStream = msReadStream;
	pStream->msWriteStream = msWriteStream;

	return TRUE;


}
#endif