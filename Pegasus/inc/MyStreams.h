/*
	MyStreams.h
	Headers file
*/

#include <windows.h>
#pragma once

// initial size of buffer 
#define MY_STREAM_INIT_SIZE 102400	

// pseudo-stream definition
typedef struct _MY_STREAM MY_STREAM;
typedef struct _MY_STREAM {
	
	LPVOID pData;			// data buffer ptr
	SIZE_T lDataLen;		// amount of data currently in buffer
	SIZE_T lMaxBufferLen;	// max amount of data currently able to fit in buffer

	// exported methods
	VOID (*msFreeStream)	(MY_STREAM *pStream);
	VOID (*msWriteStream)	(MY_STREAM *pStream, LPVOID pData, SIZE_T lDataLen);
	SIZE_T (*msReadStream)	(MY_STREAM *pStream, LPVOID pReadBuffer, SIZE_T lReadBufferLen);

} MY_STREAM, *PMY_STREAM;

#ifdef __cplusplus
	extern "C" {
#endif

	// apis
	BOOL msInitStream_(MY_STREAM *pStream);

#ifdef _DEBUG
	BOOL msInitStream_dbg(LPSTR szCaller, MY_STREAM *pStream);
#endif

	//VOID msFreeStream(MY_STREAM *pStream);
	//VOID msWriteStream(MY_STREAM *pStream, LPVOID pData, SIZE_T lDataLen);
	//SIZE_T msReadStream(MY_STREAM *pStream, LPVOID pReadBuffer, SIZE_T lReadBufferLen);

#ifdef __cplusplus
}
#endif

#ifndef _DEBUG
	#define msInitStream msInitStream_
#else
	#define msInitStream(ms) msInitStream_dbg(__FUNCTION__"@"QUOTE(__LINE__), ms)
#endif