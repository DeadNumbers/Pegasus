/*
	NetMessageEnvelope.h
*/

#pragma once

#include <windows.h>


#pragma pack(push)	
#pragma pack(1)		
// special structure to envelope all network messages into
typedef struct _NET_MESSAGE_ENVELOPE {

	DWORD dwRandomKey;	// some random value to encode all other fields

	// --- hash is calculated starting from here ---
	BYTE bMessageHash[20];	// sha hash of all chunk except first dword with rnd encoding value

	// params to identify a message
	BYTE bMessageId;	// id of message appended

} NET_MESSAGE_ENVELOPE, *PNET_MESSAGE_ENVELOPE;
#pragma pack(pop)

VOID nmeMakeEnvelope(LPVOID pBuffer, DWORD dwBufferLen, BYTE bMessageId, LPVOID *pEnveloped, DWORD *dwEnvelopedLen);
BOOL nmeCheckRemoveEnvelope(LPVOID pBuffer, DWORD *dwBufferLen, BYTE *bMessageId);