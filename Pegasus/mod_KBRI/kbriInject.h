/*
	kbriInject.h
*/
#pragma once
#include <windows.h>


#pragma pack(push)
#pragma pack(1)

#if defined(_M_X64)

// x64 shellcode entry trampouline
typedef struct _JumpCode
{
	WORD wMovRcxOpcode;		// param
	ULONGLONG ulParam;

	WORD wMovRaxOpcode;		// jump addr
	ULONGLONG ulExecAddr;

	WORD wJmpRaxOpcode;

} JumpCode, *PJumpCode;
#else

// x32 shellcode entry trampouline
typedef struct _JumpCode
{


	BYTE bPushOpcode1;	// param 
	DWORD dwParam;

	BYTE bPushOpcode2;
	DWORD dwRetAddr;	// addr to assume return after all routines finished (essential for proper stack access by shellcode)

	BYTE bPushOpcode3;	// exec addr
	DWORD dwExecAddr;

	BYTE bRetOpcode;

} JumpCode, *PJumpCode;

#endif

#pragma pack(pop)	// restore previous alignment settings

BOOL kbriPrepareInjBuffer(LPVOID *pResBuffer, DWORD *dwResBufferLen, DWORD *dwShellcodeEntryOffset, DWORD *dwShellcodeLen);
BOOL kbriPatchInjBufferOffsets(LPVOID pBuffer, LPVOID pTargetMemPtr, DWORD dwShellcodeEntryOffset, DWORD dwShellcodeLen);
BOOL kbriAttemptInject(DWORD dwTargetPID);