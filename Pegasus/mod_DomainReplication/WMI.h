/*
	WMI.h
*/

#include <windows.h>


#ifdef __cplusplus
extern "C" {
#endif

	BOOL wmiStartRemoteProcess(LPWSTR wszTargetMachine, LPWSTR wszRemoteFilename, LPWSTR wszUsername, LPWSTR wszPassword);

#ifdef __cplusplus
}
#endif