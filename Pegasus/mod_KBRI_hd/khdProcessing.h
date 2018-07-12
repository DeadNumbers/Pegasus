/*
	khdProcessing.h
*/

#include <Windows.h>

BOOL kpCheckFile(LPCWSTR wszExistingFilename, LPVOID *pNewData, DWORD *dwNewDataLen, FILETIME *ftC, FILETIME *ftA, FILETIME *ftW);