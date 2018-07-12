/*
	RegFuncs.h
*/

#pragma once

#include <windows.h>


LSTATUS RegCreatePath(HKEY hRootKey, LPCWSTR wszRegPath);
BOOL RegWriteDWORD(LPCWSTR wszRegPath, LPCWSTR wszKeyName, DWORD dwValueToSet);
BOOL RegRemoveValue(HKEY hRootKey, LPCWSTR wszRegPath, LPCWSTR wszRegKeyname);
BOOL RegRemoveKey(HKEY hRootKey, LPCWSTR wszRegPath);