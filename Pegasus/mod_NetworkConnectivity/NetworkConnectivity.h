/*
	NetworkConnectivity.h
	Headers file
*/
#pragma once

#include <windows.h>






VOID ncStartNetworkConnectivity();


// used by transport_Pipes.cpp
LPWSTR nmlGetFreshestItem();
UINT64 ncGetMachineHash();