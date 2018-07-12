/*
	inst.h
	Headers for main file
*/

#pragma once

#include <windows.h>

// prototype of shellcode's entrypoint - it receives ptr where in mem it is placed
typedef void (_stdcall *ShellcodeEntrypoint)(LPVOID);










