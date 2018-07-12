/*
	MyStringRoutines.h
 Headers file

*/
#pragma once

#include <windows.h>
#include "RandomGen.h"


// define functions for import-export, used in both compilation modes
typedef struct _MyStringRoutines_ptrs {

	DWORD (*fnsr_replacechar)(LPWSTR wszString, WCHAR wCharToFind, WCHAR wCharToSet);
	VOID(*fnsr_replacelastchar)(LPWSTR wszString, WCHAR wCharToFind, WCHAR wCharToSet);
	VOID(*fnsr_genRandomChars)(WORD wStringLenMin, WORD wStringLenMax, WCHAR *wszOutbuffer);
	VOID(*fnsr_genRandomCharsRG)(RndClass *rg, WORD wStringLenMin, WORD wStringLenMax, LPWSTR wszOutbuffer);
	VOID(*fnsr_genRandomCharsRG_h)(RndClass *rg, WORD wStringLenMin, WORD wStringLenMax, LPWSTR wszOutbuffer);
	LPWSTR(*fnsr_findlastchar)(LPWSTR wszString, WCHAR wCharToFind);
	VOID(*fnsr_lowercase)(LPWSTR wszString);

} MyStringRoutines_ptrs, *PMyStringRoutines_ptrs;




#ifdef ROUTINES_BY_PTR

#pragma message(__FILE__": ROUTINES_BY_PTR compilation mode")

// global var definition to be visible by all modules which use this one
extern MyStringRoutines_ptrs MyStringRoutines_apis;

// transparent code replacements
#define sr_replacechar MyStringRoutines_apis.fnsr_replacechar
#define sr_replacelastchar MyStringRoutines_apis.fnsr_replacelastchar
#define sr_genRandomChars MyStringRoutines_apis.fnsr_genRandomChars
#define sr_genRandomCharsRG MyStringRoutines_apis.fnsr_genRandomCharsRG
#define sr_genRandomCharsRG_h MyStringRoutines_apis.fnsr_genRandomCharsRG_h
#define sr_findlastchar MyStringRoutines_apis.fnsr_findlastchar
#define sr_lowercase MyStringRoutines_apis.fnsr_lowercase


VOID MyStringRoutines_resolve(MyStringRoutines_ptrs *apis);

#else




#ifdef __cpluplus
extern "C" {
#endif
	
	DWORD sr_replacechar(LPWSTR wszString, WCHAR wCharToFind, WCHAR wCharToSet);
	VOID sr_replacelastchar(LPWSTR wszString, WCHAR wCharToFind, WCHAR wCharToSet);
	VOID sr_genRandomChars(WORD wStringLenMin, WORD wStringLenMax, WCHAR *wszOutbuffer);
	VOID sr_genRandomCharsRG(RndClass *rg, WORD wStringLenMin, WORD wStringLenMax, LPWSTR wszOutbuffer);
	VOID sr_genRandomCharsRG_h(RndClass *rg, WORD wStringLenMin, WORD wStringLenMax, LPWSTR wszOutbuffer);
	LPWSTR sr_findlastchar(LPWSTR wszString, WCHAR wCharToFind);
	VOID sr_lowercase(LPWSTR wszString);

	VOID MyStringRoutines_imports(MyStringRoutines_ptrs *apis);

#ifdef __cpluplus
			}
#endif

#endif