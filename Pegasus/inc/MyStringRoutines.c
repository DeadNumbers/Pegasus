/*
	MyStringRoutines.c
 Misc string handling/manipulation routines

*/

#include <windows.h>
#include "dbg.h"
#include "MyStringRoutines.h"

#ifdef ROUTINES_BY_PTR

MyStringRoutines_ptrs MyStringRoutines_apis;	// global var for transparent name translation into call-by-pointer	

// should be called before any other apis used to fill internal structures
VOID MyStringRoutines_resolve(MyStringRoutines_ptrs *apis)
{
#ifdef _DEBUG
	if (IsBadReadPtr(apis, sizeof(MyStringRoutines_ptrs))) { DbgPrint("DBG_ERR: bad read ptr %p len %u", apis, sizeof(MyStringRoutines_ptrs)); }
#endif
	// save to a global var
	MyStringRoutines_apis = *apis;
}

#else 

#include "mem.h"
#include "dbg.h"
#include "RandomGen.h"

/*
	Fill passed structure with ptrs to all exported functions
	Used when module compiled as code to provide ptrs to some other child code
*/
VOID MyStringRoutines_imports(MyStringRoutines_ptrs *apis)
{
	apis->fnsr_replacechar = sr_replacechar;
	apis->fnsr_replacelastchar = sr_replacelastchar;
	apis->fnsr_genRandomChars = sr_genRandomChars;
	apis->fnsr_genRandomCharsRG = sr_genRandomCharsRG;
	apis->fnsr_genRandomCharsRG_h = sr_genRandomCharsRG_h;
	apis->fnsr_findlastchar = sr_findlastchar;
	apis->fnsr_lowercase = sr_lowercase;
}


/*
	Scans unicode string and replaces all occurences of wchar there
	Returns amount of replacements done
*/
DWORD sr_replacechar(LPWSTR wszString, WCHAR wCharToFind, WCHAR wCharToSet)
{
	DWORD dwReplaceCount = 0;	// function's result
	SIZE_T lStrLen;	// input string len
	WORD *pwStr = (WORD *)wszString;	// get ptr of first word in unicode string

	__try {

	// calc string len
	lStrLen = lstrlenW(wszString);

	// perform iteration
	while (lStrLen) {

		// check word for replace
		if (*pwStr == wCharToFind) { *pwStr = wCharToSet; dwReplaceCount+=1; }

		// move on
		lStrLen -= 1; pwStr++;

	} // while loop

	} __except(1) { DbgPrint("WARN: exception catched"); }

	return dwReplaceCount;
}



/*
	Scans unicode string and replaces last occurence of wchar there
*/
VOID sr_replacelastchar(LPWSTR wszString, WCHAR wCharToFind, WCHAR wCharToSet)
{
	SIZE_T lStrLen;	// input string len
	WORD *pwStr = (WORD *)wszString;	// get ptr of first word in unicode string

	__try {

	// calc string len
	lStrLen = lstrlenW(wszString);

	// initial pos 
	pwStr += lStrLen;

	// perform iteration
	while (lStrLen) {

		// check word for replace
		if (*pwStr == wCharToFind) { *pwStr = wCharToSet; break; }

		// move on
		lStrLen -= 1; pwStr--;

	} // while loop

	} __except(1) { DbgPrint("WARN: exception catched"); }
}


// generates an 'a'..'z' random string of [min..max] len, with randomly-inited rnd generator
// caller should allocate wszOutbuffer itself
VOID sr_genRandomChars(WORD wStringLenMin, WORD wStringLenMax, LPWSTR wszOutbuffer)
{
	RndClass *rg;

	__try {

	// init rnd generator in rnd way
	rg = (RndClass *)my_alloc( sizeof(RndClass));
	rgNew(rg);

	// this is essential to produce random output
	rg->rgInitSeedFromTime(rg);

	sr_genRandomCharsRG(rg, wStringLenMin, wStringLenMax, wszOutbuffer);

	// free used mem
	my_free(rg);

	} __except(1) { DbgPrint("WARN: exception catched"); }

}


// generates an 'a'..'z' random string of [min..max] len using specified pre-inited RndClass pseudo-object
// caller should allocate wszOutbuffer itself
VOID sr_genRandomCharsRG(RndClass *rg, WORD wStringLenMin, WORD wStringLenMax, LPWSTR wszOutbuffer)
{
	WORD wCount = 0;	// amount of chars to generate
	WORD *pwStr = (WORD *)wszOutbuffer;	// get ptr of first word in unicode string

	__try {

	// decide on chars count
	wCount = (WORD)rg->rgGetRnd(rg, wStringLenMin, wStringLenMax);
	//DbgPrint("sr_genRandomChars: wCount=%u\r\n", wCount);

	// alloc out buffer
	//*wszOutbuffer = (WCHAR)my_alloc( ( (wCount+1) * 2) );

	while (wCount) {

		// add rnd char
		*pwStr = (WORD)rg->rgGetRnd(rg, 'a', 'z');

		// dec counter
		wCount -=1; pwStr++;
	
	} // wCount

	} __except(1) { DbgPrint("WARN: exception catched"); }

}

// generates hex upcased string 
VOID sr_genRandomCharsRG_h(RndClass *rg, WORD wStringLenMin, WORD wStringLenMax, LPWSTR wszOutbuffer)
{
	WORD wCount = 0;	// amount of chars to generate
	WORD *pwStr = (WORD *)wszOutbuffer;	// get ptr of first word in unicode string

	__try {

		// decide on chars count
		wCount = (WORD)rg->rgGetRnd(rg, wStringLenMin, wStringLenMax);
		//DbgPrint("sr_genRandomChars: wCount=%u\r\n", wCount);

		// alloc out buffer
		//*wszOutbuffer = (WCHAR)my_alloc( ( (wCount+1) * 2) );

		while (wCount) {

			// add rnd hex char
			if (rg->rgGetRnd(rg, 0, 100) > 70) { *pwStr = (WORD)rg->rgGetRnd(rg, 'A', 'F'); } else { *pwStr = (WORD)rg->rgGetRnd(rg, '0', '9'); }


			// dec counter
			wCount -= 1; pwStr++;

		} // wCount

	}
	__except (1) { DbgPrint("WARN: exception catched"); }

}



/*
	Scans unicode string and returns ptr to last occurece of a char to find
	NULL if nothing was found
*/
LPWSTR sr_findlastchar(LPWSTR wszString, WCHAR wCharToFind)
{
	SIZE_T lStrLen;	// input string len
	WORD *pwStr = (WORD *)wszString;	// get ptr of first word in unicode string

	__try {

	// calc string len
	lStrLen = lstrlenW(wszString);

	// initial pos 
	pwStr += lStrLen;

	// perform iteration
	while (lStrLen) {

		// check word for replace
		if (*pwStr == wCharToFind) { return (LPWSTR)(pwStr + 1); }

		// move on
		lStrLen -= 1; pwStr--;

	} // while loop

	} __except(1) { DbgPrint("WARN: exception catched"); }

	// no result till the end - return null
	return NULL;

}


/*
	Scans mb string and returns ptr to first occurece of a char to find
	NULL if nothing was found
*//*
LPSTR sr_findchar(LPSTR szString, CHAR cCharToFind)
{
	SIZE_T lStrLen;	// input string len
	BYTE *pStr = (BYTE *)szString;	// get ptr of first word in unicode string

	__try {

	// calc string len
	lStrLen = lstrlenA(szString);

	// perform iteration
	while (lStrLen) {

		// check word for replace
		if (*pStr == cCharToFind) { return (LPSTR)(pwStr + 1); }

		// move on
		lStrLen -= 1; pStr++;

	} // while loop

	} __except(1) { DbgPrint("WARN: exception"); }

	// no result till the end - return null
	return NULL;

}*/

/*
	Modifies wszString - make all lowercased
*/
VOID sr_lowercase(LPWSTR wszString)
{
	WORD *pwStr = (WORD *)wszString;	// get ptr of first word in unicode string

	//__try {



	// perform iteration
	while (*pwStr != 0x0000) {

		// check word for replace
		if ((*pwStr >= 'A') && (*pwStr <= 'Z')) { *pwStr += 0x20;  }

		// move on
		pwStr++;

	} // while loop

	//} __except(1) { DbgPrint("exception catched"); elLogErr(13, 0, NULL, 0); }

}


#endif