/*
	RandomGen.c
 Routines dedicated to generating pseudorandom values
in ranges, defined by the caller.
 Implemented via C classlike struct

*/

#include <windows.h>
#include "dbg.h"

#include "RandomGen.h"
//#include "dbg.h"

#ifdef ROUTINES_BY_PTR

extern "C" {
	RndClass_ptrs RndClass_apis;	// global var for transparent name translation into call-by-pointer	
}

// should be called before any other apis used to fill internal structures
VOID RndClass_resolve(RndClass_ptrs *apis)
{
#ifdef _DEBUG
	if (IsBadReadPtr(apis, sizeof(RndClass_ptrs))) { DbgPrint("DBG_ERR: bad read ptr %p len %u", apis, sizeof(RndClass_ptrs)); }
#endif
	// save to a global var
	RndClass_apis = *apis;
}

#else 


/*
	Fill passed structure with ptrs to all exported functions
	Used when module compiled as code to provide ptrs to some other child code
*/
VOID RndClass_imports(RndClass_ptrs *apis)
{
	apis->fnrgNew = rgNew;
}

#define STRHASH_PARAM(n) n
// RndClass struc constructor
// fill all the values of passed struct
BOOL rgNew(RndClass *rg)
{

	// check if it is already initialized
	if (rg->lStrucLen != sizeof(RndClass)) {

		// struct size, at the same time - init flag
		rg->lStrucLen = sizeof(RndClass);

		// Any pair of unsigned integers should be fine
		// NB: constants replaced with GetTickCount() calls
		rg->m_w = GetTickCount();
		rg->m_z = GetTickCount() ^ (DWORD)STRHASH_PARAM(0x16ca75882606765a);

		// method pointers
		rg->rgInitSeed = rgInitSeed;
		rg->rgInitSeedFromTime = rgInitSeedFromTime;
		rg->rgGetRndDWORD = rgGetRndDWORD;
		rg->rgGetRnd = rgGetRnd;

		// report we have done initialization
		return TRUE;

	}	else {

		// struct seems to be already initialized
		return FALSE;

	}	// init check

}


// init seeds with passed values
// if seeds are 0, the default values are left
VOID rgInitSeed(RndClass *rg, UINT64 i64Seed)
{
	if (i64Seed) { 
		rg->m_w = (DWORD)( i64Seed >> 32 );  
		rg->m_z = (DWORD)i64Seed; 

		//DbgPrint("w=%08Xh (%u) z=%08Xh (%u)", rg->m_w, rg->m_w, rg->m_z, rg->m_z);
	}
}

// internally inits rnd seeds from system time/tickcount values
// may be disabled or rewritten for ring0 code
VOID rgInitSeedFromTime(RndClass *rg)
{
	SYSTEMTIME st;	// result of GetSystemTime api

	// get system time, to use seconds & milliseconds at rnd seed #2
	GetSystemTime(&st);

	// call internal method to really set the values
	rg->rgInitSeed(rg, MAKE_UINT64(GetTickCount(), (DWORD)(((DWORD)st.wSecond << 16) + st.wMilliseconds)));
}

// The heart of the generator
// It uses George Marsaglia's MWC algorithm to produce an unsigned integer
DWORD rgGetRndDWORD(RndClass *rg)
{
    rg->m_z = 36969 * (rg->m_z & 65535) + (rg->m_z >> 16);
    rg->m_w = 18000 * (rg->m_w & 65535) + (rg->m_w >> 16);
	//DbgPrint("a=%08Xh (%u) b=%08Xh (%u) ", (rg->m_z & 65535), (rg->m_z & 65535), (36969 * (rg->m_z & 65535)), (36969 * (rg->m_z & 65535)));
    return (rg->m_z << 16) + rg->m_w;
}

// returns random number in range [dwMin, dwMax]
DWORD rgGetRnd(RndClass *rg, DWORD dwMin, DWORD dwMax)
{
		double dRes;	// to avoid too aggressive compiler optimizations (double->dword inside of calculations)

// calculate with no matter what is bigger
if (dwMin>dwMax) { dRes = dwMax+((dwMin-dwMax+1)*(rg->rgGetRndDWORD(rg)/(MAXDWORD+1.0)));  }
			else { dRes = dwMin+((dwMax-dwMin+1)*(rg->rgGetRndDWORD(rg)/(MAXDWORD+1.0)));  } 

return (DWORD)dRes;

}

#endif