/*
	RandomGen.h
 Headers file

 */

#pragma once

#define MAKE_UINT64(high, low) (UINT64)( ((UINT64)high << 32 ) | (DWORD)low )

// declarate struc with no definition, to allow self-links in method
typedef struct _RndClass RndClass;

// define the pseudo-class struct
typedef struct _RndClass
{
	// internal seed values
	SIZE_T lStrucLen;	// used as a flag meaning initialization is already done
	DWORD m_w;
	DWORD m_z;

	// exported methods
	VOID(*rgInitSeed)			(RndClass *rg, UINT64 i64Seed);
	VOID	(*rgInitSeedFromTime)	(RndClass *rg);
	DWORD	(*rgGetRndDWORD)		(RndClass *rg);
	DWORD	(*rgGetRnd)				(RndClass *rg, DWORD dwMin, DWORD dwMax);

} RndClass, *PRndClass;


// define functions for import-export, used in both compilation modes
typedef struct _RndClass_ptrs {

	BOOL (*fnrgNew)(RndClass *rg);	// this is sufficient, all other functions are exported internally

} RndClass_ptrs, *PRndClass_ptrs;




#ifdef ROUTINES_BY_PTR

	#pragma message(__FILE__": ROUTINES_BY_PTR compilation mode")

	// global var definition to be visible by all modules which use this one
	#ifdef __cplusplus
		extern "C" RndClass_ptrs RndClass_apis;
	#else
		extern RndClass_ptrs RndClass_apis;
	#endif

	// transparent code replacements
	#define rgNew RndClass_apis.fnrgNew


	VOID RndClass_resolve(RndClass_ptrs *apis);

#else



	#ifdef __cplusplus
	extern "C" {
	#endif

		// RndClass struc constructor
		// fill all the values of passed struct
		// NB: re-init safe, no rg rewrite in case func finds struct to be already initialized
		// returns TRUE in case values were written, signalizing to caller need to perform additional init steps, like rgInitSeedFromTime
		BOOL rgNew(RndClass *rg);

		// init seeds with passed values
		// if seeds are 0, the default values are left
		VOID rgInitSeed(RndClass *rg, UINT64 i64Seed);

		// internally inits rnd seeds from system time/tickcount values
		// may be disabled or rewritten for ring0 code
		VOID rgInitSeedFromTime(RndClass *rg);

		// The heart of the generator
		// It uses George Marsaglia's MWC algorithm to produce an unsigned integer
		DWORD rgGetRndDWORD(RndClass *rg);

		// returns random number in range [dwMin, dwMax]
		DWORD rgGetRnd(RndClass *rg, DWORD dwMin, DWORD dwMax);

		VOID RndClass_imports(RndClass_ptrs *apis);

	#ifdef __cplusplus
		}
	#endif


#endif