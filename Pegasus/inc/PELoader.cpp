/*
	PELoader.cpp
 PE loader x32/x64, direct mapping, for simple dlls only

*/

#include <windows.h>

#ifndef SHELLCODE_MODE
	#pragma message("usual mode")
	#include "dbg.h"

	// define apis usually
	#define VirtualAlloc_ VirtualAlloc	
	#define VirtualFree_ VirtualFree
	#define GetProcAddress_ GetProcAddress
	#define LoadLibraryA_ LoadLibraryA

	//#define OutputDebugStringA_ OutputDebugStringA

	#define _stop

#else
	#pragma message("SHELLCODE mode")
	#define DbgPrint(args, ...)

	// define apis using shellcode context
	#define VirtualAlloc_ pAPIs->p_VirtualAlloc	
	#define VirtualFree_ pAPIs->p_VirtualFree
	#define GetProcAddress_ pAPIs->p_GetProcAddress
	#define LoadLibraryA_ pAPIs->p_LoadLibraryA

	//#define OutputDebugStringA_ pAPIs->p_OutputDebugStringA

	// sleep stop at errors
	//#define _stop while(true) {}
	#define _stop

#endif

#include "PELoader.h"

_inline void *my_memcpy(void *dst, const void *src, size_t n)
{
size_t i;
 
for( i = 0; i < n; i++ )
   ((unsigned char*)dst)[i] = ((unsigned char*)src)[i];
 
return dst;

}

// simple lstrcpy() replacement
_inline void my_lstrcpy(PCHAR pDest, PCHAR pSrc)
{
	BYTE *pbSrc = (BYTE *)pSrc;
	BYTE *pbDst = (BYTE *)pDest;

	while (*pbSrc) { *pbDst = *pbSrc; pbSrc++; pbDst++; }

}

_inline SIZE_T PeSupAlign(SIZE_T Size, SIZE_T Alignment)
{
	SIZE_T AlignedSize = Size & ~(Alignment-1);

	if (Size != AlignedSize)
		AlignedSize += Alignment;

	return(AlignedSize);
}

BOOL LoaderProcessRelocs(LPVOID NewBase, PIMAGE_NT_HEADERS Pe)
{
	DWORD						i;
	PIMAGE_DATA_DIRECTORY		DataDir;
	LONG						RelocSize;

	DataDir = PeSupGetDirectoryEntryPtr(Pe, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if (DataDir->VirtualAddress && (RelocSize = DataDir->Size))
	{
		ULONG_PTR	BaseDelta = ((ULONG_PTR)NewBase - (ULONG_PTR)PeSupGetOptionalField(Pe, ImageBase));
		PIMAGE_BASE_RELOCATION_EX	Reloc = (PIMAGE_BASE_RELOCATION_EX)((SIZE_T)NewBase + DataDir->VirtualAddress);	// DWORD -> SIZE_T

		while(RelocSize > IMAGE_SIZEOF_BASE_RELOCATION)
		{
			ULONG	NumberRelocs = (Reloc->SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / sizeof(WORD);
			PCHAR	PageVa = (PCHAR)((SIZE_T)NewBase + Reloc->VirtualAddress);	// DWORD -> SIZE_T

			if (RelocSize >= (LONG)Reloc->SizeOfBlock)
			{
				for (i=0; i<NumberRelocs; i++)
				{
					USHORT	RelocType = (Reloc->TypeOffset[i] >> IMAGE_REL_BASED_SHIFT);

					switch(RelocType)
					{
					case IMAGE_REL_BASED_ABSOLUTE:
						// Do nothing. This one is used just for alingment.
						break;
					case IMAGE_REL_BASED_HIGHLOW:
						*(PULONG)(PageVa + (Reloc->TypeOffset[i] & IMAGE_REL_BASED_MASK)) += (ULONG)BaseDelta;
						break;
#ifdef _M_AMD64
					case IMAGE_REL_BASED_DIR64:
						*(PULONG_PTR)(PageVa + (Reloc->TypeOffset[i] & IMAGE_REL_BASED_MASK)) += BaseDelta;
						break;
#endif
					default:
						break;
					}	// switch(RelocType)
				}	// for (i=0; i<NumberRelocs; i++)
			}	// if (RelocSize >= (LONG)Reloc->SizeOfBlock)
			RelocSize -= (LONG)Reloc->SizeOfBlock;
			Reloc = (PIMAGE_BASE_RELOCATION_EX)((PCHAR)Reloc + Reloc->SizeOfBlock);
		}	// while(RelocSize > IMAGE_SIZEOF_BASE_RELOCATION)
	}	// if (!ImageAtBase && DataDir->VirtualAddress && (RelocSize = DataDir->Size)

	return TRUE;
}

#if (!defined(_M_X64))
	#define PIMAGE_THUNK_DATA_XXX PIMAGE_THUNK_DATA32
	#define IMAGE_ORDINAL_FLAGXX IMAGE_ORDINAL_FLAG32
#else
	#define PIMAGE_THUNK_DATA_XXX PIMAGE_THUNK_DATA64
	#define IMAGE_ORDINAL_FLAGXX IMAGE_ORDINAL_FLAG64
#endif

#ifndef SHELLCODE_MODE
BOOL LoaderProcessImports(LPVOID NewBase, PIMAGE_NT_HEADERS Pe)
#else
BOOL LoaderProcessImports(SHELLCODE_APIS *pAPIs, LPVOID NewBase, PIMAGE_NT_HEADERS Pe)
#endif
{
	PIMAGE_IMPORT_DESCRIPTOR    pImportDescriptor = NULL;   
	PIMAGE_IMPORT_BY_NAME       pImageImportByName = NULL; 

	PIMAGE_THUNK_DATA_XXX         pFirstThunkData = NULL;   
	PIMAGE_THUNK_DATA_XXX         pOriginalThunkData = NULL;  

	PCHAR						ModuleName;
	PVOID						ModuleBase;
	PCHAR						FuncName;
	LPVOID						FuncAddr;

	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((SIZE_T)PeSupGetDirectoryEntryPtr(Pe, IMAGE_DIRECTORY_ENTRY_IMPORT)->VirtualAddress);
	if (pImportDescriptor != NULL)    
	{   
		pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((SIZE_T)NewBase+(SIZE_T)pImportDescriptor);
		while (pImportDescriptor->Name != 0)   
		{       
			ModuleName = (PCHAR)((SIZE_T)NewBase + (SIZE_T)pImportDescriptor->Name);
			//DbgPrint("ModuleName: %s", ModuleName); 
			
			// dbg chk
			//if (OutputDebugStringA_) { OutputDebugStringA_(ModuleName); }	// dbg
			//if (!ModuleName) { do {} while (TRUE); }
			

			ModuleBase = LoadLibraryA_( ModuleName );   
			if ( ModuleBase == NULL )   
			{
				// Required dll not loaded. So error occured.
				DbgPrint("ERR: module [%s] not loaded", ModuleName);
				_stop
				return FALSE;
			}
			 
			//DbgPrint( "0x%.8x:%s", ModuleBase, ModuleName );   

			pFirstThunkData = (PIMAGE_THUNK_DATA_XXX)((SIZE_T)NewBase + (SIZE_T)(pImportDescriptor->FirstThunk));
			pOriginalThunkData = (PIMAGE_THUNK_DATA_XXX)((SIZE_T)NewBase + (SIZE_T)(pImportDescriptor->OriginalFirstThunk));

			while ( pOriginalThunkData->u1.Ordinal != 0 )   
			{  

				// check for name or ordinal
				if (!(pOriginalThunkData->u1.Ordinal&IMAGE_ORDINAL_FLAGXX)) {

					// name
					pImageImportByName = (PIMAGE_IMPORT_BY_NAME)RVATOVA(NewBase, pOriginalThunkData->u1.AddressOfData);   
					FuncName = (PCHAR)(&pImageImportByName->Name);   


				} else {

					// ordinal
					FuncName = (PCHAR)( (SIZE_T)pOriginalThunkData->u1.Ordinal & 0x0000FFFF  );

				}
	
				//if (OutputDebugStringA_) { OutputDebugStringA_(FuncName); }	// dbg
				FuncAddr = GetProcAddress_((HMODULE)ModuleBase, FuncName);

				//DbgPrint("0x%.8x:%s", FuncAddr, FuncName);   

				if (FuncAddr == 0)   
				{
					// Required funciton not found. So error occured.
					DbgPrint("ERR: import not resolved:");
					if (!(pOriginalThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAGXX)) { DbgPrint("module name [%s]ptr%04Xh api name [%s]ptr%04Xh", ModuleName, ModuleName, FuncName, FuncName); } else { DbgPrint("module name [%s] api ordinal %04Xh", ModuleName, FuncName); }
					
					_stop
					return FALSE;   
				}

				// ULONG* was, SIZE_T tried
				*(LPVOID *)pFirstThunkData = FuncAddr;

				pOriginalThunkData++;   
				pFirstThunkData++;   
			}   

			pImportDescriptor++;   
		}   
	}
	return TRUE;
}

/*
	Simple PE loader wrapper function
	pPE - ptr to buffer with dll to be loaded (it's size is calculated from PE header)
	pImage & lImageSize - ptrs to resulting virtual HMODULE (dll imagebase) and it's size
	pDllMainParam - value to be specified to dllmain as lpvReserved param
	pEntryPoint - ptr to receive entry point (dllmain)
	NB: it is up to caller to execute module's entrypoint with essential params!
*/
#ifndef SHELLCODE_MODE
BOOL PELoad(LPVOID pPE, LPVOID *pImage, SIZE_T *lImageSize, LPVOID *pEntryPoint )
#else
BOOL PELoad(SHELLCODE_APIS *pAPIs, LPVOID pPE, LPVOID *pImage, SIZE_T *lImageSize, LPVOID *pEntryPoint )
#endif
{
	BOOL bRes = FALSE;	// initial func result

	SIZE_T						i, NumberSections, FileAlign, bSize;
	PIMAGE_NT_HEADERS			Pe = (PIMAGE_NT_HEADERS)PeSupGetImagePeHeader((SIZE_T)pPE);
	PIMAGE_SECTION_HEADER		Section = IMAGE_FIRST_SECTION(Pe);

	if ((!pPE)||(!pImage)||(!lImageSize)||(!pEntryPoint)) {	DbgPrint("WARN: input params validation failed"); return bRes; }

	*lImageSize = PeSupGetOptionalField(Pe, SizeOfImage);
	*pImage = (PCHAR)VirtualAlloc_(0, *lImageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	NumberSections	= Pe->FileHeader.NumberOfSections;
	FileAlign		= PeSupGetOptionalField(Pe, FileAlignment);

	my_memcpy(*pImage, pPE, PeSupGetOptionalField(Pe, SizeOfHeaders));

	// Copying sections
	for(i=0; i<NumberSections; i++)
	{
		bSize = PeSupAlign(Section->SizeOfRawData, FileAlign);
		if (bSize)
		{
			my_memcpy((LPVOID)((SIZE_T)*pImage + Section->VirtualAddress), (LPVOID)((SIZE_T)pPE + Section->PointerToRawData), bSize);
		}
		Section += 1;
	}

	// Processing relocs and imports
#ifndef SHELLCODE_MODE
	if(!LoaderProcessRelocs(*pImage, Pe) || !LoaderProcessImports(*pImage, Pe))
#else
	if(!LoaderProcessRelocs(*pImage, Pe) || !LoaderProcessImports(pAPIs, *pImage, Pe))
#endif
	{
		DbgPrint("failure during relocs or imports processing");
		VirtualFree_(*pImage, 0, MEM_RELEASE);
		return bRes;
	}

	*pEntryPoint = (LPVOID)((SIZE_T)*pImage+PeSupGetOptionalField(Pe, AddressOfEntryPoint));
	DbgPrint("EP is found at %04Xh",  *pEntryPoint);
	bRes = TRUE;

	return bRes;

}