<?php
/*
	mod_petools.php
	PE parsing utilities
*/

// PE-processing related
define('IMAGE_FILE_MACHINE_I386', 0x014c);
define('IMAGE_FILE_MACHINE_AMD64', 0x8664);
define('sizeof_IMAGE_FILE_HEADER', 20);
define('sizeof_IMAGE_SECTION_HEADER', 40);

// IMAGE_FILE_HEADER.Characteristics
define('IMAGE_FILE_DLL', 0x2000);	//

/*
	Parse PE headers and section params into $res array
	in case of errors detected, exits via errExit()
	$pe_data contains clear file read from disk
*/
function ParsePEHeaders($pe_data, &$res)
{
	// IMAGE_DOS_HEADER
	$res['IMAGE_DOS_HEADER'] = unpack('ve_magic/ve_cblp/ve_cp/ve_crlc/ve_cparhdr/ve_minalloc/ve_maxalloc/ve_ss/ve_sp/ve_csum/ve_ip/ve_cs/ve_lfarlc/ve_ovno/v4e_res/ve_oemid/ve_oeminfo/v10e_res2/ve_lfanew', $pe_data);
	if ($res['IMAGE_DOS_HEADER']['e_magic'] != 0x05a4d) {  errExit("Invalid DOS header signature"); }

	// arch-independent part of IMAGE_NT_HEADERS : Signature + IMAGE_FILE_HEADER
	$res['IMAGE_FILE_HEADER'] = unpack('VSignature/vMachine/vNumberOfSections/VTimeDateStamp/VPointerToSymbolTable/VNumberOfSymbols/vSizeOfOptionalHeader/vCharacteristics', substr($pe_data, $res['IMAGE_DOS_HEADER']['e_lfanew']));
	if ($res['IMAGE_FILE_HEADER']['Signature'] != 0x4550) {  errExit("Invalid PE header signature");  }

	// check if machine type supported
	if (($res['IMAGE_FILE_HEADER']['Machine'] != IMAGE_FILE_MACHINE_I386)&&($res['IMAGE_FILE_HEADER']['Machine'] != IMAGE_FILE_MACHINE_AMD64)) { errExit("Unzupported target machine type {$res['IMAGE_FILE_HEADER']['Machine']}"); }

	// parse according to arch
	if ($res['IMAGE_FILE_HEADER']['Machine'] == IMAGE_FILE_MACHINE_I386) {

		// x32
		$sizeof_IMAGE_NT_HEADERS = 248;
		// IMAGE_OPTIONAL_HEADER32 is at e_lfanew + DWORD IMAGE_NT_HEADERS32.Signature + IMAGE_FILE_HEADER
		$res['IMAGE_OPTIONAL_HEADER32'] = unpack('vMagic/CMajorLinkerVersion/CMinorLinkerVersion/VSizeOfCode/VSizeOfInitializedData/VSizeOfUninitializedData/VAddressOfEntryPoint/VBaseOfCode/VBaseOfData/VImageBase/VSectionAlignment/VFileAlignment/vMajorOperatingSystemVersion/vMinorOperatingSystemVersion/vMajorImageVersion/vMinorImageVersion/vMajorSubsystemVersion/vMinorSubsystemVersion/'.
					 'VWin32VersionValue/VSizeOfImage/VSizeOfHeaders/VCheckSum/vSubsystem/vDllCharacteristics/VSizeOfStackReserve/VSizeOfStackCommit/VSizeOfHeapReserve/VSizeOfHeapCommit/VLoaderFlags/VNumberOfRvaAndSizes'.
			'/Vdd0_va/Vdd0_size/Vdd1_va/Vdd1_size/Vdd2_va/Vdd2_size/Vdd3_va/Vdd3_size', substr($pe_data, $res['IMAGE_DOS_HEADER']['e_lfanew'] + sizeof_IMAGE_FILE_HEADER + 4));

		$res['IMAGE_OPTIONAL_HEADER'] = $res['IMAGE_OPTIONAL_HEADER32'];

	} else {

		// x64
		$sizeof_IMAGE_NT_HEADERS = 264;
		// Differs: ULONGLONG ImageBase, SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit, removed BaseOfData
		$res['IMAGE_OPTIONAL_HEADER64'] = unpack('vMagic/CMajorLinkerVersion/CMinorLinkerVersion/VSizeOfCode/VSizeOfInitializedData/VSizeOfUninitializedData/VAddressOfEntryPoint/VBaseOfCode/V2ImageBase/VSectionAlignment/VFileAlignment/vMajorOperatingSystemVersion/vMinorOperatingSystemVersion/vMajorImageVersion/vMinorImageVersion/vMajorSubsystemVersion/vMinorSubsystemVersion/'.
					 'VWin32VersionValue/VSizeOfImage/VSizeOfHeaders/VCheckSum/vSubsystem/vDllCharacteristics/V2SizeOfStackReserve/V2SizeOfStackCommit/V2SizeOfHeapReserve/V2SizeOfHeapCommit/VLoaderFlags/VNumberOfRvaAndSizes'.
			'/Vdd0_va/Vdd0_size/Vdd1_va/Vdd1_size/Vdd2_va/Vdd2_size/Vdd3_va/Vdd3_size', substr($pe_data, $res['IMAGE_DOS_HEADER']['e_lfanew'] + sizeof_IMAGE_FILE_HEADER + 4));

		$res['IMAGE_OPTIONAL_HEADER'] = $res['IMAGE_OPTIONAL_HEADER64'];

	}	// arch check

	// iterate sections
	$res['sections'] = array();
	$sh_offset = $res['IMAGE_DOS_HEADER']['e_lfanew'] + $sizeof_IMAGE_NT_HEADERS;	// calc starting section header offset

    for ($i=1;$i<=$res['IMAGE_FILE_HEADER']['NumberOfSections'];$i++) {

		$sh = unpack('a8Name/VVirtualSize/VVirtualAddress/VSizeOfRawData/VPointerToRawData/VPointerToRelocations/VPointerToLinenumbers/vNumberOfRelocations/vNumberOfLinenumbers/VCharacteristics', substr($pe_data, $sh_offset));
        $sh['Characteristics'] = sprintf('%u', $sh['Characteristics']);  // php-specific signed to unsigned conversion

		$res['sections'][] = $sh;

		// adjust ptr
		$sh_offset += sizeof_IMAGE_SECTION_HEADER;

	} // for enum sections

	// all done ok
	return TRUE;
}

?>