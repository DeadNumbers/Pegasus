<?php
// shellcode2bin.php
// extracts code section from special shellcode-style exe and puts in into
// special .inc file
// Reason for extracting code from exe is full-program optimization done by VC

// php -n -f shellcode2bin.php <source_exe> <target_h_file>

// test args
//print_r($argv); die();

//$g_Filename_in = "x32.exe";  $g_Filename_out = "x32.h";
$g_Filename_in = $argv[1];  $g_Filename_out = $argv[2];



/*
	$bin - binary chunk of code section to be encoded via external tool as all other data
	Returns - processed encoded data ready for convert into binhex
*/
function encode_via_tool($bin_data)
{
	// check for tool file in current dir
	if (!file_exists('LZ4_pack.exe')) { die("ERR: LZ4_pack.exe not found in current dir\n"); }

	// put orig data in current dir
	@unlink('sh_tmp');
	file_put_contents('sh_tmp', $bin_data);

	// exec tool waiting for result
	echo "Executing LZ4_pack.exe..."; ob_flush();
	exec('LZ4_pack.exe sh_tmp sh_tmp.lz4');
	echo "done\n";

	if (!file_exists('sh_tmp.lz4')) { die("ERR: no output file from LZ4_pack.exe (sh_tmp.lz4)\n"); }

	// read res and wipe tmps
	$res = file_get_contents('sh_tmp.lz4');
	@unlink('sh_tmp.lz4');
	@unlink('sh_tmp');

	echo "pack result ".strlen($bin_data)." -> ".strlen($res)." bytes\n";

	return $res;
}



/* receives
  	$file - file contents
  	$sh - parsed IMAGE_SECTION_HEADER array to first section with code params
  	$EP_offset - offset to entrypoint from the start of code section
*/
function ProcessFromSection($file, $sh, $EP_offset)
{
	global $g_Filename_out;
 	echo "Code section found at {$sh['Name']} of len {$sh['VirtualSize']}\n";

  	$bin_orig = substr($file, $sh['PointerToRawData'], $sh['VirtualSize']);

	// convert binary into encoded/packed form using external tool
	$bin = encode_via_tool($bin_orig);

	// form name
  	$name = basename($g_Filename_out, ".h");

	// resulting string
    $s = '';

    $s = "/*
    ".basename($g_Filename_out)."
	shellcode2bin converted, sha1_res ".sha1($bin)." sha1_src ".sha1($bin_orig)."
*/

#define {$name}_len_orig {$sh['VirtualSize']}
#define {$name}_len ".strlen($bin)."
#define {$name}_EP_offset {$EP_offset}

BYTE shellcode_{$name}[".strlen($bin)."] = {";

	// convert bin 2 hex
	$hex = unpack('H*', $bin); $hex_arr = str_split($hex[1], 2); //print_r($hex_arr);

	$counter = 1;
	foreach ($hex_arr as $val) {
         $s .= "0x{$val},";
         $counter++;
         if ($counter >20 ) { $s .="\r\n"; $counter = 1; }
	}

	// cut last comma
	$s = substr($s, 0, -1);

	$s .= "};";

	// save resulting dat
	file_put_contents($g_Filename_out, $s);

	echo "\nSaved to {$g_Filename_out}";
}



// for browser output
//echo "<pre>";

$file = file_get_contents($g_Filename_in);
if (strlen($file)<512) { die("file not found"); }

// IMAGE_DOS_HEADER
$idh = unpack('ve_magic/ve_cblp/ve_cp/ve_crlc/ve_cparhdr/ve_minalloc/ve_maxalloc/ve_ss/ve_sp/ve_csum/ve_ip/ve_cs/ve_lfarlc/ve_ovno/v4e_res/ve_oemid/ve_oeminfo/v10e_res2/ve_lfanew', $file);

if ($idh['e_magic'] != 0x05a4d) { die("invalid DOS header signature"); }

/*
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

*/

$nth = unpack('VSignature/vMachine/vNumberOfSections/VTimeDateStamp/VPointerToSymbolTable/VNumberOfSymbols/vSizeOfOptionalHeader/vCharacteristics', substr($file, $idh['e_lfanew']));

if ($nth['Signature'] != 0x4550) { die("ERR: invalid PE header signature"); }

// IMAGE_FILE_MACHINE_I386 == 0x014c,  IMAGE_FILE_MACHINE_AMD64 == 0x8664

if (($nth['Machine'] != 0x014c)&&($nth['Machine'] != 0x8664)) { die("ERR: Unknown Machine type {$nth['Machine']}"); }

    // struct sizes for x32
	$sizeof_IMAGE_FILE_HEADER = 20;
	$sizeof_IMAGE_SECTION_HEADER = 40;
	if ($nth['Machine'] == 0x014c) {

		// x32
		echo "ARCH: X32\n";
		$sizeof_IMAGE_NT_HEADERS = 248;
		// IMAGE_OPTIONAL_HEADER32 is at e_lfanew + DWORD IMAGE_NT_HEADERS32.Signature + IMAGE_FILE_HEADER
		$oh = unpack('vMagic/CMajorLinkerVersion/CMinorLinkerVersion/VSizeOfCode/VSizeOfInitializedData/VSizeOfUninitializedData/VAddressOfEntryPoint/VBaseOfCode/VBaseOfData/VImageBase/VSectionAlignment/VFileAlignment/vMajorOperatingSystemVersion/vMinorOperatingSystemVersion/vMajorImageVersion/vMinorImageVersion/vMajorSubsystemVersion/vMinorSubsystemVersion/'.
					 'VWin32VersionValue/VSizeOfImage/VSizeOfHeaders/VCheckSum/vSubsystem/vDllCharacteristics/VSizeOfStackReserve/VSizeOfStackCommit/VSizeOfHeapReserve/VSizeOfHeapCommit/VLoaderFlags/VNumberOfRvaAndSizes'.
			'/Vdd0_va/Vdd0_size/Vdd1_va/Vdd1_size/Vdd2_va/Vdd2_size/Vdd3_va/Vdd3_size', substr($file, $idh['e_lfanew'] + $sizeof_IMAGE_FILE_HEADER + 4));

	} else {

		// x64
		echo "ARCH: X64\n";
		$sizeof_IMAGE_NT_HEADERS = 264;
		// ULONGLONG ImageBase, SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit
		// removed BaseOfData
		$oh = unpack('vMagic/CMajorLinkerVersion/CMinorLinkerVersion/VSizeOfCode/VSizeOfInitializedData/VSizeOfUninitializedData/VAddressOfEntryPoint/VBaseOfCode/V2ImageBase/VSectionAlignment/VFileAlignment/vMajorOperatingSystemVersion/vMinorOperatingSystemVersion/vMajorImageVersion/vMinorImageVersion/vMajorSubsystemVersion/vMinorSubsystemVersion/'.
					 'VWin32VersionValue/VSizeOfImage/VSizeOfHeaders/VCheckSum/vSubsystem/vDllCharacteristics/V2SizeOfStackReserve/V2SizeOfStackCommit/V2SizeOfHeapReserve/V2SizeOfHeapCommit/VLoaderFlags/VNumberOfRvaAndSizes'.
			'/Vdd0_va/Vdd0_size/Vdd1_va/Vdd1_size/Vdd2_va/Vdd2_size/Vdd3_va/Vdd3_size', substr($file, $idh['e_lfanew'] + $sizeof_IMAGE_FILE_HEADER + 4));

	}


	//print_r($oh);
	// check some basics
	if ($oh['SizeOfInitializedData'] > 0) { echo("WARN: file contains initialized globals\n"); }
	if ($oh['SizeOfUninitializedData'] > 0) { echo("WARN: file contains uninitialized globals\n"); }

	// data directory is defined as ddN_va & ddN_size -> DATA_DIRECTORY[N] - virtual_address & size
	// ids: 0 - export, 1 - import, 2 - resource, 3 - exception
	if ($oh['dd0_size'] > 0) { die("ERR: file contains exports\n"); }
	if ($oh['dd1_size'] > 0) { die("ERR: file contains imports\n"); }

	if ($oh['dd2_size'] > 0) { echo("WARN: file contains resources, which will not be available\n"); }
	if ($oh['dd3_size'] > 0) { echo("WARN: file contains exception records, which will not be available\n"); }

	// iterate section until .code found
	$sh_offset = $idh['e_lfanew'] + $sizeof_IMAGE_NT_HEADERS;
    for ($i=1;$i<=$nth['NumberOfSections'];$i++) {

		$sh = unpack('a8Name/VVirtualSize/VVirtualAddress/VSizeOfRawData/VPointerToRawData/VPointerToRelocations/VPointerToLinenumbers/vNumberOfRelocations/vNumberOfLinenumbers/VCharacteristics', substr($file,  $sh_offset));
        $sh['Characteristics'] = sprintf('%u', $sh['Characteristics']);  // php-specific signed to unsigned conversion

		// check for relocs
		if ($sh['NumberOfRelocations'] > 0) { die("ERR: file contains relocations"); }

		//print_r($sh);

		// check for .code & params

		if (($sh['Characteristics'] & 0x20) == 0x20) { ProcessFromSection($file, $sh, $oh['AddressOfEntryPoint'] - $oh['BaseOfCode']); exit; }

		// adjust ptr
		$sh_offset += $sizeof_IMAGE_SECTION_HEADER;

	} // for enum sections

	// if we got here -> no code section was found
	die("ERR: no code section found");


//print_r($nth);


//echo substr($file, $idh['e_lfanew'] + $sizeof_IMAGE_NT_HEADERS + ( ($nth['NumberOfSections'] - 1) * $sizeof_IMAGE_SECTION_HEADER ) );

?>