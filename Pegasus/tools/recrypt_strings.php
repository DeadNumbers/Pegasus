<?php

/*
  	v0.51 modified Aug-2015

	v0.51

	* gen_xor_byte() contains new constant instead of 0x0CC, which was added to signature detect by NOD

	-----

	* hashing routines fix to prevent 32+ rolls which led to 0x00 hash values
	* gen_xor_byte() implemented

	* CRSTR, A, W
	* String hashing support with algo params pre-enter


	  String hashing support information
	-------------------------------------

		Selects one of many (todo) hashing algorithms, and
	uses it to replace all occurencies of HASHSTR("string", 0xBEEFDEAD) macroses
		Supported parameters are the following:

		STRHASH_ALGID(n)	- n is changed every parse to contain used hashing algo id
		Compile #defines should select an appropriate code using this value

		STRHASH_PARAM(0xNNNNNNNN) - set once per script called to contain extra parameter,
		specific for selected hashing algo. Most likely - an ending hash value. This value should be
		used in hashing proc's implementation

		HASHSTR("StringToHash", xxx) - xxx will be replaced with calculated hash by selected
		algo and params.

		NB: if parses detects calls to HASHSTR without usage of STRHASH_ALGID & STRHASH_PARAM,
		it will issue an error before terminating it's execution


*/

// specify hard-coded base filename
// all linked sources and includes will be processed
$fname=$argv[1];

// save target's path to be used everywhere while quering files
$g_Path=dirname($fname)."\\";


// global vars used in code
$g_HashAlgId = 0;  // selected algo id
$g_HashParam1 = 0;	// selected extra param
$g_HashParam2 = 0;

// flag values related to hashstr macro processing
$g_IsHashStrUsed = FALSE;
$g_IsHashStrParamUsed = FALSE;
$g_IsHashStrAlgIdUsed = FALSE;

// misc constants
define("ALGID_MAXVALUE", 1);

/*
  	Initializes $g_HashAlgId & $g_HashParam
*/
function InitHashingParams()
{	global $g_HashAlgId, $g_HashParam1, $g_HashParam2;

	// select rnd values
	$g_HashAlgId = rand(1, ALGID_MAXVALUE);

	$g_HashParam1 = mt_rand(65535, mt_getrandmax());
	$g_HashParam2 = mt_rand(65535, mt_getrandmax());

}



/*
    Generates one byte (0..255) value using passed params
 This byte is used as encryption key for a byte of source data
*/
function gen_xor_byte($dwKey, $wCharPos)
{	return  ((0x05F + ($wCharPos << 3) + 1) & 0x0FF);
}


/*
  	Performs actual string's encryption using clean
  ANSI string in a binary form (removed all slashes, C-stuff like \r\n, etc)
  Should return encoded string sequence like '\x02\x05\x33\x10\x90\x90\x90\x00'
  to be incorporated into C-source
  	Encoding scheme:
  <DWORD dwRandomValue>{encoded_chunk using dwRandomValue}
  {encoded_chunk} = <WORD strLen><BYTE encoded chars>

  NB: encoded_chunk SHOULD NOT CONTAIN ANY nullchar EXCEPT AT THE END
  In case null char is detected, function should be re-started (recursion is ok in this case)
*/
function encode_string($s)
{ $dwRandom = rand(0x010000000, 0x0FFFFFFFA);

 //$b_data='';	// resulting data

 // *** prepare contents of {encoded_chunk} ***
 // put <WORD strLen> (little endian, intel style)
 $b_data=pack("v", strlen($s));

 // iterate each byte in $s[$i]
 for($i=0;$i<strlen($s);$i++) { 	// get ordinal of each byte
 	$b_char=ord($s[$i]);

	// generate xor encryption byte using some params
	$b_xor=gen_xor_byte($dwRandom, $i);

	// make byte xor
	$b_char ^= $b_xor;

	// put byte into resulting strin
	$b_data.=chr($b_char);


 }

// in case resulting string's length is not a multiply of 4, add random padding bytes
// this will prevent automated pattern recognition then last bytes of key will be
// idential to the last bytes of string
$iResLen = strlen($b_data);
$iNeedMore = 4 - ($iResLen - (( $iResLen >> 2 ) * 4));
if ($iNeedMore) {	// append extra chars
	//echo "strlen={$iResLen}, need {$iNeedMore} to 4-byte pad\r\n";
	while ($iNeedMore) {		// add random byte
		$b_data.=chr(rand(1,255));

		// dec counter
		$iNeedMore-=1;
	}
}


// xor full string using generated random key
// in case we finds a 00h char as a result byte - exit loop and re-call self
// to generate a new, possibly a better random value without 00h as a resulting byte

//echo "step1_res[{$b_data}]\r\n";

// generate a xor string using $dwRandom as dword pattern
$iLen=strlen($b_data) / 4;
$xorString='';
while ($iLen) { $xorString.=pack("V", $dwRandom); $iLen-=1;}

// xor step1 string with a key string
$b_data_s2=$b_data ^ $xorString;


// scan output string for 00h chars
$flMayProceed=TRUE;
for ($i=0;$i<strlen($b_data_s2)-1;$i++) {	// check byte value
	if (ord($b_data_s2[$i])==0) {		// signalize failure
		//echo "found 0 at pos {$i}";
  		$flMayProceed=FALSE;
	}

}

// append leading xor key
$b_data_s2=pack("V", $dwRandom).$b_data_s2;

// encode into hex sequence
$hex='';
for ($i=0;$i<strlen($b_data_s2)-1;$i++) {
	$hex.="\\x".sprintf ("%02x", ord($b_data_s2[$i]));
}

// check if we should call self again because of 00h byte in self resulting data
if (!$flMayProceed) {
	//echo "\r\nzero bytes found, chaining\r\n";	$hex=encode_string($s);
}

// output result
return $hex;

}



/*
  Called by regexp when it finds CRSTR macro
  $in_string contains all the inner text from CRSTR macro
  Should return reformatted macro in a style
  = CRSTR("source", "crypted")
  $macro_name = [ CRSTR | CRSTRA | CRSTRW ]
*/
function ParseCRSTR($macro_name, $in_string)
{
global	$repl_count;

	// before processing any slashes, handle special situations


	// remove slashes added by preg_replace with /e param
	// and before it, remove possible c-style encodins
	$s=stripcslashes($in_string);

	// get the first param by ',' pos
	$s=substr($s, 0, strpos($s, ','));

	// remove leading and trailing slashes as from "string" definition
	$s=substr($s, 1, strlen($s)-2);

	// special case: replace \" -> "
	$s=str_replace('\"', '"', $s);

	// save clean param to be used later as first CRSTR param
	// should include all special chars / cases
	//							\r	  \n	 \		 	"
	$clean=addcslashes( $s , chr(13).chr(10).chr(0x5c).chr(0x22) );

	// special case: " -> \"
	//$clean=str_replace('"', '\"', $clean);

	// perform source ANSI string encryption
	$out_param=encode_string($s);

	$repl_count+=1;	//echo "\r\n in_string=[{$in_string}]\r\n s_to_be_encoded=[{$s}]\r\n clean_for_c_source=[{$clean}]\r\n out=[{$out_param}]\r\n\r\n";

	return "= {$macro_name}(\"{$clean}\", \"{$out_param}\")";
}

/*
	Used by CRSTR*_RND macro to generate random string
	of len from min to max
	$sType is preg_match like /[a-zA-Z0-9-.]/ for each char to be checked
*/
function rnd_string($iMinLen, $iMaxLen, $sType)
{

	echo "rnd_string: len from {$iMinLen} to {$iMaxLen} [{$sType}] \r\n";
 	$s = '';
	$min = $iMinLen; if ($min < 1) { $min = 4; }
	$max = $iMaxLen; if ($max > 255) { $max = 255; }
 	$len = rand($min, $max);
 	$iteration_count = 0;

 	while (($len > 0) && ($iteration_count < 100000)) {		// pre-gen str and check it against defined regexp
		$t_s = chr(rand(0,255));

		if (preg_match($sType, $t_s) === 1) { $s.=$t_s; $len--;  }

    	// inc iterations anyway
    	$iteration_count++;
 	}

 	// check for problem with too many iterations
 	if ($iteration_count >= 100000) { die("ERROR: iteration limit reached at rnd_string(), please re-check regexp generation pattern\r\n"); }

	return $s;
}


/*
  Called by regexp when it finds CRSTR macro
  $in_string contains all the inner text from CRSTR macro
  Should return reformatted macro in a style
  = CRSTR("source", "crypted")
  $macro_name = [ CRSTR_RND | CRSTRA_RND | CRSTRW_RND ]

  #define CRSTRW_RND(rnd_decrypted_str, rnd_encrypted_str, n_minlen, n_maxlen, n_type) __cs_AtoW(__CRSTRDecrypt((BYTE *)rnd_encrypted_str))
*/
function ParseCRSTR_RND($macro_name, $in_string)
{
global	$repl_count;

	// remove slashes added by preg_replace with /e param
	// do not touch c-encodings, or explode may fail if , is decoded in encrypted text
	$params=stripslashes($in_string);

	// make params from list
	$params_array = explode(",", $params, 5);
	//print_r($params_array);

	if (count($params_array) < 5) { die("ERROR: insufficient params count in CRSTR*_RND() macro (needs 5)\r\n"); }

	// prepare regexp
	$regexp = trim($params_array[4]); // remove spaces
	$regexp = substr($regexp, 1, -1);	// remove staring and ending quotes

	// perform str gen
	$clean_string = rnd_string( intval($params_array[2]), intval($params_array[3]), $regexp);
	$out_param=encode_string($clean_string);

	$repl_count+=1;

	//echo "\r\n in_string=[{$in_string}]\r\n s_to_be_encoded=[{$s}]\r\n clean_for_c_source=[{$clean}]\r\n out=[{$out_param}]\r\n\r\n";

	return "= {$macro_name}(\"{$clean_string}\", \"{$out_param}\",{$params_array[2]},{$params_array[3]},{$params_array[4]})";
}


/*
  	converts signed into unsigned text representation
*/
function unsign($i)
{
	return sprintf("%u", $i);
}

/*
	Perform logical rol on 32bit number
 It differs from arithmetic rol which is implemented by >> sign in a matter
 that no sign extension is performed in case of negative number.
 	This is essential due to PHP does not support unsigned int natively.
 This is needed for x32 php only.
*/
function LROL32($i, $iRol)
{
	// rol as usual	$res = $i >> $iRol;

	// clear leftmost bits which should be zero (but will be 1 in case of sign extension)
    $mask = ~( 0xFFFFFFFF << (32 - $iRol));
    return $res & $mask;
}


/*
  	Performs ROL on 64 bit int specifies as 2 32bit parts
  	Input values are modified
  	$iRol = [0..64]
*/
function ROTL64($i64_HI, $i64_LOW, $iRol, &$i64Res_HI, &$i64Res_LOW)
{  if ($iRol <= 32) {
	$i64Res_LOW = ($i64_LOW << $iRol)  ^ LROL32($i64_HI, (32 - $iRol)) ;
	$i64Res_HI =  ($i64_HI << $iRol)   ^ LROL32($i64_LOW, (32 - $iRol) );
  } else {    $i64Res_LOW = ($i64_HI  << ($iRol-32) )  ^ LROL32($i64_LOW, (32 - ($iRol-32))) ;
	$i64Res_HI =  ($i64_LOW << ($iRol-32) )  ^ LROL32($i64_HI,  (32 - ($iRol-32))) ;
  }
 	/* $i64Res_LOW = unsign($i64Res_LOW);
 	 $i64Res_HI =  unsign($i64Res_HI); */

 	//  echo sprintf("%08x %08x xROL %u -> %08x %08x \r\n", $i64_HI, $i64_LOW, $iRol, $i64Res_HI, $i64Res_LOW);
 	//  echo sprintf("%032b %032b xROL %u -> %032b %032b \r\n", $i64_HI, $i64_LOW, $iRol, $i64Res_HI, $i64Res_LOW);
}



/*
  	Performs hashing for ANSI string
*/
function hash_string($s)
{	// as far as php has problems with native 64bit int on some platforms, cast hash as 2 32bit unsigned ints
	// anyway, result is the string so far, so not too much troubles with conversion
 	$i64Res_HI = 0; $i64Res_LOW = 0;
	$i64Tmp_HI = 0; $i64Tmp_LOW = 0;

	//echo "\r\nin_str [{$s}]";

 	// scan input string
	for($i=0;$i<strlen($s);$i++) {

		$i64Res_LOW = $i64Res_LOW ^ ord($s[$i]);

		// avoid 32 bit roll which will make 0 in result
		$rot_val = (( ord($s[$i]) + ($i & 0xFF) ) & 0x3F);
		if (( $rot_val <> 32)&&($rot_val >0)) {

			// make rol64
			ROTL64($i64Res_HI, $i64Res_LOW, $rot_val , $i64Tmp_HI, $i64Tmp_LOW );


			// xor with rol's results
			$i64Res_HI = ( $i64Res_HI ^ $i64Tmp_HI);
			$i64Res_LOW = ( $i64Res_LOW ^ $i64Tmp_LOW);

		}

		//echo sprintf("step %u %08x %08x rot_v %u\r\n", $i, $i64Res_HI, $i64Res_LOW, $rot_val );
 	}

	//echo "\r\n==============";

	return "0x".sprintf("%08x%08x", $i64Res_HI, $i64Res_LOW);
}




/*
  	Just like ParseCRSTR, but for another macro
*/
function ParseHASHSTR($macro_name, $in_string)
{	global	$repl_count;
	global $g_HashAlgId, $g_HashParam1, $g_HashParam2, $g_IsHashStrUsed, $g_IsHashStrParamUsed, $g_IsHashStrAlgIdUsed;

	// contains resulting param(s) to be included at = MACRO(XXX) as XXX
	$macro_all_params = '';

	// detect which macro are we parsing
	switch ($macro_name) {		
	
	// difference are in .h only, first is without rnd xor
	case "HASHSTR_CONST":
	case "HASHSTR":

			// first param should start with "
			if (substr($in_string, 1, 1)!='"') { return "{$macro_name}(".stripcslashes($in_string).")"; }

          	// remove slashes added by preg_replace with /e param
			// and before it, remove possible c-style encodins
			$s=stripcslashes($in_string);

			// get the first param by ',' pos
			$s=substr($s, 0, strpos($s, ','));

			// remove leading and trailing slashes as from "string" definition
			$s=substr($s, 1, strlen($s)-2);

			// special case: replace \" -> "
			$s=str_replace('\"', '"', $s);

			// save clean param to be used later as first CRSTR param
			// should include all special chars / cases
			//							\r	  \n	 \		 	"
			$clean=addcslashes( $s , chr(13).chr(10).chr(0x5c).chr(0x22) );

			// special case: " -> \"
			//$clean=str_replace('"', '\"', $clean);

			// perform source ANSI string hashing
			$out_param=hash_string($s);

			$macro_all_params = "\"{$clean}\", {$out_param}";

			// dbg out string hash
   			//echo "\r\n {$clean} => {$out_param}";

   			$repl_count++;

   			return "{$macro_name}({$macro_all_params})";

		break;

		// only one param generated, $in_string is not used
		case "STRHASH_ALGID": $macro_all_params = strval($g_HashAlgId); $g_IsHashStrAlgIdUsed = TRUE; break;
		case "STRHASH_PARAM": $macro_all_params = "0x".dechex($g_HashParam1).dechex($g_HashParam2); 
							  $g_IsHashStrParamUsed = TRUE; 
							  $repl_count++;
							  return "{$macro_name}({$macro_all_params})"; 
			break;

	} // switch

    $repl_count++;
	return "= {$macro_name}({$macro_all_params})";

}




/*
  Receives every single file's contents for parsing
  Shound re-write file passed at $fname in case of any changes made
  Also should return int meaning amount of replacement done
*/
function process_contents($fname, $source)
{
global	$repl_count;

	$repl_count=0;		// initial replacement count

	// parse script's content using regexp
	// \\2 is usually name of macro
	// \\3 all it's internal params as string

	// CRSTR, A, W
 	$r_source=preg_replace("/(.*)\s*=\s*(CRSTR|CRSTRA|CRSTRW)\s*\((.*)\)(.*)/e",  "'\\1'.ParseCRSTR('\\2', '\\3').'\\4'", $source);

 	// CRSTR*_RND
 	$r_source=preg_replace("/(.*)\s*=\s*(CRSTR_RND|CRSTRA_RND|CRSTRW_RND)\s*\((.*)\)(.*)/e",  "'\\1'.ParseCRSTR_RND('\\2', '\\3').'\\4'", $r_source);

	// HASHSTR and extras
    $r_source=preg_replace("/(.*)(HASHSTR|HASHSTR_CONST)\s*\((.*)\)(.*)/eU",  "'\\1'.ParseHASHSTR('\\2', '\\3').'\\4'", $r_source); // ungreedy to keep all other "()"
	$r_source=preg_replace("/(.*)(STRHASH_ALGID|STRHASH_PARAM)\s*\(0x(.*)\)(.*)/e",  "'\\1'.ParseHASHSTR('\\2', '\\3').'\\4'", $r_source);

	// check if we need to re-write target
	if ($repl_count)  {		// maybe first backup the source
		// ...

		// overwrite target
		file_put_contents($fname, $r_source);    // to disable actual write, comment this line
	}

    return $repl_count;
}


/*
  Performs file reading, content scanning, search for linked files,
  and replacement in case of data replacement
*/
function process_file($fname)
{
	// define we are using a global var for storing/checking filenames
	global $scanned_names, $g_Path;

	// convert into direct path
	$fname = realpath($fname);

	// check if this filename is not in global $scanned_names
	if (array_search($fname, $scanned_names)===FALSE) {
		// get file contents
		@$source = file_get_contents($fname);
		if ($source) {

			// new value - push into array
			array_push($scanned_names, $fname);

			// output info
			echo ":: ".basename($fname)."\n"; //" (".strlen($source)." bytes)\n";

			// process contents
			$n_found=process_contents($fname, $source);

			// final info output
			//echo ", {$n_found} repl\r\n";

			// scan for includes using regexp func in order to call self with new filename
			preg_replace("/(.*)include \"(.*)\"(.*)/e",  "'\\1'.ParseFileName('\\2').'\\3'", $source);



		} //else { echo "{$fname} not found\r\n"; } // check for size > 0

	} // check for new item

}


function ParseTry($filename_path_noext)
{
	process_file($filename_path_noext."c");
	process_file($filename_path_noext."cpp");
	process_file($filename_path_noext."h");
}


/*
   Use filename to scan both .c and .h
*/
function ParseFileName($filename)
{
	global $scanned_names, $g_Path;


	// we assume to receive "xxxx.h" only
	$f_part=substr($filename, 0, -1);

	// try both .h & .c / .cpp
	ParseTry($f_part);
	//process_file($f_part."c");
	//process_file($f_part."cpp");
	//process_file($f_part."h");

	// file path of current file
	ParseTry($g_Path.$f_part);
	//process_file($g_Path.$f_part."c");
	//process_file($g_Path.$f_part."cpp");
	//process_file($g_Path.$f_part."h");
	// file path of last processed file (cross-dirs includes)
	$l_path = pathinfo($scanned_names[count($scanned_names)-1]); $l_path = realpath($l_path['dirname'])."\\";
	ParseTry($l_path.$f_part);

}





// we will handle all the errors manually
// may be commented out for debugging purposes
//error_reporting(0);

// try to get source file's contents
if (!file_exists($fname)) { die("ERROR: Source file {$fname} not found\r\n"); }

// init global file scan list to prevent infinite recursion
$scanned_names = array();

// init global algo params for hashing macroses
InitHashingParams();

set_time_limit(10000);

// call re-enterable parser
ParseFileName($fname);

// check if hashing macro was used
if ($g_IsHashStrUsed === TRUE) {	// check if STRHASH_ALGID & STRHASH_PARAM both were used
	if ( ($g_IsHashStrParamUsed !== TRUE) || ($g_IsHashStrAlgIdUsed !== TRUE) ) {		echo "/r/n WARN: HASHSTR() without STRHASH_ALGID() and/or STRHASH_PARAM(). Results will be unusable!";
		sleep(30);

	}
} // $g_IsHashStrUsed

?>