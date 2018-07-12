<?php
// file2bin.php
// simple data 2 .h include converter

// php -n -f shellcode2bin.php <source_exe> <target_h_file>

// test args
//print_r($argv); die();




$g_Filename_in = $argv[1];  $g_Filename_out = $argv[2];

	if (!file_exists($g_Filename_in)) { echo "ERR: input file {$g_Filename_in} not found"; die(); }
 	//echo "Processing {$g_Filename_in} into {$g_Filename_out} ";

  	$bin = file_get_contents($g_Filename_in);

  	//mangle_file($bin);

  	$len = strlen($bin);

	// form name
  	$name = basename($g_Filename_out, ".h");

/*	// query orig file's length into $len_orig by cutting last extension from passed input filename
	// usually input is filename.ext.lz4
	$fname_orig = substr($g_Filename_in, 0, strrpos($g_Filename_in, '.') );
	$len_orig = filesize($fname_orig);
	if (!$len_orig) { die("ERR: unable to query original file {$fname_orig}"); } */

	// resulting string
    $s = '';

    $s = "/*
    ".basename($g_Filename_out)."
	file2bin converted, sha1 ".sha1($bin)."
*/

#define bin_{$name}_len_orig {$len_orig}
#define bin_{$name}_len {$len}

BYTE bin_{$name}[{$len}] = {";

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

	//echo "\ndone";



?>