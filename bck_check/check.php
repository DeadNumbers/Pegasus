<?php
/*
  	Parses bck logs to get balance briefs
*/



/*
  	Returns value identified by $val_name
  	by searching $data for ValName="value"

*/
function GetVal($data, $val_name)
{  $from = strpos($data, $val_name);

  if ($from === FALSE) { return ''; }

  $res = '';

  $from += strlen($val_name) + 2;

  while ($data[$from] != '"') { $res .= $data[$from]; $from++; }

	return $res;
}

function fmt($val)
{	return round($val / 100 / 1000 / 1000, 2).'M';
}



/*
  	Parses file contents, specified by file pointer

*/
function ParseFileContentsByFP($fp, &$context)
{
	// read all file's contents into var
 	$data = '';

 	while (!feof($fp)) {
        $data .= fread($fp, 100000);
    }


	// check for interested patterns
	if (strpos($data, '<ED211') !== FALSE) {


		//echo "got";
		//CreditLimitSum="3000000000" EndTime="18:18:41" EnterBal="4741475536" EDDate="2015-10-15" LastMovetDate="2015-10-14" OutBal="4174667525"
        $stamp = GetVal($data, 'LastMovetDate')." ".GetVal($data, 'EndTime');

        echo $stamp." ".fmt(GetVal($data, 'EnterBal'))." -> ".fmt(GetVal($data, 'OutBal'))."<br>";

		if ($context[GetVal($data, 'LastMovetDate')]['min'] == 0) { $context[GetVal($data, 'LastMovetDate')]['min'] = GetVal($data, 'EnterBal'); }
		if ($context[GetVal($data, 'LastMovetDate')]['max'] == 0) { $context[GetVal($data, 'LastMovetDate')]['max'] = GetVal($data, 'EnterBal'); }

        $context[GetVal($data, 'LastMovetDate')]['min'] = min($context[GetVal($data, 'LastMovetDate')]['min'], GetVal($data, 'EnterBal'), GetVal($data, 'OutBal'));
        $context[GetVal($data, 'LastMovetDate')]['max'] = max($context[GetVal($data, 'LastMovetDate')]['max'], GetVal($data, 'EnterBal'), GetVal($data, 'OutBal'));

	}



	// free mem
	unset($data);
}



/*
  	Parses a single zip file - extracts files
  	and send it to other parsers
*/
function ParseZip($fname, &$context)
{
	// enum all files in that zip
	$zip = new ZipArchive;
	//open the archive
	if ($zip->open($fname) === TRUE) {
	    //iterate the archive files array and display the filename or each one
	    for ($i = 0; $i < $zip->numFiles; $i++) {

	    	// echo $zip->getNameIndex($i) . '<br />';

	        // read file contents into memory
	        $fp = $zip->getStream($zip->getNameIndex($i));

         	// parse contents by file pointer
         	if ($fp) { ParseFileContentsByFP($fp, $context); fclose($fp); }

	    }   // for files inside
	} else {
	    echo "Failed to open {$fname}";
	}

	$zip->close();

}

set_time_limit(600);

// results array context
$context = array();

foreach (glob("./bck_logs/*/*.zip") as $fname) {
    //echo "{$fname}<br>";
    ParseZip($fname, $context);
   // die();
}


echo "<br><hr>";
foreach ($context as $key => $val) {
	echo $key." -> ".fmt($val['min'])." - ".fmt($val['max'])."<br>";

}


?>