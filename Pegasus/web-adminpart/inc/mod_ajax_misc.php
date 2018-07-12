<?php
/*
	mod_ajax_misc.php
*/

	require_once 'mod_db.php';
	require_once 'ip2location.class.php';

// displays an error in json and exists
// some callbacks needs module id, which may be passed as $module_id param
function errExit($msg, $module_id = '')
{
	$res = array('error' => $msg);
	if ($module_id!='') { $res['m'] = $module_id; }
	echo json_encode( $res );
	exit;
}

// translates GetTickCount() ticks into readable result
function ticks2string($ticks, $bShort = FALSE)
{
	$sec = $ticks / 100;

	$s = $sec%60;
	$m = floor( ($sec%3600)/60 );
	$h = floor( ($sec%86400)/3600 );
	$d = floor( ($sec%2592000)/86400 );

	if (!$bShort) {
	    // not short, 2 elements
		if ($d) { $many=''; if ($d>1) { $many="s"; } return "{$d} day{$many} {$h} h"; }
		if ($h) { return "{$h} h {$m} min"; }
		if ($m) { return "{$m} min {$s} s"; }
		if ($sec) { return "{$s} sec"; }
	} else {
		// short, only largest entity
		if ($d) { $many=''; if ($d>1) { $many="s"; } return "{$d} day{$many}"; }
		if ($h) { return "{$h} h"; }
		if ($m) { return "{$m} min"; }
		if ($sec) { return "{$s} sec"; }
	}
}

// translate tz bias value to GMT+-nh
function bias2string($min_bias)
{
	if (!$min_bias) { return 'GMT'; }

 	if ($min_bias>0) { $res = "GMT+"; } else { $res = "GMT"; }

	$m = $min_bias % 60;
	$h = floor( ($min_bias%3600)/60 );

	$res .= strval($h);

	if ($m) { $res .= "h{$m}m"; }

	return $res;
}

// $ips contains one or more ips separated by comma
// query ip2city with all of them and return one text result
// receives geo2ip initialized object ready to use
function ips2city($ips, $gip)
{
	global $g_exclude_ips;

	if ($ips=='') { return ''; }

	$ips_array = explode(',', $ips);
	if (count($ips_array)<1) { return ''; }

	$res = '';
    foreach ($ips_array as $ip) {

		if (!in_array($ip, $g_exclude_ips)) {

	    	$ip_info = $gip->getAll($ip);        //print_r($ip_info);

	        if ((strlen($ip_info->city)) && ($ip_info->city != '-') ) {

	        	// check if city & region are the same or looks like each other
	        	if ((strpos($ip_info->city,$ip_info->region)===FALSE) && (strpos($ip_info->region,$ip_info->city)===FALSE)) {

	        		$res .= "{$ip_info->countryShort} {$ip} {$ip_info->city}, {$ip_info->region}<br>";

	        	} else { $res .= "{$ip_info->countryShort} {$ip} {$ip_info->city}<br>";  }

	        } else { $res .= "{$ip}<br>"; }

        }
    } // foreach

    return ucwords(strtolower($res));
}


// called when $_GET['jedit']
// should return plain value passed if modification was ok
// $target_row_id should be set to numeric row
function mParseJeditMemo($table_name, $bFailOnEmpty = FALSE, $target_row_id)
{
	global $g_dblink;

 	// check input params
 	$id = intval($target_row_id); if (!$id) { die('invalid id'); }
 	$val = mysqli_real_escape_string($g_dblink, htmlspecialchars(trim($_POST['value'])));

	// if empty memo forbidden, query current value from db
 	if (($bFailOnEmpty) && ($val == '')) {
 		$res = mysqli_fetch_assoc(mysqli_query($g_dblink, "SELECT `memo` FROM `{$table_name}` WHERE `id`={$id} LIMIT 1;"));
 		die($res['memo']);
 	}

	// support for absent rows in case of build id memo at vbuilds_memo table
 	if (!mysqli_query($g_dblink, "INSERT INTO `{$table_name}` (`id`, `memo`) VALUES ({$id}, '{$val}')
 								  ON DUPLICATE KEY UPDATE `stamp`=`stamp`, `memo`='{$val}';")) { die('mysql err: '.mysqli_error($g_dblink)); }

 	// all ok
 	echo htmlspecialchars($_POST['value']);
 	exit;
}

// executed when user requests removal of a row
// should return delrow answer for callback
function mDeleteRowRequest($table_name, &$answer, $mod_id, $row_id_postval)
{
	global $g_dblink;

	$row_id = intval($row_id_postval);
	if (!$row_id) { errExit("invalid row id passed [{$row_id_postval}]"); }
	$res = mysqli_query($g_dblink, "DELETE FROM `{$table_name}` WHERE `id`={$row_id} LIMIT 1;");
	if (!$res) { errExit("db error: ".mysqli_error($g_dblink), $mod_id); }

	if (!mysqli_affected_rows($g_dblink)) { errExit("Record id {$row_id} already removed (possibly another user interacting)", $mod_id); }

	// done ok if got here
	$answer['res'] = 'delrow';
	$answer['r'] = $row_id;

	return TRUE;
}

// returns array with count of records in menu-related tables
function mCountsQuery()
{	global $g_dblink;

	$fres = array();

	$res = mysqli_query($g_dblink, "SELECT COUNT(*) AS `c` FROM `cli`
							  UNION ALL SELECT COUNT(*) FROM `creds`
							  UNION ALL SELECT COUNT(*) FROM `cmd_params`
							  UNION ALL SELECT COUNT(*) FROM `q_log`
							  UNION ALL SELECT COUNT(*) FROM `t_accs`
							  UNION ALL SELECT SUM(`trans_count_registered`) FROM `t_accs`
							  UNION ALL SELECT SUM(`trans_sum_registered`) FROM `t_accs`");
    while ($row = mysqli_fetch_assoc($res)) { $fres[] = $row['c']; }

	// K - M sizes check
	if ($fres[6] > 1000) { $fres[6] = strval(round($fres[6]/1000, 1)).'M'; } else { $fres[6] .= 'K'; }

    return $fres;
}

// converts cmd id into text to be returned to client
function CmdIdToString($cmdid)
{
	switch ($cmdid) {
	    case 1: return "Shell script";
	    case 2: return "Run dll from memory";
	    case 3: return "Run exe from disk (CreateProcess)";
	    case 4: return "Run file from disk (ShellExecute)";
	    case 5: return "Terminate host process (ExitProcess)";
		default: return "Unknown cmdid {$cmdid}";
	}
}

function CmdIdToStringShort($cmdid)
{
	switch ($cmdid) {
	    case 1: return "cmd_script";
	    case 2: return "dll_mem";
	    case 3: return "exe_disk";
	    case 4: return "shell_exec";
	    case 5: return "kill";
		default: return "unk cmdid {$cmdid}";
	}
}

// converts raw bytes into Kb/Mb/etc field
function BytesFormatted($val)
{
	$i = intval($val);
	$pos = 0;
	while ($i > 1024) { $i = $i / 1024; $pos ++; }

	$r = array('b', 'Kb', 'Mb', 'Gb', 'Tb');
	if (!isset($r[$pos])) { $r[$pos] = '?b'; }

	return strval(round($i, 1))." ".$r[$pos];
}

?>