<?php
/*
	mod_ajax_mcreds.php
*/

	require_once 'mod_ajax_misc.php';
	require_once 'mod_db.php';

function mCreds($ts, $mod_id)
{
  	global $g_dblink;

	// define resulting answer
	$answer = array();
	// current module id
	$answer['m'] = $mod_id;

	// prepare query
	$sql_extra = '';
	if ($ts) { $sql_extra = "WHERE `stamp` > FROM_UNIXTIME({$ts})";  }
	$sql = "SELECT 	`id`,
					`src_id`,
					DATE_FORMAT(`stamp`, '%d/%m %H:%i') AS `stamp`,
					(UNIX_TIMESTAMP(NOW()) - UNIX_TIMESTAMP(`stamp`)) AS `ts_ago`,
					UNIX_TIMESTAMP(`stamp`) AS `ts`,
					`SM`,
					`D`,
					`U`,
					`P`
					FROM `creds` {$sql_extra} ORDER BY `stamp` DESC";

    // issue query
	if (!($res = mysqli_query($g_dblink, $sql))) { errExit("db query error: ".mysqli_error($g_dblink)); }

	$answer['r'] = array();
	$answer['ts'] = 0;

	while ($row = mysqli_fetch_assoc($res)) {

		// set some fields
		$row['cred'] = $row['D']."\\".$row['U'].":".$row['P']; unset($row['D']); unset($row['U']); unset($row['P']);

		$row['ts_ago'] = ticks2string($row['ts_ago']*100, TRUE);

		$answer['r'][] = $row;
       	if ($row['ts'] > $answer['ts'])  { $answer['ts'] = $row['ts']; }
	   	unset($row);
	} // while

	$answer['c'] = count($answer['r']);

	// all modules count assign
	$answer['mc'] = mCountsQuery();

	echo json_encode($answer);
	exit;
}



?>