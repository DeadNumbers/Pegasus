<?php
/*
	mod_ajax_msqlog.php
*/

	require_once 'mod_ajax_misc.php';
	require_once 'mod_db.php';

// suspicious query log display
function mSQLog($ts, $mod_id)
{
  	global $g_dblink;

	// define resulting answer
	$answer = array();
	// current module id
	$answer['m'] = $mod_id;

	if (isset($_POST['c'])) {

		switch ($_POST['c']) {

			case 'remove': 	mDeleteRowRequest('q_log', $answer, $mod_id, $_POST['r']); break;

		    default: errExit("unknown cmd [{$_POST['c']}]");
		} // switch cmd

		echo json_encode($answer);
	    exit;
	} // cmd parsing part

	// prepare query
	$sql_extra = '';
	if ($ts) { $sql_extra = "WHERE `stamp` > FROM_UNIXTIME({$ts})";  }
	$sql = "SELECT 	`id`,
					DATE_FORMAT(`stamp`, '%d/%m %H:%i') AS `stamp`,
					(UNIX_TIMESTAMP(NOW()) - UNIX_TIMESTAMP(`stamp`)) AS `ts_ago`,
					UNIX_TIMESTAMP(`stamp`) AS `ts`,
					`log_json`
					FROM `q_log` {$sql_extra} ORDER BY `id` DESC";

    // issue query
	if (!($res = mysqli_query($g_dblink, $sql))) { errExit("db query error: ".mysqli_error($g_dblink)); }

	$answer['r'] = array();
	$answer['ts'] = 0;

	while ($row = mysqli_fetch_assoc($res)) {

		$row['log'] = json_decode($row['log_json']); unset($row['log_json']);
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