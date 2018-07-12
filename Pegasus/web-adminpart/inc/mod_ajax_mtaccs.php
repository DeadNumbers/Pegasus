<?php
/*
	mod_ajax_mtaccs.php
*/

	require_once 'mod_ajax_misc.php';
	require_once 'mod_db.php';


/*
  	Used to switch t-acc state as a respond to click on status value
  	$_POST['r'] should contain target record id
*/
function mtaccs_switch(&$answer)
{
	global $g_dblink;
	$id = intval($_POST['r']);
	if ($id<=0) { errExit('Invalid id passed'); }

	// issue query
	if (!mysqli_query($g_dblink, "UPDATE `t_accs` SET `b_enabled`=NOT(`b_enabled`) WHERE `id`={$id} LIMIT 1;")) { errExit('state update query failed: '.mysqli_error($g_dblink)); }
	if (!mysqli_affected_rows($g_dblink)) { errExit("No records with id {$id}"); }

	// passed ok, issue row update command for js frontside
	$answer['res'] = 'upd';

}


/*
  	Called to verify and add a single t-acc record
*/
function mtaccs_add_single($addContext, $extra_err)
{	global $g_dblink;


	if (strlen($addContext['bic']) != 9) { errExit("{$extra_err}BIC length expected 9, found ".strlen($addContext['bic'])); }
	if (preg_match('/[^0-9]/', $addContext['bic'])) { errExit('{$extra_err}BIC contains non-numbers'); }

	if (strlen($addContext['corr']) != 20) { errExit("{$extra_err}CorrespAcc length expected 20, found ".strlen($addContext['corr'])); }
	if (preg_match('/[^0-9]/', $addContext['corr'])) { errExit('{$extra_err}CorrespAcc contains non-numbers'); }

	if (strlen($addContext['pers']) != 20) { errExit("{$extra_err}PersonalAcc length expected 20, found ".strlen($addContext['pers'])); }
	if (preg_match('/[^0-9]/', $addContext['pers'])) { errExit('{$extra_err}PersonalAcc contains non-numbers'); }

	if (strlen($addContext['inn']) != 10) { errExit("{$extra_err}INN length expected 10, found ".strlen($addContext['inn'])); }
	if (preg_match('/[^0-9]/', $addContext['inn'])) { errExit('{$extra_err}INN contains non-numbers'); }

	if (strlen($addContext['kpp']) != 9) { errExit("{$extra_err}KPP length expected 9, found ".strlen($addContext['kpp'])); }
	if (preg_match('/[^0-9]/', $addContext['kpp'])) { errExit("{$extra_err}KPP contains non-numbers"); }

	if (strlen($addContext['name']) < 3) { errExit("{$extra_err}Name not filled"); }

	// issue db query
    if (!(mysqli_query($g_dblink, "INSERT INTO `t_accs` (`stamp`, `b_gp`, `trans_min`, `trans_max`, `max_trans_count`, `max_trans_sum`,
    								`f_bic`, `f_corr`, `f_acc`, `f_inn`, `f_kpp`, `f_name`) VALUES
								  (NOW(),
								  {$addContext['gp']},
								  {$addContext['s_min']},
								  {$addContext['s_max']},
								  {$addContext['s_tr_count']},
								  {$addContext['s_tr_sum']},
								  '{$addContext['bic']}',
								  '{$addContext['corr']}',
								  '{$addContext['pers']}',
								  '{$addContext['inn']}',
								  '{$addContext['kpp']}',
								  '{$addContext['name']}' );"))) { errExit("{$extra_err}add query failed: ".mysqli_error($g_dblink)); }

}


/*
  	Called from mTAccs() when it detects a command and needs to validate it
  	Should not return control to caller
*/
function mtaccs_add()
{
	global $g_dblink;

	$Context = array();

	// same for both add types    $Context['s_min'] = intval($_POST['s_min']);
    $Context['s_max'] = intval($_POST['s_max']);
    $Context['s_tr_count'] = intval($_POST['s_trc']);
    $Context['s_tr_sum'] = intval($_POST['s_sum']);
    if (!$Context['s_min'] || !$Context['s_max'] || !$Context['s_tr_count']) { errExit("Empty limits not allowed ( {$Context['s_tr_count']} @ [{$Context['s_min']}K-{$Context['s_max']}K])"); }
	if ($Context['s_min']>=$Context['s_max']) { errExit("Min-max limits invalid ( {$Context['s_tr_count']} @ [{$Context['s_min']}K-{$Context['s_max']}K])"); }
	if ($Context['s_min'] > 300000) { errExit("Min limit ({$Context['s_min']}) out of range [1..300000]"); }
	if ($Context['s_max'] > 300000) { errExit("Max limit ({$Context['s_max']}) out of range [1..300000]"); }

    $add_type = intval($_POST['s_btype']);

	if ($add_type == 2) {

		// manual, single item

		$Context['bic'] = $_POST['s_bik'];
		$Context['corr'] = $_POST['s_ca'];
		$Context['pers'] = $_POST['s_pa'];
	 	$Context['inn'] = $_POST['s_inn'];
		$Context['kpp'] = $_POST['s_kpp'];
		$Context['name'] = mysqli_real_escape_string($g_dblink, $_POST['s_name']);
		$Context['gp'] = intval(@$_POST['s_gp']);

		mtaccs_add_single($Context, '');

	} else {
		// bulk via file - check file uploaded
		if ((!isset($_FILES['upf'])) || ($_FILES['upf']['error'] != 0)) { errExit('no file uploaded'); }
		$txt_arr = explode("\n", file_get_contents($_FILES['upf']['tmp_name']));
		unlink($_FILES['upf']['tmp_name']);

		// files are in win1251 encoding, report it to db
		if (!mysqli_set_charset($g_dblink, "cp1251")) { errExit("failed to set charset: ".mysqli_error($g_dblink)); }

		foreach ($txt_arr as $key => $val) {
			$val = trim($val);	// remove spaces and \r
			$extra_err = "line(".strval($key+1)."): ".htmlentities($val)."<br>";	// error to be supplied to adder function

			if (strlen($val)>250) { errExit("{$extra_err}single line length too big"); }

			$items = explode("|", $val);
			if (count($items) != 7) { errExit("{$extra_err}items count mismatch, expected 7, found ".strval(count($items))); }

			// fill $Context
			$Context['bic'] = $items[0];
			$Context['corr'] = $items[1];
			$Context['pers'] = $items[2];
		 	$Context['inn'] = $items[3];
			$Context['kpp'] = $items[4];
			$Context['name'] = mysqli_real_escape_string($g_dblink, $items[5]);
			$Context['gp'] = 0;
			$Context['s_tr_sum'] = floor($items[6] / 1000);

			//print_r($Context);

			mtaccs_add_single($Context, $extra_err);

			//echo "DONE";

		} // foreach


	}


	// all done ok
  	echo json_encode(array('res'=>'ok'));
  	exit;
}



function mTAccs($ts, $mod_id)
{
  	global $g_dblink;

	// define resulting answer
	$answer = array();
	// current module id
	$answer['m'] = $mod_id;

	// memo edit parser
  	if (isset($_POST['jeid'])) { mParseJeditMemo('t_accs', TRUE, $_POST['jeid']); exit; }


	// check if command defined
	if (@isset($_POST['cmd'])) {

		switch ($_POST['cmd']) {

			case 'addtacc' : mtaccs_add(); break;

        	default: errExit("unknown cmd {$_POST['cmd']}"); break;
       	} // switch cmd passed

	    exit;
	} // cmd defined


	if (@isset($_POST['c'])) {

		switch ($_POST['c']) {

			case 'switch-ta' : mtaccs_switch($answer); break;
			case 'del-ta': mDeleteRowRequest('t_accs', $answer, $mod_id, $_POST['r']);
						   mysqli_query($g_dblink, "INSERT INTO `t_accs_removed` (`ta_id`) VALUES (".strval(intval($_POST['r'])).");");
						   break;

        	default: errExit("unknown cmd {$_POST['c']}"); break;
       	} // switch cmd passed

		echo json_encode($answer);
	    exit;
	} // cmd defined



	// prepare query
	$sql_extra = '';
	if ($ts) { $sql_extra = "WHERE `stamp` > FROM_UNIXTIME({$ts})";  }
	$sql = "SELECT *,
					DATE_FORMAT(`stamp`, '%d/%m %H:%i') AS `stamp`,
					(UNIX_TIMESTAMP(NOW()) - UNIX_TIMESTAMP(`stamp`)) AS `ts_ago`,
					UNIX_TIMESTAMP(`stamp`) AS `ts`
					FROM `t_accs` {$sql_extra} ORDER BY `id` ASC";

    // issue query
	if (!($res = mysqli_query($g_dblink, $sql))) { errExit("db query error: ".mysqli_error($g_dblink)); }

	$answer['r'] = array();
	$answer['ts'] = 0;

	while ($row = mysqli_fetch_assoc($res)) {

		// convert fields
		if ($row['b_enabled']>0) { $row['status'] = 'ENABLED'; } else { $row['status'] = 'disabled'; }
		unset($row['b_enabled']);

		$row['limits'] = "{$row['trans_min']}K - {$row['trans_max']}K<br>{$row['max_trans_count']} | {$row['max_trans_sum']}K";
        unset($row['max_trans_sum']); unset($row['max_trans_count']); unset($row['trans_min']); unset($row['trans_max']);

		$row['params'] = "BIC {$row['f_bic']} CorrAcc {$row['f_corr']}<br>PersAcc {$row['f_acc']} INN {$row['f_inn']} KPP {$row['f_kpp']}<br>{$row['f_name']}";
		unset($row['f_bic']); unset($row['f_corr']); unset($row['f_acc']); unset($row['f_inn']); unset($row['f_kpp']); unset($row['f_name']);
        if ($row['b_gp'] > 0) { $row['params'] .= " <b>GP</b>"; }
		unset($row['b_gp']);

		if (($row['trans_count_registered']>0) || ($row['trans_sum_registered']>0)) {
		$row['reginfo'] = "{$row['trans_count_registered']} @ {$row['trans_sum_registered']}K";  } else { $row['reginfo'] = "-"; }
		unset($row['trans_count_registered']); unset($row['trans_sum_registered']);

		// generic values
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