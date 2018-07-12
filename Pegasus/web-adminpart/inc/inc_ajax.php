<?php
/*
	ajax.php
	In/out json data via ajax
	Executed by main router script only after auth is done
*/

	require_once 'mod_ajax_misc.php';

	// modules includes
	require_once 'mod_ajax_mmachines.php';
	require_once 'mod_ajax_mjobs.php';
	require_once 'mod_ajax_msqlog.php';
	require_once 'mod_ajax_mcreds.php';
	require_once 'mod_ajax_mtaccs.php';

	//echo "ajax here\n";

	//echo json_encode( "POST=".print_r($_POST, TRUE)." GET=".print_r($_GET, TRUE) );

	$mod_id = $_POST['m'];
	$ts = intval($_POST['ts']);

	if (!$mod_id) { errExit("invalid input params"); }
    $db_err = '';
	if (!dbInit($db_err)) { errExit("db err: {$db_err}"); }

	switch ($mod_id) {
		// modules requests
		case 'm_machines': 	mMachines($ts, $mod_id); break;
		case 'm_sqlog': 	mSQLog($ts, $mod_id); break;
		case 'm_creds': 	mCreds($ts, $mod_id); break;
		case 'm_jobs': 		mJobs($ts, $mod_id); break;
		case 'm_taccs':		mTAccs($ts, $mod_id); break;

		// simple queries
		case 'q_jlist': 	qGetAssignableJobsList(); break;
		case 'q_addjob':	qAddJob(intval($_POST['t']), intval($_POST['j'])); break;
		case 'q_jlist_cid': qGetJobsForClientId(intval($_POST['id'])); break;
		case 'del-ljob':	qRemoveJob(intval(substr($_POST['r'], 1))); break;
		case 'q_bids':		qGetBidsInfo(); break;

	 	default: errExit("unknown module {$mod_id}");
	}   // switch


?>