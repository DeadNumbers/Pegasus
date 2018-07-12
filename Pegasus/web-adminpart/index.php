<?php
/*
	index.php
	Admin main
*/

//error_reporting(0);

header('Content-Type: text/html; charset=utf-8');

require_once './cfg/config.php';
require_once './inc/mod_db.php';
require_once './inc/mod_auth.php';
require_once './inc/mod_router.php';

// check auth
lgDoCheckAuth();

// db connection
$db_err = '';
if (!dbInit($db_err)) { die("dbe: {$db_err}"); }

// router for requested resources via rewrite engine
rrDoRoute();

?>