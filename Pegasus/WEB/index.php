<?php
/*
	index.php
	Main input
*/

error_reporting(0);

require_once './cfg/config.php';
require_once './inc/mod_db.php';
require_once './inc/mod_parser.php';
require_once './inc/mod_output.php';
require_once './inc/mod_log.php';

// db connection
$db_err = '';
if (!dbInit($db_err)) { die("dbe: {$db_err}"); }

// try to parse input data
$parse_error = '';
if (!inpCheckParse($parse_error)) { logSaveQuery($parse_error); outReturnRandom(); exit; }

?>