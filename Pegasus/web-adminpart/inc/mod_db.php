<?php
/*
	mod_db.php
*/

require_once './cfg/config.php';

$g_dblink = 0;	// global db connection handle

function dbInit(&$resulting_error)
{	global 	$g_dblink, $g_db;

	// check if already inited
	if ($g_dblink) { return TRUE; }

    if (!($g_dblink=mysqli_connect($g_db['host'], $g_db['user'], $g_db['password'], $g_db['db']))) { $resulting_error = mysqli_error(); return FALSE; }

    mysqli_query($g_dblink, "SET NAMES utf8");

	return TRUE;
}

?>