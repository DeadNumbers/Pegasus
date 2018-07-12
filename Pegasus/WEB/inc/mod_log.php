<?php
/*
	mod_log.php
*/

require_once './cfg/config.php';
require_once './inc/mod_db.php';

// for nginx
if (!function_exists('getallheaders'))
{
    function getallheaders()
    {
           $headers = '';
       foreach ($_SERVER as $name => $value)
       {
           if (substr($name, 0, 5) == 'HTTP_')
           {
               $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
           }
       }
       return $headers;
    }
}

/*
  	Saves unparsed query information to db
*/
function logSaveQuery($parse_error)
{
	global $g_dblink;

	$log = array_merge(
		array(
		'ERR' => $parse_error,
     	'Method' => $_SERVER['REQUEST_METHOD'],
     	'Uri' => $_SERVER['REQUEST_URI'],
     	'Remote-Address' => $_SERVER['REMOTE_ADDR']
		),
		getallheaders()
	);

	$enc_log = mysqli_real_escape_string($g_dblink, json_encode($log));

 	mysqli_query($g_dblink, "INSERT INTO `q_log` (`stamp`, `log_json`) VALUES (NOW(), '{$enc_log}')");

}

?>