 <?php
/*
	config.php
*/

$g_db = array(
	'host' 		=> 'localhost',
	'db' 		=> 'pegasus',
	'user' 		=> 'root',
	'password' 	=> '12345'
);

// testpass
$g_auth_data = array(
  	'user' => 'root',
    'pass' => 'testpass'
);

// ips to exclude from geo2ip queries
$g_exclude_ips = array(
	'127.0.0.1',
    '127.0.0.1'
);

?>