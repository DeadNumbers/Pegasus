<?php
/*
	mod_auth.php
	digest auth
*/

require_once './cfg/config.php';


function DigestAuthForm($realm)
{    header('HTTP/1.1 401 Unauthorized');
    header('WWW-Authenticate: Digest realm="'.$realm.'",qop="auth",nonce="'.uniqid().'",opaque="'.md5($realm).'"');

    echo 'Auth needed';

	exit;
}

// function to parse the http auth header
function http_digest_parse($txt)
{
    // protect against missing data
    $needed_parts = array('nonce'=>1, 'nc'=>1, 'cnonce'=>1, 'qop'=>1, 'username'=>1, 'uri'=>1, 'response'=>1);
    $data = array();
    $keys = implode('|', array_keys($needed_parts));

    preg_match_all('@(' . $keys . ')=(?:([\'"])([^\2]+?)\2|([^\s,]+))@', $txt, $matches, PREG_SET_ORDER);

    foreach ($matches as $m) {
        $data[$m[1]] = $m[3] ? $m[3] : $m[4];
        unset($needed_parts[$m[1]]);
    }

    return $needed_parts ? false : $data;
}



function lgDoCheckAuth()
{  	global $g_auth_data;

  	$realm = 'Restricted area';

  	// set auth
  	if ( (!@isset($g_auth_data['user'])) || (!@isset($g_auth_data['pass'])) ) { die("check auth config"); }

 	// set check
 	if (empty($_SERVER['PHP_AUTH_DIGEST'])) { DigestAuthForm($realm); }
    if (!($data = http_digest_parse($_SERVER['PHP_AUTH_DIGEST']))) { DigestAuthForm($realm); }

	// generate valid response
	$A1 = md5($g_auth_data['user'] . ':' . $realm . ':' . $g_auth_data['pass']);
	$A2 = md5($_SERVER['REQUEST_METHOD'].':'.$data['uri']);
	$valid_response = md5($A1.':'.$data['nonce'].':'.$data['nc'].':'.$data['cnonce'].':'.$data['qop'].':'.$A2);

	if ($data['response'] != $valid_response) { DigestAuthForm($realm); }


}

?>