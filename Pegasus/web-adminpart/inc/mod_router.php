<?php
/*
	mod_router.php
*/

require_once './cfg/config.php';


function rrNotFound()
{	header($_SERVER["SERVER_PROTOCOL"]." 404 Not Found");
	exit;
}


/*
  	checks for a file in a res folder and returns it
*/
function rrRouteResource($rContext)
{
	$res = './res/'.$rContext['basename'];
	if (!file_exists($res)) { rrNotFound(); exit; }

	// file found ok, send it
	$types = array(0 => 'text/html',
				   'js' => 'text/javascript'

				   );
 	header('Content-type: '.$types[$rContext['extension']].'; charset=utf-8');

    echo file_get_contents($res);

}



function rrRouteScript($rContext)
{

	$res = './inc/inc_'.$rContext['filename'].'.php';
	if (!file_exists($res)) { rrNotFound(); exit; }

	// force refresh
	header('Content-type: text/html; charset=utf-8');	header( 'Expires: Sat, 26 Jul 1997 05:00:00 GMT' );
	header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s' ) . ' GMT' );
	header( 'Cache-Control: no-store, no-cache, must-revalidate' );
	header( 'Cache-Control: post-check=0, pre-check=0', false );
	header( 'Pragma: no-cache' );

	require_once $res;

}



/*
  	Parses input from rewrite engine and loads/returns correct resource
*/
function rrDoRoute()
{    // $_SERVER['REQUEST_URI'] => '/pegasus-admin/index.js?sfdfd=ddd'
	// $urlparts => Array ( [path] => /pegasus-admin/index.js [query] => sfdfd=ddd )
	$urlparts = parse_url($_SERVER['REQUEST_URI']);

	// $fileparts => Array ( [dirname] => /pegasus-admin [basename] => index.js [extension] => js [filename] => index )
	$fileparts = pathinfo($urlparts['path']);

	// form context
	$rContext = $fileparts;
	$rContext['query'] = $urlparts['query'];

    //print_r($rContext);

    // fishy params check
    if (strpos($rContext['basename'], '..')) { die("fish"); }

	// check for non-php
	if ($rContext['extension'] != 'php') { rrRouteResource($rContext); } else { rrRouteScript($rContext); }


}

?>