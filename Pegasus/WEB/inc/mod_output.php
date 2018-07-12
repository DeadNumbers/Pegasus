<?php
/*
	mod_output.php
*/


/*
  	Returns a buffer with random data
*/
function outReturnRandom()
{ 	$res = '';
 	$iLen = mt_rand(500, 70000);

 	while ($iLen) { 		$res .= chr(mt_rand(0, 255));
 		$iLen--;
 	}

 	echo $res;
}

?>