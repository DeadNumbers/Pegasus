<?php
/*
	mod_output.php
*/


/*
  	Returns a buffer with random data
*/
function outReturnRandom()
{
 	$iLen = mt_rand(500, 70000);

 	while ($iLen) {
 		$iLen--;
 	}

 	echo $res;
}

?>