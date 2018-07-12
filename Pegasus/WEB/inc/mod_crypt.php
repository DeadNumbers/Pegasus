<?php
/*
    mod_crypt.php 
*/

function cryptGenPwd()
{
    global $g_k;
    
    $pwd = '';
    
    $mask = ~( 0xFFFFFFFF << 16);   // wipe sign extension
    
    $k = unpack('Nm_w/Nm_z', pack("H*", $g_k));
    $len = 164;
    
    // signed int -> unsigned
    $k['m_w'] = (float)sprintf('%u', $k['m_w']);
    $k['m_z'] = (float)sprintf('%u', $k['m_z']);
    
    //echo "k={$g_k} w=".bin2hex(pack('V', $k['m_w']))." ({$k['m_w']}) z=".bin2hex(pack('V', $k['m_z']))." ({$k['m_z']})\n";
    
    while ($len) {
    
        //echo "i={$len} a=".strval(($k['m_w'] & 65535))." b=".strval(36969 * ($k['m_w'] & 65535))." c=".strval((($k['m_w'] >> 16) & $mask))." ";
        
        $k['m_z'] = 36969 * ($k['m_z'] & 65535) + (($k['m_z'] >> 16) & $mask);  
        $k['m_w'] = 18000 * ($k['m_w'] & 65535) + (($k['m_w'] >> 16) & $mask);  
        
        $val = (($k['m_z'] << 16) + $k['m_w']) & 0xFF;
        
        $pwd .= chr($val);
        //echo "i={$len} v={$val} w=".bin2hex(pack('V', $k['m_w']))." ({$k['m_w']}) z=".bin2hex(pack('V', $k['m_z']))." ({$k['m_z']})\n";
        
        $len--;
    }
    
    
    return sha1($pwd, TRUE);
}



function cryptDecrypt($data)
{
    return @openssl_decrypt($data, 'des', cryptGenPwd(), 1);
}



function cryptEncrypt($data)
{
    return @openssl_encrypt($data, 'des', cryptGenPwd(), 1);
}

?>