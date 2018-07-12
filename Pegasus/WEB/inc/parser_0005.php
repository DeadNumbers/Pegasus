<?php
/*
    parser_0005.php

 */

define('sizeof_LPR_RESULT', 2+4);

/* 
    main enter function. Returns FALSE in case of any errors
    Params passed:
    $m_id - numeric id identifying particular machine
    $mod_data - binary chunk to be parsed by this module
    $error - buffer to contain any error for logging in case of parse failure
 */ 
function Parser_id0005($m_id, $mod_data, &$error)
{
    global $g_dblink;
    
    // only one item assumed to be present for this type
    $item = unpack("vwResultCode/VdwLastError", $mod_data);

    
    if (!mysqli_query($g_dblink, "INSERT INTO `lp_last_results` (`id`, `stamp`, `res`, `le`) VALUES ({$m_id}, NOW(), {$item['wResultCode']}, {$item['dwLastError']})
                                  ON DUPLICATE KEY UPDATE `res`={$item['wResultCode']}, `le`={$item['dwLastError']};")) { $error = __FUNCTION__."(".__LINE__."): query failed: ".mysqli_error($g_dblink); return FALSE; }
    
    // all ok if got here 
    return TRUE;
}
?>