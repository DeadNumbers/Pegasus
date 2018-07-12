<?php
/*
    parser_0003.php

 */

define('sizeof_CLIENT_COMMAND_RESULT', 4+2+4);

/* 
    main enter function. Returns FALSE in case of any errors
    Params passed:
    $m_id - numeric id identifying particular machine
    $mod_data - binary chunk to be parsed by this module
    $error - buffer to contain any error for logging in case of parse failure
*/ 
function Parser_id0003($m_id, $mod_data, &$error)
{
    global $g_dblink;
    
    // only one item assumed to be present for this type
    $item = unpack("VdwUniqCmdId/vwGenericResult/VdwPayloadSize", $mod_data);
    $payload = substr($mod_data, sizeof_CLIENT_COMMAND_RESULT);
    
    // basic checks
    if ($item['dwPayloadSize'] > strlen($mod_data)) { $error = __FUNCTION__."(".__LINE__."): basic len check failed, found {$item['dwPayloadSize']}, max expected ".strval(strlen($mod_data)); return FALSE; }
    if (strlen($payload) != $item['dwPayloadSize']) { $error = __FUNCTION__."(".__LINE__."): payload len mismatch, expected {$item['dwPayloadSize']}, found ".strval(strlen($payload)); return FALSE; } 
  
    $payload = mysqli_real_escape_string($g_dblink, $payload);
    
    if (!mysqli_query($g_dblink, "UPDATE `cmds_list` SET `is_done`={$item['wGenericResult']}, `answer`='{$payload}' WHERE `id`={$item['dwUniqCmdId']} LIMIT 1;")) { $error = __FUNCTION__."(".__LINE__."): query failed: ".mysqli_error($g_dblink); return FALSE; }
    
    // all ok if got here 
    return TRUE;
}

?>