<?php
/*
    parser_0002.php
    Empty heartbeat parser

 */



/* 
    main enter function. Returns FALSE in case of any errors
    Params passed:
    $m_id - numeric id identifying particular machine
    $mod_data - binary chunk to be parsed by this module
    $error - buffer to contain any error for logging in case of parse failure
*/ 
function Parser_id0002($m_id, $mod_data, &$error)
{
    global $g_dblink;
    
    // all ok if got here 
    return TRUE;
}

?>