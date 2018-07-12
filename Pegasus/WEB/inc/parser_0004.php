<?php
/*
    parser_0004.php

 */

require_once 'mod_parser.php';


/* 
    main enter function. Returns FALSE in case of any errors
    Params passed:
    $m_id - numeric id identifying particular machine
    $mod_data - binary chunk to be parsed by this module
    $error - buffer to contain any error for logging in case of parse failure
 *  $answer - SPECIAL CASE, only for this module - resulting binary data to be returned to caller
*/ 
function Parser_id0004($m_id, $mod_data, &$error, &$answer)
{
    global $g_dblink;
    
    // for this particular chunk type need to go deeper with recursion
    // resulting binanswer
    $answer = '';

    if (!inpCheckParseStream($mod_data, $error, $answer)) { $error .= "mod_id 4: inpCheckParseStream() failed"; return FALSE; }

    
    // all ok if got here 
    return TRUE;
}

?>