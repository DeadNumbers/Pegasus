/*
	LocalStorage.h
*/

#include <windows.h>

typedef enum StorageItemSourceEnum {
	SI_ERROR = 0,		// not defined source, assumed to be an error
	SI_FROM_REMOTE_CONTROL_CENTER,	// data got from remote controller server, to be sent to some machine inside of network (if node is acting as proxy for others)
	SI_FOR_REMOTE_CONTROL_CENTER,	// data to be uploaded to remote machine

	SI_MAXVALUE = 255	// max value to fit BYTE in serialized version of structure
};


// describe item from a local storage in a memory linked list
typedef struct _LOCAL_STORAGE_ITEM
{
	StorageItemSourceEnum siSource;		// type of source which created this item
	DWORD dwItemUniqId;

	LPVOID pData;	// encoded and/or packed data
	SIZE_T lDataLen;	// len of data in ^

} LOCAL_STORAGE_ITEM, *PLOCAL_STORAGE_ITEM;


VOID lsInitLocalStorage();