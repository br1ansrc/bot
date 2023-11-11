#ifndef _TYPEDEF_H_
#define _TYPEDEF_H_

#define ID_MODULE32 1
#define ID_MODULE64 2

#define BOT_COMMAND_EXECUTE 1
#define BOT_COMMAND_UPDATE 2
#define BOT_COMMAND_UNINSTALL 3
#define BOT_COMMAND_PLUGIN_START 4
#define BOT_COMMAND_PLUGIN_STOP 5
#define BOT_COMMAND_PLUGIN_UPDATE 6
#define BOT_COMMAND_PLUGIN_DELETE 7


#define MAGIC_BOT_REQUEST 0x718295AA
typedef struct _BOT_REQUEST
{
    DWORD dwMagic;
    DWORD dwID;
    DWORD dwNAT;
    DWORD dwDomain;
    DWORD dwUptime;
    DWORD dwLastInput;
    DWORD dwOS;
    DWORD dwRights;
    DWORD dwCapacity;
    DWORD dwProcNumber;
    DWORD dwProc;
    DWORD dwRAM;
    DWORD dwGPU;
    DWORD dwVersion;
    DWORD dwTask;
    CHAR szGroup[16];
} BOT_REQUEST, *PBOT_REQUEST;

#define MAGIC_BOT_RESPONSE 0x516E2438
typedef struct _BOT_RESPONSE
{
    DWORD dwMagic;
    DWORD dwTask;
    DWORD dwCommand;
    CHAR szFile[MAX_PATH];
} BOT_RESPONSE, *PBOT_RESPONSE;



#define MAGIC_FILE_REQUEST 0x6E0A4688
typedef struct _FILE_REQUEST
{
    DWORD dwMagic;
    CHAR szFileName[MAX_PATH];
} FILE_REQUEST, *PFILE_REQUEST;

#define MAGIC_FILE_RESPONSE 0x52D78B41
typedef struct _FILE_RESPONSE
{
    DWORD dwMagic;
    DWORD dwSize;
    DWORD dwCRC32;
} FILE_RESPONSE, *PFILE_RESPONSE;



#define MAGIC_TELEMETRY_REQUEST 0x286AE954
typedef struct _TELEMETRY_REQUEST
{
    DWORD dwMagic;
    DWORD dwID;
    DWORD dwVersion;
    DWORD dwString;
    DWORD dwError;
    CHAR szModule[MAX_PATH];
    CHAR szFile[MAX_PATH];
} TELEMETRY_REQUEST, *PTELEMETRY_REQUEST;

#define MAGIC_TELEMETRY_RESPONSE 0xF9A655ED
typedef struct _TELEMETRY_RESPONSE
{
    DWORD dwMagic;
} TELEMETRY_RESPONSE, *PTELEMETRY_RESPONSE;


typedef struct _BOT_INFO32
{
    DWORD dwID;
    DWORD dwLauncherPID;
    DWORD dwLoaderSize;
    DWORD dwLauncherSize;
    LPVOID lpLoaderBase;
    LPVOID lpLauncherBase;
    WCHAR wszLauncherPath[MAX_PATH];
} BOT_INFO32, *PBOT_INFO32;

typedef struct _BOT_INFO64
{
    DWORD dwID;
    DWORD dwLauncherPID;
    DWORD dwLoaderSize;
    DWORD dwLauncherSize;
    UINT64 lpLoaderBase;
    UINT64 lpLauncherBase;
    WCHAR wszLauncherPath[MAX_PATH];
} BOT_INFO64, *PBOT_INFO64;

#endif /* !_TYPEDEF_H_ */