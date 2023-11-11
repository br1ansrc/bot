#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <windows.h>
#include <stdlib.h>
#include <strsafe.h>
#include "config.h"

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

typedef DWORD (WINAPI *func_RtlComputeCrc32)(DWORD, PBYTE, INT);

extern DWORD dwID;

BOOL XorData(LPDWORD lpData, DWORD dwLength, DWORD dwKEY);
DWORD Generate_CRC32(PBYTE pbData, DWORD dwData);

#endif /* !_CRYPTO_H_ */