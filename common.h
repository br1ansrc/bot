#ifndef _COMMON_H_
#define _COMMON_H_

#include <windows.h>
#include <shlwapi.h>
#include <iphlpapi.h>
#include <combaseapi.h>
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

extern DWORD dwID;

LPVOID MemoryAllocate(LPVOID lpMemory, DWORD dwSize);
BOOL MemoryFree(LPVOID lpMemory);
DWORD MemorySize(LPVOID lpMemory);

PWCHAR AsciiToUnicode(PCHAR pszString);
PCHAR UnicodeToAscii(PWCHAR pwszString);

DWORD GetMachineID();
BOOL DeleteMachineID();
BOOL IsFilePE(LPVOID lpFile, DWORD dwFile, LPBOOL lpbX64);
BOOL EnablePrivilege(HANDLE hProcess, PWCHAR pwszPrivilegeType);
BOOL IsProcessSystem(HANDLE hProcess);
LPVOID GetResource(HMODULE hModule, INT ID_RCDATA, PWCHAR pwszResourceType, LPDWORD lpdwResourceSize);

LPVOID ReadFromFile(PWCHAR pwszFilePath, LPDWORD lpdwFile);
BOOL WriteToFile(PWCHAR pwszFilePath, LPVOID lpFile, DWORD dwFile);

DWORD GenerateRandomNumber(DWORD dwMin, DWORD dwMax);
PBYTE GenerateRandomByte(DWORD dwRandomSize);

BOOL GenerateRandomTime(PFILETIME pft);
BOOL SetRandomFileTime(PWCHAR pwszFilePath);

BOOL EraseFile(PWCHAR pwszFilePath);
BOOL KillProcess(DWORD dwPID);

#endif /* !_COMMON_H_ */