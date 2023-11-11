#ifndef _LAUNCHER_H_
#define _LAUNCHER_H_

#include <windows.h>
#include <winnt.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <strsafe.h>
#include "typedef.h"
#include "config.h"

#define __MODULE__ "LAUNCHER"

typedef VOID (*pCreateRemoteThread64)(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId,
    LPHANDLE hThread
);

#endif /* !_LAUNCHER_H_ */