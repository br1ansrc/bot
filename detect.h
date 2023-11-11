#ifndef _DETECT_H_
#define _DETECT_H_

#include <windows.h>
#include <shlwapi.h>
#include <wbemidl.h>
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

BOOL IsOnVirtualMachine();

#endif /* !_DETECT_H_ */