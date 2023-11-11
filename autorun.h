#ifndef _AUTORUN_H_
#define _AUTORUN_H_

#include <windows.h>
#include <shlwapi.h>
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

BOOL InstallSystemModeAutorun(PWCHAR pwszLauncherPath);
BOOL IsSystemModeAutorunInstalled();
BOOL UninstallSystemModeAutorun(PWCHAR pwszLauncherPath);

BOOL InstallUserModeAutorun(PWCHAR pwszLauncherPath);
BOOL IsUserModeAutorunInstalled();
BOOL UninstallUserModeAutorun(PWCHAR pwszLauncherPath);

#endif /* !_AUTORUN_H_ */