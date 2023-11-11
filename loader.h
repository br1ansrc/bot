#ifndef _LOADER_H_
#define _LOADER_H_

#include <windows.h>
#include <winnt.h>
#include <winternl.h>
#include <lmserver.h>
#include <lmerr.h>
#include <lmapibuf.h>
#include <shlwapi.h>
#include <stdlib.h>
#include <strsafe.h>
#include "typedef.h"
#include "config.h"

#define __MODULE__ "LOADER"

typedef HMODULE (WINAPI *func_LoadLibrary)(LPCSTR);
typedef FARPROC (WINAPI *func_GetProcAddress)(HMODULE, LPCSTR);

typedef UINT (WINAPI *func_nvmlInit)();
typedef UINT (WINAPI *func_nvmlDeviceGetCount)(PUINT);

extern DWORD dwID;

#endif /* !_LOADER_H_ */