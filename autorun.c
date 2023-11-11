#include "autorun.h"


BOOL InstallSystemModeAutorun(PWCHAR pwszLauncherPath)
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hService = NULL;
    BOOL bRet = FALSE;

    if (pwszLauncherPath == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (pwszLauncherPath[0] == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCM == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hService = CreateServiceW(hSCM, SERVICE_NAME, SERVICE_DISPLAY_NAME, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, pwszLauncherPath, NULL, NULL, NULL, NULL, NULL);
    if (hService == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    bRet = TRUE;

cleanup:
    if (hSCM != NULL) CloseServiceHandle(hSCM);
    if (hService != NULL) CloseServiceHandle(hService);

    return bRet;
}


BOOL IsSystemModeAutorunInstalled()
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hService = NULL;
    BOOL bRet = FALSE;

    hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCM == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hService = OpenServiceW(hSCM, SERVICE_NAME, SERVICE_QUERY_STATUS);
    if (hService == NULL)
    {
        goto cleanup;
    }

    bRet = TRUE;

cleanup:
    if (hSCM != NULL) CloseServiceHandle(hSCM);
    if (hService != NULL) CloseServiceHandle(hService);

    return bRet;
}


BOOL UninstallSystemModeAutorun(PWCHAR pwszLauncherPath)
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hService = NULL;
    LPENUM_SERVICE_STATUS_PROCESS pServiceList = NULL;
    LPQUERY_SERVICE_CONFIG pServiceConfig = NULL;
    DWORD dwByteCount = 0;
    DWORD dwEntryCount = 0;
    DWORD dwEnumHandle = 0;
    DWORD dwCnt = 0;
    BOOL bRet = FALSE;

    if (pwszLauncherPath == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (pwszLauncherPath[0] == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCM == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32_OWN_PROCESS, SERVICE_STATE_ALL, NULL, 0, &dwByteCount, &dwEntryCount, &dwEnumHandle, NULL))
    {
        if (GetLastError() != ERROR_MORE_DATA)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }
    }

    pServiceList = MemoryAllocate(NULL, dwByteCount);
    if (pServiceList == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32_OWN_PROCESS, SERVICE_STATE_ALL, pServiceList, dwByteCount, &dwByteCount, &dwEntryCount, &dwEnumHandle, NULL))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    for (dwCnt = 0; dwCnt < dwEntryCount; dwCnt++)
    {
        hService = OpenServiceW(hSCM, pServiceList[dwCnt].lpServiceName, SERVICE_QUERY_CONFIG);
        if (hService == NULL)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (!QueryServiceConfigW(hService, NULL, 0, &dwByteCount))
        {
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            {
                TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
                goto cleanup;
            }
        }

        pServiceConfig = MemoryAllocate(NULL, dwByteCount);
        if (pServiceConfig == NULL)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (!QueryServiceConfigW(hService, pServiceConfig, dwByteCount, &dwByteCount))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (StrCmpIW(pwszLauncherPath, pServiceConfig->lpBinaryPathName) == 0)
        {
            CloseServiceHandle(hService) ? hService = NULL : 0;

            hService = OpenServiceW(hSCM, pServiceList[dwCnt].lpServiceName, DELETE);
            if (hService == NULL)
            {
                TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
                goto cleanup;
            }

            if (DeleteService(hService))
            {
                bRet = TRUE;
                goto cleanup;
            }
            else
            {
                TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
                goto cleanup;
            }
        }

        MemoryFree(pServiceConfig) ? pServiceConfig = NULL : 0;
        CloseServiceHandle(hService) ? hService = NULL : 0;
    }

cleanup:
    if (pServiceList != NULL) MemoryFree(pServiceList);
    if (pServiceConfig != NULL) MemoryFree(pServiceConfig);
    if (hSCM != NULL) CloseServiceHandle(hSCM);
    if (hService != NULL) CloseServiceHandle(hService);

    return bRet;
}


BOOL InstallUserModeAutorun(PWCHAR pwszLauncherPath)
{
    HRESULT hr = S_OK;
    HKEY hKey = NULL;
    SIZE_T nStrLen = 0;
    DWORD dwRet = 0;
    BOOL bRet = FALSE;

    if (pwszLauncherPath == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (pwszLauncherPath[0] == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    dwRet = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", NULL, KEY_SET_VALUE, &hKey);
    if (dwRet != ERROR_SUCCESS)
    {
        if (dwRet == ERROR_ACCESS_DENIED)
        {
            goto cleanup;
        }

        TELEMETRY(dwID, __VERSION__,  __LINE__, dwRet, __MODULE__, __FILE__);
        goto cleanup;
    }

    hr = StringCchLengthW(pwszLauncherPath, STRSAFE_MAX_CCH, &nStrLen);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    dwRet = RegSetValueExW(hKey, REGISTRY_NAME, 0, REG_SZ, (PBYTE)pwszLauncherPath, (nStrLen + 1) * sizeof(WCHAR));
    if (dwRet != ERROR_SUCCESS)
    {
        //TELEMETRY(dwID, __VERSION__,  __LINE__, dwRet, __MODULE__, __FILE__);
        goto cleanup;
    }

    bRet = TRUE;

cleanup:
    if (hKey != NULL) RegCloseKey(hKey);

    return bRet;
}


BOOL IsUserModeAutorunInstalled()
{
    HKEY hKey = NULL;
    DWORD dwRet = 0;
    BOOL bRet = FALSE;

    dwRet = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_QUERY_VALUE, &hKey);
    if (dwRet != ERROR_SUCCESS)
    {
        if (dwRet == ERROR_ACCESS_DENIED)
        {
            bRet = TRUE;
            goto cleanup;
        }

        TELEMETRY(dwID, __VERSION__,  __LINE__, dwRet, __MODULE__, __FILE__);
        goto cleanup;
    }

    dwRet = RegQueryValueExW(hKey, REGISTRY_NAME, NULL, NULL, NULL, NULL);
    if (dwRet != ERROR_SUCCESS)
    {
        if (dwRet == ERROR_FILE_NOT_FOUND)
        {
            goto cleanup;
        }

        TELEMETRY(dwID, __VERSION__,  __LINE__, dwRet, __MODULE__, __FILE__);
        goto cleanup;
    }

    bRet = TRUE;

cleanup:
    if (hKey != NULL) RegCloseKey(hKey);

    return bRet;
}


BOOL UninstallUserModeAutorun(PWCHAR pwszLauncherPath)
{
    HKEY hKey = NULL;
    DWORD dwRet = 0;
    BOOL bRet = FALSE;

    if (pwszLauncherPath == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (pwszLauncherPath[0] == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    dwRet = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey);
    if (dwRet != ERROR_SUCCESS)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, dwRet, __MODULE__, __FILE__);
        goto cleanup;
    }

    dwRet = RegDeleteValueW(hKey, REGISTRY_NAME);
    if (dwRet != ERROR_SUCCESS)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, dwRet, __MODULE__, __FILE__);
        goto cleanup;
    }

    bRet = TRUE;

cleanup:
    if (hKey != NULL) RegCloseKey(hKey);

    return bRet;
}