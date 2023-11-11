#include "common.h"


LPVOID MemoryAllocate(LPVOID lpMemory, DWORD dwSize)
{
    LPVOID lpAllocate = NULL;

    if (dwSize == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        return NULL;
    }

    if (lpMemory == NULL)
    {
        lpAllocate = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
        if (lpAllocate == NULL)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }
    }
    else
    {
        lpAllocate = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lpMemory, dwSize);
        if (lpAllocate == NULL)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            HeapFree(GetProcessHeap(), 0, lpMemory);
            goto cleanup;
        }
    }

cleanup:

    return lpAllocate;
}


BOOL MemoryFree(LPVOID lpMemory)
{
    BOOL bRet = FALSE;

    if (lpMemory == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!HeapFree(GetProcessHeap(), 0, lpMemory))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    bRet = TRUE;

cleanup:

    return bRet;
}


DWORD MemorySize(LPVOID lpMemory)
{
    SIZE_T nSize = 0;
    DWORD dwRet = 0;

    if (lpMemory == NULL)
    {
        goto cleanup;
    }

    nSize = HeapSize(GetProcessHeap(), 0, lpMemory);
    if (nSize == (SIZE_T)-1)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    dwRet = nSize;

cleanup:

    return dwRet;
}


PWCHAR AsciiToUnicode(PCHAR pszString)
{
    HRESULT hr = S_OK;
    PWCHAR pwszString = NULL;
    SIZE_T nStrLen = 0;

    if (pszString == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (pszString[0] == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hr = StringCchLengthA(pszString, STRSAFE_MAX_CCH, &nStrLen);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    pwszString = MemoryAllocate(NULL, (nStrLen + 1) * sizeof(WCHAR));
    if (pwszString == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, pszString, -1, pwszString, nStrLen + 1) == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        MemoryFree(pwszString) ? pwszString = NULL : 0;
        goto cleanup;
    }

cleanup:

    return pwszString;
}


PCHAR UnicodeToAscii(PWCHAR pwszString)
{
    HRESULT hr = S_OK;
    PCHAR pszString = NULL;
    SIZE_T nStrLen = 0;

    if (pwszString == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (pwszString[0] == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hr = StringCchLengthW(pwszString, STRSAFE_MAX_CCH, &nStrLen);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    pszString = (PCHAR)MemoryAllocate(NULL, nStrLen + 1);
    if (pszString == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (WideCharToMultiByte(CP_ACP, 0, pwszString, nStrLen, pszString, nStrLen + 1, NULL, NULL) == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        MemoryFree(pszString) ? pszString = NULL : 0;
        goto cleanup;
    }

cleanup:

    return pszString;
}


DWORD GetMachineID()
{
    HKEY hKey = NULL;
    PBYTE pbMachineID = NULL;
    DWORD dwRet = 0;
    DWORD dwSize = sizeof(DWORD);
    DWORD dwMachineID = 0;
    BOOL bWOW64 = FALSE;

    dwRet = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software", 0, KEY_READ | KEY_WRITE, &hKey);
    if (dwRet != ERROR_SUCCESS)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, dwRet, __MODULE__, __FILE__);
        goto cleanup;
    }

    dwRet = RegQueryValueExW(hKey, MACHINE_ID_KEY, NULL, NULL, &dwMachineID, &dwSize);
    if (dwRet != ERROR_SUCCESS)
    {
        if (dwRet == ERROR_FILE_NOT_FOUND)
        {
            pbMachineID = GenerateRandomByte(sizeof(DWORD));
            if (pbMachineID == NULL)
            {
                TELEMETRY(dwID, __VERSION__,  __LINE__, dwRet, __MODULE__, __FILE__);
                goto cleanup;
            }

            dwRet = RegSetValueExW(hKey, MACHINE_ID_KEY, NULL, REG_DWORD, pbMachineID, MemorySize(pbMachineID));
            if (dwRet != ERROR_SUCCESS)
            {
                TELEMETRY(dwID, __VERSION__,  __LINE__, dwRet, __MODULE__, __FILE__);
                goto cleanup;
            }

            CopyMemory(&dwMachineID, pbMachineID, sizeof(dwMachineID));
        }
        else
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, dwRet, __MODULE__, __FILE__);
            goto cleanup;
        }
    }

cleanup:
    if (pbMachineID != NULL) MemoryFree(pbMachineID);
    if (hKey != NULL) RegCloseKey(hKey);

    return dwMachineID;
}


BOOL DeleteMachineID()
{
    HKEY hKey = NULL;
    DWORD dwRet = 0;
    BOOL bRet = FALSE;

    dwRet = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software", 0, KEY_SET_VALUE, &hKey);
    if (dwRet != ERROR_SUCCESS)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, dwRet, __MODULE__, __FILE__);
        goto cleanup;
    }

    dwRet = RegDeleteValueW(hKey, MACHINE_ID_KEY);
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


BOOL IsFilePE(LPVOID lpFile, DWORD dwFile, LPBOOL lpbX64)
{
    PIMAGE_DOS_HEADER pidh = NULL;
    PIMAGE_NT_HEADERS pinh = NULL;
    BOOL bRet = FALSE;

    if (lpFile == NULL || dwFile == 0 )
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    pidh = (PIMAGE_DOS_HEADER)lpFile;
    if (pidh->e_magic != IMAGE_DOS_SIGNATURE)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    pinh = (PIMAGE_NT_HEADERS)(lpFile + pidh->e_lfanew);
    if (pinh->Signature != IMAGE_NT_SIGNATURE)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (lpbX64 != NULL)
    {
        if (pinh->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            *lpbX64 = FALSE;
        }
        else if (pinh->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            *lpbX64 = TRUE;
        }
    }

    bRet = TRUE;

cleanup:

    return bRet;
}


BOOL EnablePrivilege(HANDLE hProcess, PWCHAR pwszPrivilegeType)
{
    TOKEN_PRIVILEGES tkp;
    HANDLE hToken = INVALID_HANDLE_VALUE;
    BOOL bRet = FALSE;

    if (pwszPrivilegeType == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!OpenProcessToken(hProcess != NULL ? hProcess : GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    SecureZeroMemory(&tkp, sizeof(TOKEN_PRIVILEGES));

    if (!LookupPrivilegeValueW(NULL, pwszPrivilegeType, &tkp.Privileges[0].Luid))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    bRet = TRUE;

cleanup:
    if (hToken != INVALID_HANDLE_VALUE) CloseHandle(hToken);

    return bRet;
}


BOOL IsProcessSystem(HANDLE hProcess)
{
    SID_IDENTIFIER_AUTHORITY sia = SECURITY_NT_AUTHORITY;
    HANDLE hToken = INVALID_HANDLE_VALUE;
    PSID psid = NULL;
    ULONG ulTokenUser = 0;
    BOOL bRet = FALSE;
    UCHAR ucTokenUser[sizeof(TOKEN_USER) + 8 + 4 * SID_MAX_SUB_AUTHORITIES];

    if (!OpenProcessToken(hProcess != NULL ? hProcess : GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!GetTokenInformation(hToken, TokenUser, &ucTokenUser, sizeof(ucTokenUser), &ulTokenUser))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!AllocateAndInitializeSid(&sia, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &psid))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (EqualSid(((PTOKEN_USER)ucTokenUser)->User.Sid, psid))
    {
        bRet = TRUE;
    }

cleanup:
    if (hToken != INVALID_HANDLE_VALUE) CloseHandle(hToken);
    if (psid != NULL) FreeSid(psid);

    return bRet;
}


LPVOID GetResource(HMODULE hModule, INT ID_RCDATA, PWCHAR pwszResourceType, LPDWORD lpdwResourceSize)
{
    HRSRC hPayload = NULL;
    HGLOBAL hResource = NULL;
    LPVOID lpResource = NULL;
    DWORD dwSize = 0;

    if (ID_RCDATA == 0 || pwszResourceType == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hPayload = FindResourceW(hModule != NULL ? hModule : GetModuleHandle(NULL), MAKEINTRESOURCE(ID_RCDATA), pwszResourceType);
    if (hPayload == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hResource = LoadResource(hModule != NULL ? hModule : GetModuleHandle(NULL), hPayload);
    if (hResource == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    dwSize = SizeofResource(hModule != NULL ? hModule : GetModuleHandle(NULL), hPayload);
    if (dwSize == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    lpResource = LockResource(hResource);
    if (lpResource == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (lpdwResourceSize != NULL)
    {
        *lpdwResourceSize = dwSize;
    }

cleanup:

    return lpResource;
}


LPVOID ReadFromFile(PWCHAR pwszFilePath, LPDWORD lpdwFile)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    LPVOID lpFile = NULL;
    DWORD dwFile = 0;

    if (pwszFilePath == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (pwszFilePath[0] == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hFile = CreateFileW(pwszFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    dwFile = GetFileSize(hFile, NULL);
    if (dwFile == INVALID_FILE_SIZE)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    lpFile = MemoryAllocate(NULL, dwFile);
    if (lpFile == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!ReadFile(hFile, lpFile, dwFile, &dwFile, NULL))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        MemoryFree(lpFile) ? lpFile = NULL : 0;
        goto cleanup;
    }

    if (lpdwFile != NULL)
    {
        *lpdwFile = dwFile;
    }

cleanup:
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

    return lpFile;
}


BOOL WriteToFile(PWCHAR pwszFilePath, LPVOID lpFile, DWORD dwFile)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD dwWritten = 0;
    BOOL bRet = FALSE;

    if (pwszFilePath == NULL || lpFile == NULL || dwFile == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (pwszFilePath[0] == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (GetFileAttributesW(pwszFilePath) != INVALID_FILE_ATTRIBUTES)
    {
        if (!SetFileAttributesW(pwszFilePath, FILE_ATTRIBUTE_NORMAL))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }
    }

    hFile = CreateFileW(pwszFilePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!WriteFile(hFile, lpFile, dwFile, &dwWritten, NULL))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    bRet = TRUE;

cleanup:
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

    return bRet;
}


DWORD GenerateRandomNumber(DWORD dwMin, DWORD dwMax)
{
    HCRYPTPROV hProvider = 0;
    DWORD dwRandom = 0;
    DWORD dwResult = 0;

    if (dwMin >= dwMax)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!CryptAcquireContextW(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!CryptGenRandom(hProvider, sizeof(DWORD), (PBYTE)&dwRandom))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    dwResult = (dwRandom % ((dwMax + 1) - dwMin)) + dwMin;

cleanup:
    if (hProvider != NULL) CryptReleaseContext(hProvider, 0);

    return dwResult;
}


PBYTE GenerateRandomByte(DWORD dwRandomSize)
{
    HCRYPTPROV hProvider = 0;
    PBYTE pbRandom = NULL;

    if (dwRandomSize == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!CryptAcquireContextW(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    pbRandom = MemoryAllocate(NULL, dwRandomSize);
    if (pbRandom == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!CryptGenRandom(hProvider, dwRandomSize, (PBYTE)pbRandom))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        MemoryFree(pbRandom) ? pbRandom = NULL : 0;
        goto cleanup;
    }

cleanup:
    if (hProvider != NULL) CryptReleaseContext(hProvider, 0);

    return pbRandom;
}


BOOL GenerateRandomTime(PFILETIME pft)
{
    SYSTEMTIME st;
    BOOL bRet = FALSE;

    if (pft == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    SecureZeroMemory(&st, sizeof(SYSTEMTIME));

    GetSystemTime(&st);
    st.wYear -= GenerateRandomNumber(1, 3);
    st.wMonth = GenerateRandomNumber(1, 12);
    st.wDayOfWeek = GenerateRandomNumber(0, 6);
    st.wDay = GenerateRandomNumber(1, 28);
    st.wHour = GenerateRandomNumber(0, 23);
    st.wMinute = GenerateRandomNumber(0, 59);
    st.wSecond = GenerateRandomNumber(0, 59);
    st.wMilliseconds = GenerateRandomNumber(0, 999);

    if (!SystemTimeToFileTime(&st, pft))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    bRet = TRUE;

cleanup:

    return bRet;
}


BOOL SetRandomFileTime(PWCHAR pwszFilePath)
{
    FILETIME ft;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD dwFileAttributes = INVALID_FILE_ATTRIBUTES;
    BOOL bRet = FALSE;

    if (pwszFilePath == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (pwszFilePath[0] == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    dwFileAttributes = GetFileAttributesW(pwszFilePath);
    if (dwFileAttributes == INVALID_FILE_ATTRIBUTES)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!SetFileAttributesW(pwszFilePath, FILE_ATTRIBUTE_NORMAL))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hFile = CreateFileW(pwszFilePath, FILE_WRITE_ATTRIBUTES, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    SecureZeroMemory(&ft, sizeof(FILETIME));

    if (!GenerateRandomTime(&ft))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!SetFileTime(hFile, &ft, &ft, &ft))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!SetFileAttributesW(pwszFilePath, dwFileAttributes))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    bRet = TRUE;

cleanup:
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

    return bRet;
}


BOOL EraseFile(PWCHAR pwszFilePath)
{
    DWORD dwCnt = 0;
    BOOL bRet = FALSE;

    if (pwszFilePath == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (pwszFilePath[0] == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!SetFileAttributesW(pwszFilePath, FILE_ATTRIBUTE_NORMAL))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    for (dwCnt = 0; dwCnt < 10; dwCnt++)
    {
        if (DeleteFileW(pwszFilePath))
        {
            bRet = TRUE;
            break;
        }

        Sleep(1000);
    }

cleanup:

    return bRet;
}


BOOL KillProcess(DWORD dwPID)
{
    HANDLE hProcess = NULL;
    DWORD dwExitCode = 0;
    BOOL bRet = FALSE;

    if (dwPID == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hProcess = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, dwPID);
    if (hProcess == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!GetExitCodeProcess(hProcess, &dwExitCode))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (dwExitCode == STILL_ACTIVE)
    {
        if (!TerminateProcess(hProcess, 0))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }
    }

    bRet = TRUE;

cleanup:
    if (hProcess != NULL) CloseHandle(hProcess);

    return bRet;
}