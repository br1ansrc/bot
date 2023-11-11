#ifndef _TELEMETRY_H_
#define _TELEMETRY_H_

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shlwapi.h>
#include <stdlib.h>
#include <strsafe.h>
#include "config.h"
#include "typedef.h"

#define BOT_RECV_TIMEOUT 10*1000
#define CP_RECV_TIMEOUT 10*1000

#define CP_RESPONSE "TELEMETRY RESPONSE"

typedef struct _CLIENT
{
    SOCKADDR_STORAGE ss;
    SOCKET hSock;
} CLIENT, *PCLIENT;

#endif /* !_TELEMETRY_H_ */