#include "crypto.h"


BOOL XorData(LPDWORD lpData, DWORD dwLength, DWORD dwKEY)
{
    DWORD dwCnt = 0;

    if (lpData == NULL || dwLength == 0)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        return FALSE;
    }

    for (dwCnt = 0; dwCnt < dwLength; dwCnt++)
    {
        lpData[dwCnt] = lpData[dwCnt] ^ dwKEY;
    }

    return TRUE;
}


DWORD Generate_CRC32(PBYTE pbData, DWORD dwData)
{
    func_RtlComputeCrc32 fn_RtlComputeCrc32 = NULL;
    HMODULE hModule = NULL;
    DWORD dwHash = 0;

    if (pbData == NULL || dwData == 0)
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

    fn_RtlComputeCrc32 = (func_RtlComputeCrc32) GetProcAddress(hModule, "RtlComputeCrc32");
    if (fn_RtlComputeCrc32 == NULL)
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, GetLastError(), __MODULE__, __FILE__);
        goto cleanup;
    }

    dwHash = fn_RtlComputeCrc32(0, pbData, dwData);

cleanup:

    return dwHash;
}