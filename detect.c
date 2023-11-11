#include "detect.h"


BOOL IsOnVirtualMachine()
{
    HRESULT hr = S_FALSE;
    VARIANT var1;
    VARIANT var2;
    IWbemLocator *pLocator = NULL;
    IWbemServices *pNamespace = NULL;
    IEnumWbemClassObject *pEnumerator = NULL;
    IWbemClassObject *pObject = NULL;
    ULONG uReturn = 0;
    BOOL bRet = FALSE;

    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    hr = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID*)&pLocator);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    hr = pLocator->lpVtbl->ConnectServer(pLocator, L"ROOT\\CIMV2", NULL, NULL, 0, NULL, 0, 0, &pNamespace);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    hr = CoSetProxyBlanket(pNamespace, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    hr = pNamespace->lpVtbl->ExecQuery(pNamespace, L"WQL", L"SELECT * FROM Win32_ComputerSystem", WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    while (pEnumerator)
    {
        hr = pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pObject, &uReturn);
        if (FAILED(hr))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
            goto cleanup;
        }

        if (uReturn == 0)
        {
            break;
        }

        hr = pObject->lpVtbl->Get(pObject, L"Manufacturer", 0, &var1, 0, 0);
        if (SUCCEEDED(hr))
        {
            if (StrStrIW(var1.bstrVal, L"VMWare") != NULL || StrStrIW(var1.bstrVal, L"Xen") != NULL || StrStrIW(var1.bstrVal, L"innotek GmbH") != NULL || StrStrIW(var1.bstrVal, L"QEMU") != NULL)
            {
                VariantClear(&var1);
                bRet = TRUE;
                goto cleanup;
            }

            VariantClear(&var1);
        }

        hr = pObject->lpVtbl->Get(pObject, L"Model", 0, &var2, 0, 0);
        if (SUCCEEDED(hr))
        {
            if (StrStrIW(var2.bstrVal, L"VirtualBox") != NULL || StrStrIW(var2.bstrVal, L"HVM domU") != NULL || StrStrIW(var2.bstrVal, L"VMWare") != NULL)
            {
                VariantClear(&var2);
                bRet = TRUE;
                goto cleanup;
            }

            VariantClear(&var2);
        }

        if (pObject != NULL)
        {
            pObject->lpVtbl->Release(pObject);
            pObject = NULL;
        }
    }

    if (pEnumerator != NULL)
    {
        pEnumerator->lpVtbl->Release(pEnumerator);
        pEnumerator = NULL;
    }

    hr = pNamespace->lpVtbl->ExecQuery(pNamespace, L"WQL", L"SELECT * FROM Win32_BIOS", WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    if (FAILED(hr))
    {
        TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
        goto cleanup;
    }

    while (pEnumerator)
    {
        hr = pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pObject, &uReturn);
        if (FAILED(hr))
        {
            TELEMETRY(dwID, __VERSION__,  __LINE__, hr, __MODULE__, __FILE__);
            goto cleanup;
        }

        if (uReturn == 0)
        {
            break;
        }

        hr = pObject->lpVtbl->Get(pObject, L"SerialNumber", 0, &var1, 0, 0);
        if (SUCCEEDED(hr))
        {
            if (StrStrIW(var1.bstrVal, L"VMWare") != NULL || StrStrIW(var1.bstrVal, L"Xen") != NULL || StrStrIW(var1.bstrVal, L"Virtual") != NULL || StrStrIW(var1.bstrVal, L"A M I") != NULL)
            {
                VariantClear(&var1);
                bRet = TRUE;
                goto cleanup;
            }

            VariantClear(&var1);
        }

        if (pObject != NULL)
        {
            pObject->lpVtbl->Release(pObject);
            pObject = NULL;
        }
    }

cleanup:
    if (pLocator != NULL) pLocator->lpVtbl->Release(pLocator);
    if (pNamespace != NULL) pNamespace->lpVtbl->Release(pNamespace);
    if (pEnumerator != NULL) pEnumerator->lpVtbl->Release(pEnumerator);
    if (pObject != NULL) pObject->lpVtbl->Release(pObject);
    CoUninitialize();

    return bRet;
}