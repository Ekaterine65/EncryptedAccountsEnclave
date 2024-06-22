#define WIN32_LEAN_AND_MEAN             // Исключите редко используемые компоненты из заголовков Windows
// Файлы заголовков Windows
#include <windows.h>
#include <stdio.h>

/* 1. специфичные заголовки для использования анклава */
#include "sgx_urts.h" // вместо #include <string.h>
#include "sgx_tseal.h"
#include "Enclave_u.h"
#include "Header.h"
#define ENCLAVE_FILE L"Enclave.signed.dll"

sgx_enclave_id_t eid;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        case DLL_THREAD_ATTACH: {
            sgx_status_t ret = SGX_SUCCESS;
            sgx_launch_token_t token = { 0 };
            int updated = 0;

            const wchar_t libname[] = ENCLAVE_FILE; // L"Enclave.signed.dll";

            ret = sgx_create_enclave(libname, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
            if (ret != SGX_SUCCESS) {
                printf("App: error %#x, failed to create enclave.\n", ret);
                return -1;
            }
            break;
        }
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH: {
            if (SGX_SUCCESS != sgx_destroy_enclave(eid))
                return -1;
            break;
        }
    }
    return TRUE;
}

void accessPersonalData(
    char* outbuf,		// ВЫХОДНОЙ параметр
    const size_t len,	// максимальная длина буфера
    const size_t i)		// номер элемента в массиве
{
    accessPD(eid, outbuf, len, i);
}

void setPersonalData(
    char* inbuf,
    const size_t len,
    const size_t i) 
{
    setPD(eid, inbuf, len, i);
}