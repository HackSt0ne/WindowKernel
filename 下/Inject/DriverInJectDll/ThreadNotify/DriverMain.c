#include <ntifs.h>

VOID NotifyFunc(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    )
{
    if (Create)
    {
        DbgPrintEx(77, 0, "ProcessId: %lld, ThreadId: %lld\r\n", ProcessId, ThreadId);
    }
}


VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
    DbgPrintEx(77, 0, "DriverUnload\r\n");
    PsRemoveCreateThreadNotifyRoutine(NotifyFunc);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{
    DbgPrintEx(77, 0, "DriverEntry\r\n");
    pDriver->DriverUnload = DriverUnload;

    PsSetCreateThreadNotifyRoutine(NotifyFunc);

    return STATUS_SUCCESS;
}