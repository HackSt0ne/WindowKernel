#include <ntifs.h>
#include "Memory.h"

VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
    KdPrint(("DriverUnload"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pRegPath)
{
   // KdBreakPoint();
    KdPrint(("DriverEntry"));
    NTSTATUS lStatus = STATUS_SUCCESS;
    pDriver->DriverUnload = DriverUnload;

    ULONG64 uBaseAddr = AllocateMemoryExecutable(3228, PAGE_SIZE * 3);
    //if (uBaseAddr)
    //{
    //    DbgPrint("[dbg], %p\r\n", uBaseAddr);
    //    FreeMemory(3228, uBaseAddr, PAGE_SIZE*3);
    //}

    return lStatus;
}
