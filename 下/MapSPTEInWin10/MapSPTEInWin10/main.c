#include <ntifs.h>

VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
    DbgPrintEx(77, 0, "DriverUnload\r\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{
    DbgPrintEx(77, 0, "DriverEntry\r\n");
    pDriver->DriverUnload = DriverUnload;

    DbgBreakPoint();
    //在win7下可以直接这样来映射一个系统pte的物理地址到另一个虚拟地址
    //但是在win10下不行
    //PHYSICAL_ADDRESS addr = { 0 };
    //addr.QuadPart = 0x000000020b4f8000;//system进程的cr3
    //PVOID pMem = MmMapIoSpace(addr, PAGE_SIZE, MmCached);
    
    //win10之后要这样做
    UNICODE_STRING uDeviceName = { 0 };
    RtlInitUnicodeString(&uDeviceName, L"\\Device\\PhysicalMemory");
    OBJECT_ATTRIBUTES obj = { 0 };
    InitializeObjectAttributes(&obj, &uDeviceName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    
    HANDLE SectionHandle = NULL;
    NTSTATUS lStatus = ZwOpenSection(&SectionHandle, SECTION_ALL_ACCESS, &obj);
    if (NT_SUCCESS(lStatus))
    {
        PVOID BaseAddress = NULL;
        LARGE_INTEGER SectionOffset = { 0 };
        SectionOffset.QuadPart = 0x00000000001ad000;
        SIZE_T ViewSize = PAGE_SIZE;
        lStatus = ZwMapViewOfSection(SectionHandle, NtCurrentProcess(), &BaseAddress, 0, PAGE_SIZE, &SectionOffset, &ViewSize,
            ViewShare, MEM_TOP_DOWN, PAGE_READWRITE);
        
        if (NT_SUCCESS(lStatus))
        {
            ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
        }
    }
    return STATUS_SUCCESS;
}