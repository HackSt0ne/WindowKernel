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
    //��win7�¿���ֱ��������ӳ��һ��ϵͳpte�������ַ����һ�������ַ
    //������win10�²���
    //PHYSICAL_ADDRESS addr = { 0 };
    //addr.QuadPart = 0x000000020b4f8000;//system���̵�cr3
    //PVOID pMem = MmMapIoSpace(addr, PAGE_SIZE, MmCached);
    
    //win10֮��Ҫ������
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