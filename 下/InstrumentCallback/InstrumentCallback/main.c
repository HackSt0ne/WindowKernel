#include <ntifs.h>

#include "InstrumentHook.h"

VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
    DbgPrintEx(77, 0, "DriverUnload\r\n");
    UnSetInstrumentHook(1108);
}

UCHAR pBuff[] = { 0x90, 0x90, 0xcc , 0x41, 0xff, 0xe2 };

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{
    DbgPrintEx(77, 0, "DriverEntry\r\n");
    pDriver->DriverUnload = DriverUnload;

    DbgBreakPoint();
   
    SetInstrumentHook(552, pBuff, sizeof(pBuff));
    
    return STATUS_SUCCESS;

}