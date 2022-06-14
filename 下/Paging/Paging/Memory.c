#include "Memory.h"

#define PTE_BASE_WIN7 0xFFFFF68000000000ull

//0x8 bytes (sizeof)
typedef struct _MMPTE_HARDWARE
{
    ULONGLONG Valid : 1;                                                      //0x0
    ULONGLONG Dirty1 : 1;                                                     //0x0
    ULONGLONG Owner : 1;                                                      //0x0
    ULONGLONG WriteThrough : 1;                                               //0x0
    ULONGLONG CacheDisable : 1;                                               //0x0
    ULONGLONG Accessed : 1;                                                   //0x0
    ULONGLONG Dirty : 1;                                                      //0x0
    ULONGLONG LargePage : 1;                                                  //0x0
    ULONGLONG Global : 1;                                                     //0x0
    ULONGLONG CopyOnWrite : 1;                                                //0x0
    ULONGLONG Unused : 1;                                                     //0x0
    ULONGLONG Write : 1;                                                      //0x0
    ULONGLONG PageFrameNumber : 36;                                           //0x0
    ULONGLONG ReservedForHardware : 4;                                        //0x0
    ULONGLONG ReservedForSoftware : 4;                                        //0x0
    ULONGLONG WsleAge : 4;                                                    //0x0
    ULONGLONG WsleProtection : 3;                                             //0x0
    ULONGLONG NoExecute : 1;                                                  //0x0
}MMPTE_HARDWARE, *PMMPTE_HARDWARE;

ULONG64 GetPteBase()
{
    static ULONG64 u64PteBase = 0;
    if (u64PteBase)
    {
        return u64PteBase;
    }
    
    RTL_OSVERSIONINFOEXW version = { 0 };
    RtlGetVersion(&version);

    if (7600 == version.dwBuildNumber || 7601 == version.dwBuildNumber)
    {
        //win7
        u64PteBase = PTE_BASE_WIN7;
    }
    else if (version.dwBuildNumber > 14393)
    {
        //大于1607，手动获取PTE
        UNICODE_STRING unFuncName = { 0 };
        RtlInitUnicodeString(&unFuncName, L"MmGetVirtualForPhysical");
        PUCHAR pFuncAddr = MmGetSystemRoutineAddress(&unFuncName);
        if (!pFuncAddr)
        {
            u64PteBase = 0;
        }
        else
        {
            u64PteBase = *(PULONG64)(pFuncAddr + 0x22);
        }
    }
    else
    {
        //win7~1607
        u64PteBase = PTE_BASE_WIN7;
    }

    return u64PteBase;
}

ULONG64 GetPte(ULONG64 u64VirtualAddr)
{
    ULONG64 u64PteBase = GetPteBase();
    return ((u64VirtualAddr >> 9) & 0x7FFFFFFFF8) + u64PteBase;
}

ULONG64 GetPde(ULONG64 u64VirtualAddr)
{
    ULONG64 u64PteBase = GetPteBase();
    ULONG64 u64Pte = GetPte(u64VirtualAddr);
    return ((u64Pte >> 9) & 0x7FFFFFFFF8) + u64PteBase;
}

ULONG64 GetPdpte(ULONG64 u64VirtualAddr)
{
    ULONG64 u64PteBase = GetPteBase();
    ULONG64 u64Pde = GetPde(u64VirtualAddr);
    return ((u64Pde >> 9) & 0x7FFFFFFFF8) + u64PteBase;
}

ULONG64 GetPxe(u64VirtuallAddr)
{
    ULONG64 u64PteBase = GetPteBase();
    ULONG64 u64Pdpte = GetPdpte(u64VirtuallAddr);
    return ((u64Pdpte >> 9) & 0x7FFFFFFFF8) + u64PteBase;
}

BOOLEAN SetMemoryExcutable(ULONG64 uStartAddr, ULONG64 uSize)
{
    BOOLEAN bRet = FALSE;
    ULONG64 uStart = uStartAddr & (~0xFFF);
    ULONG64 uEnd = (uStartAddr + uSize) & (~0xFFF);

    for (; uStart <= uEnd; uStart += PAGE_SIZE)
    {
        DbgPrint("addr: %p\r\n", uStart);
        PMMPTE_HARDWARE pPte = GetPte(uStart);
        PMMPTE_HARDWARE pPde = GetPde(uStart);
        //设置nx位和w位
        if (MmIsAddressValid(pPte) && pPte->Valid)
        {
            DbgPrint("pte: %p\r\n", pPte);
            pPte->Write = 1;
            pPte->NoExecute = 0;
            bRet = TRUE;
        }

        if (MmIsAddressValid(pPde) && pPde->Valid)
        {
            DbgPrint("Pde: %p\r\n", pPde);
            pPde->Write = 1;
            pPde->NoExecute = 0;
            bRet = TRUE;
        }
    }
    return bRet;
}

ULONG64 AllocateMemoryExecutable(HANDLE hPid, ULONG64 u64Size)
{
    if (0 == u64Size)
    {
        return NULL;
    }

    PEPROCESS pProcess = NULL;
    NTSTATUS lStatus =  PsLookupProcessByProcessId(hPid, &pProcess);
    if (!NT_SUCCESS(lStatus))
    {
        return NULL;
    }

    if (STATUS_PENDING != PsGetProcessExitStatus(pProcess))
    {
        //进程已经退出
        ObDereferenceObject(pProcess);
        return NULL;
    }

    KAPC_STATE apc_state = { 0 };
    PVOID pBaseAddr = NULL;
    KeStackAttachProcess(pProcess, &apc_state);

    //先附加然后在申请内存不会触发进程回调
    lStatus = ZwAllocateVirtualMemory(NtCurrentProcess(), &pBaseAddr, 0, &u64Size, MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(lStatus))
    {
        DbgPrintEx(77, 0, "ZwAllocateVirtualMemory Failed: %x\r\n", lStatus);
    }else
    {
        memset(pBaseAddr, 0, u64Size);
        if (!SetMemoryExcutable(pBaseAddr, u64Size))
        {
            DbgPrintEx(77, 0, "SetMemoryExcutable Failed\r\n");
        }
    }

    KeUnstackDetachProcess(&apc_state);
    
    ObDereferenceObject(pProcess);
    return pBaseAddr;
}

NTSTATUS FreeMemory(HANDLE hPid, ULONG64 u64BaseAddr, ULONG64 u64Size)
{
    PEPROCESS pProcess = NULL;
    NTSTATUS lStatus = PsLookupProcessByProcessId(hPid, &pProcess);
    if (!NT_SUCCESS(lStatus))
    {
        return lStatus;
    }

    if (STATUS_PENDING != PsGetProcessExitStatus(pProcess))
    {
        //进程已经退出
        ObDereferenceObject(pProcess);
        return STATUS_UNSUCCESSFUL;
    }

    KAPC_STATE apc_state = { 0 };
    PVOID pBaseAddr = NULL;
    KeStackAttachProcess(pProcess, &apc_state);

    if (pBaseAddr)
    {
        lStatus = ZwFreeVirtualMemory(NtCurrentProcess(), &pBaseAddr, &u64Size, MEM_RELEASE);
    }

    KeUnstackDetachProcess(&apc_state);
    ObDereferenceObject(pProcess);
    return lStatus;
}