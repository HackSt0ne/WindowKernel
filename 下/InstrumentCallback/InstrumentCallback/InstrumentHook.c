#include "InstrumentHook.h"

NTSTATUS ZwSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);

NTSTATUS SetInstrumentHook(HANDLE hPid, PUCHAR pHookFunc, ULONG64 uSize)
{
    DbgBreakPoint();
    PEPROCESS pEprocess = NULL;
    PUCHAR pBuff = NULL;
    KAPC_STATE apc_state = { 0 };
    PACCESS_TOKEN pToken = NULL;
    BOOLEAN bIsAttched = FALSE;
    NTSTATUS lStatus = STATUS_SUCCESS;

    do
    {
        lStatus = PsLookupProcessByProcessId(hPid, &pEprocess);
        if (!NT_SUCCESS(lStatus))
        {
            break;
        }

        if (STATUS_PENDING != PsGetProcessExitStatus(pEprocess))
        {
            lStatus = STATUS_UNSUCCESSFUL;
            break;
        }

        if (pHookFunc)
        {
            pBuff = ExAllocatePool(PagedPool, PAGE_SIZE);
            if (!pBuff)
            {
                lStatus = STATUS_UNSUCCESSFUL;
                break;
            }
            memset(pBuff, 0, PAGE_SIZE);
            memcpy(pBuff, pHookFunc, uSize);
        }

        KeStackAttachProcess(pEprocess, &apc_state);
        bIsAttched = TRUE;

        PUCHAR pBaseAddress = NULL;
        SIZE_T size = PAGE_SIZE;
        lStatus = ZwAllocateVirtualMemory(NtCurrentProcess(), &pBaseAddress, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!pBaseAddress)
        {
            break;
        }
        memset(pBaseAddress, 0, PAGE_SIZE);
        memcpy(pBaseAddress, pBuff, uSize);

        pToken = PsReferencePrimaryToken(pEprocess);
        if (!pToken)
        {
           lStatus = STATUS_UNSUCCESSFUL;
           break;
        }

        PULONG64 pPrivileges = (PULONG64)((PUCHAR)pToken + 0x40);
        if (!pPrivileges)
        {
            lStatus = STATUS_UNSUCCESSFUL;
            break;
        }

        pPrivileges[0] |= 0x100000;
        pPrivileges[1] |= 0x100000;
        pPrivileges[2] |= 0x100000;

        lStatus = ZwSetInformationProcess(NtCurrentProcess(), ProcessInstrumentationCallback, &pBaseAddress, 8);

        if (!NT_SUCCESS(lStatus))
        {
            lStatus = STATUS_UNSUCCESSFUL;
            break;
        }

    } while (FALSE);
    if (pToken)
    {
        PsDereferencePrimaryToken(pToken);
    }
    
    if (bIsAttched)
    {
        KeUnstackDetachProcess(&apc_state);
    }
    
    if (pBuff)
    {
        ExFreePool(pBuff);
    }

    if (pEprocess)
    {
        ObDereferenceObject(pEprocess);
    }
    
    return lStatus;
}

VOID UnSetInstrumentHook(HANDLE hPid)
{
    SetInstrumentHook(hPid, 0, 8);
}