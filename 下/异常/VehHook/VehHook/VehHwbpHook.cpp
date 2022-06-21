#include "VehHwbpHook.h"
#include "insn_len.h"

#include <vector>

typedef struct _HOOK_INFO
{
    ULONG_PTR upHookAddr;
    ULONG_PTR upTargetAddr;
    ULONG_PTR upDispatchCall;//需要释放
    UCHAR JmpOverCode[0x20];//设置硬件断点之后，触发到异常劫持到shellcode，返回的时候需要跳过触发硬件断点的那一条指令
    ULONG uJmpOverLen;
    ULONG uDrIndex;
}HOOK_INFO, *PHOOK_INFO;

std::vector<HOOK_INFO> g_vecHookInfos;

LONG NTAPI VehHandler1(
    struct _EXCEPTION_POINTERS *ExceptionInfo
)
{
    //printf("ExceptionCode:%x\r\n", ExceptionInfo->ExceptionRecord->ExceptionCode);
    //printf("ExceptionAddress:%x\r\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);
    //printf("ExceptionFlags:%x\r\n", ExceptionInfo->ExceptionRecord->ExceptionFlags);
    //printf("NumberParameters:%x\r\n", ExceptionInfo->ExceptionRecord->NumberParameters);
    //printf("Dr0:%x\r\n", ExceptionInfo->ContextRecord->Dr0);
    //printf("Dr7:%x\r\n", ExceptionInfo->ContextRecord->Dr7);
    //MessageBoxA(0,0,0,0);
    if (EXCEPTION_SINGLE_STEP == ExceptionInfo->ExceptionRecord->ExceptionCode)
    {
        for (auto& item : g_vecHookInfos)
        {
            printf("upHookAddr = %x\r\n", item.upHookAddr);
            if ((ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress == item.upHookAddr)
            {
               
                ExceptionInfo->ContextRecord->Eip = item.upDispatchCall;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

ULONG GetEmptyDr(HANDLE hThread)
{
    ULONG uDrIndex = -1;
    CONTEXT Context = { 0 };
    GetThreadContext(hThread, &Context);
    if (!Context.Dr0)
    {
        uDrIndex = 0;
    }
    else if(!Context.Dr1)
    {
        uDrIndex = 1;
    }
    else if (!Context.Dr2)
    {
        uDrIndex = 2;
    }
    else if (!Context.Dr3)
    {
        uDrIndex = 3;
    }
    
    return uDrIndex;
}

bool SetEmptyDr(HANDLE hThread, ULONG uIndex, ULONG_PTR upAddress)
{
    CONTEXT Context = { 0 };
    PDBG_REG7 pDr7 = (PDBG_REG7)&Context.Dr7;
    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    DWORD dwRet = SuspendThread(hThread);

    if (-1 != dwRet)
    {
        dwRet = GetThreadContext(hThread, &Context);

        if (dwRet)
        {
            switch (uIndex)
            {
            case 0:
                pDr7->L0 = 1;//dr0-dr3哪个有效
                //pDr7->RW0 = 1;//0:执行断点，1：读取断点。2：写入断点
                //pDr7->LEN0 = 0;//断点的长度，测试执行断点，0就有效
                Context.Dr0 = upAddress;
                break;
            case 1: 
                Context.Dr1 = upAddress;
                pDr7->L1 = 1;
                break;
            case 2: 
                Context.Dr2 = upAddress;
                pDr7->L2 = 1;
                break;
            case 3: 
                Context.Dr3 = upAddress;
                pDr7->L3 = 1;
                break;
            }

            dwRet = SetThreadContext(hThread, &Context);
            if (dwRet)
            {
                dwRet = ResumeThread(hThread);
                if (dwRet)
                {
                    return true;
                }

            }
        }
    }

    return false;
}

bool SetHook(ULONG_PTR upHookAddr, VehHookCallback upTargetAddr, HANDLE hThread)
{
    bool bIsSuccess = true;

    do
    {
        if (!upHookAddr || !upTargetAddr)
        {
            bIsSuccess = false;
            break;
        }

        ULONG uDrIndexEmpty = GetEmptyDr(hThread);
        if (-1 == uDrIndexEmpty)
        {
            bIsSuccess = false;
            break;
        }

        //1. 设置异常处理函数
        PVOID pVehNode = AddVectoredExceptionHandler(1, VehHandler1);
        if (!pVehNode)
        {
            bIsSuccess = false;
            break;
        }

        HOOK_INFO HookInfo = { 0 };
        HookInfo.upTargetAddr = (ULONG_PTR)upTargetAddr;
        HookInfo.upHookAddr = upHookAddr;
        HookInfo.uJmpOverLen = insn_len_x86_32((PVOID)upHookAddr);
        memcpy(HookInfo.JmpOverCode, (PVOID)upHookAddr, HookInfo.uJmpOverLen);

        //2. 设置分发shellcode
        UCHAR DispatchCode[] = {
         0x60,   //pushad
         0x9C,   //pushfd
         0x8B, 0xC4, // mov eax, esp
         0x50,   //push eax
         0xB8, 0x78, 0x56, 0x34, 0x12,   //mov eax, 0x12345678
         0xFF, 0xD0, //call eax
         0x9D,   //popfd
         0x61,   //popad
         //执行被jmpcode覆盖的字节
         0x68, 0x78, 0x56, 0x34, 0x12,   //push 0x12345678
         0xC3    //ret
        };

        PUCHAR pDispatchShellcode = (PUCHAR)malloc(sizeof(DispatchCode) + HookInfo.uJmpOverLen);
        if (!pDispatchShellcode)
        {
            bIsSuccess = false;
            break;
        }
        DWORD dwOldPro = 0;
        VirtualProtect(pDispatchShellcode, 0x1000, PAGE_EXECUTE_READWRITE, &dwOldPro);

        memcpy(pDispatchShellcode, DispatchCode, 14);
        memcpy(pDispatchShellcode + 14, (PVOID)upHookAddr, HookInfo.uJmpOverLen);
        memcpy(pDispatchShellcode + 14 + HookInfo.uJmpOverLen, DispatchCode + 14, 6);

        *(PULONG)(&pDispatchShellcode[6]) = (ULONG)upTargetAddr; 
        *(PULONG)(pDispatchShellcode + 15 + HookInfo.uJmpOverLen) = HookInfo.upHookAddr + HookInfo.uJmpOverLen;
        HookInfo.upDispatchCall = (ULONG_PTR)pDispatchShellcode;

        g_vecHookInfos.push_back(HookInfo);

        //3. 设置硬件断点
        HookInfo.uDrIndex = uDrIndexEmpty;
        SetEmptyDr(hThread, uDrIndexEmpty, upHookAddr);
        printf("HookOver\r\n");
    } while (false);
    
    return bIsSuccess;
}

bool UnSetHook(ULONG_PTR upHookAddr) 
{
    //todo 
    return true;
}