#include "VehHook.h"
#include "insn_len.h"

#include <ImageHLP.h>
#include <vector>
#include <map>

typedef struct _EXCEPTION_HANDLER_NODE
{
    LIST_ENTRY List;
    ULONG dwReferenceCnt;
    ULONG dwEncodedHandler;
}EXCEPTION_HANDLER_NODE, *PEXCEPTION_HANDLER_NODE;

typedef struct _HOOK_INFO
{
    ULONG_PTR upHookOffset;
    ULONG_PTR upOldModuleBase;
    ULONG_PTR upNewModuleBase;
    ULONG_PTR ModuleSize;
    UCHAR SrcReplacedCode[0x50];
    ULONG SrcReplacedCodeLength;
    ULONG_PTR upTargetFuncAddr;
    ULONG_PTR upDispatchCall;
    bool bIsHooked;
}HOOK_INFO, *PHOOK_INFO;

typedef PVOID(NTAPI*PFN_RtlPcToFileHeader)
(
    _In_ PVOID PcValue,
    _Out_ PVOID* BaseOfImage
);

std::map<ULONG_PTR, std::vector<HOOK_INFO>> g_mapHookInfo;//ULONG_PTR是模块地址，每一个HOOK_INFO代表一个Hook点


bool IsAddressInOurModifiedArea(ULONG_PTR upAddr, PULONG_PTR pOldModulebase, PULONG_PTR pNewModuleBase)
{
    for (auto& item : g_mapHookInfo)
    {
        if ((upAddr >= item.second[0].upOldModuleBase) &&
            (upAddr <= (item.second[0].upOldModuleBase + item.second[0].ModuleSize)))
        {
            *pOldModulebase = item.second[0].upOldModuleBase;
            *pNewModuleBase = item.second[0].upNewModuleBase;
            return true;
        }
    }
    return false;
}


LONG NTAPI VehHandler(
    struct _EXCEPTION_POINTERS *ExceptionInfo
)
{
    //1. 是0xC0000005异常
    //2. 出错地址是我们修改过内存属性的地址
    //3. 接管运行流程
    //4. 否则继续搜索
    ULONG_PTR upOldModuleBase = 0;
    ULONG_PTR upNewModuleBase = 0;
    if ((0xC0000005 == ExceptionInfo->ExceptionRecord->ExceptionCode) &&
        IsAddressInOurModifiedArea((ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress, &upOldModuleBase, &upNewModuleBase) &&
        upOldModuleBase &&
        upNewModuleBase)
    {
        ExceptionInfo->ContextRecord->Eip = (ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress - upOldModuleBase + upNewModuleBase;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    else
    {
      
        return EXCEPTION_CONTINUE_SEARCH;
    }

    
}

bool InitHook()
{
    PEXCEPTION_HANDLER_NODE pVehNode = (PEXCEPTION_HANDLER_NODE)AddVectoredExceptionHandler(1, VehHandler);
    if (!pVehNode)
    {
        return false;
    }
    return true;
}

ULONG GetCodeLength(ULONG_PTR upStart, ULONG uMinLen)
{
    //从给定地址开始，计算比uMinLen大的完整指令长度 
    ULONG uLen = 0;
    do
    {
        ULONG uTmp = insn_len_x86_32((void*)upStart);
        if (!uTmp)
        {
            break;
        }
        uLen += uTmp;
        upStart += uTmp;
    } while (uLen < uMinLen);

    return uLen;
}

bool AddHook(ULONG_PTR upHookAddr, VehHookCallback upTargetAddr)
{
    bool bIsSuccess = true;

    do
    {
        if (!upHookAddr || !upTargetAddr)
        {
            bIsSuccess = false;
            break;
        }

        //1. 定位函数模块基址
        PUCHAR pHookModuleBase = NULL;
        HMODULE hModule = GetModuleHandle("ntdll.dll");
        PFN_RtlPcToFileHeader pfn_RtlPcToFileHeader = (PFN_RtlPcToFileHeader)GetProcAddress(hModule, "RtlPcToFileHeader");
        pHookModuleBase = (PUCHAR)pfn_RtlPcToFileHeader((PVOID)upHookAddr, (PVOID*)&pHookModuleBase);
        if (!pHookModuleBase || *(PSHORT)pHookModuleBase != 0x5A4D)
        {
            bIsSuccess = false;
            break;
        }

        HOOK_INFO HookInfo;
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pHookModuleBase;
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pHookModuleBase + pDos->e_lfanew);
        
        HookInfo.ModuleSize = pNt->OptionalHeader.SizeOfImage;
        HookInfo.upHookOffset = upHookAddr - (ULONG_PTR)pHookModuleBase;
        HookInfo.upOldModuleBase = (ULONG_PTR)pHookModuleBase;
        HookInfo.upTargetFuncAddr = (ULONG_PTR)upTargetAddr;

        //2. 判断是否已经复制过模块，如果有则只需添加Hook点
        ULONG uJmpdeCodeLen = 5;
        ULONG uSaveCodeLen;
        if (g_mapHookInfo[(ULONG_PTR)pHookModuleBase].empty())
        {
            //添加一个新的HOOK模块
            std::vector<HOOK_INFO> stdHookInfo;
          
            //申请成新的模块
            PUCHAR pNewModuleBase = (PUCHAR)malloc(HookInfo.ModuleSize);
            DWORD dwOldPro = 0;
            bIsSuccess = VirtualProtect((PVOID)pNewModuleBase, HookInfo.ModuleSize, PAGE_EXECUTE_READWRITE, &dwOldPro);
            if (!pNewModuleBase || !bIsSuccess)
            {
                bIsSuccess = false;
                break;
            }
            memset(pNewModuleBase, 0, HookInfo.ModuleSize);
            HookInfo.upNewModuleBase = (ULONG_PTR)pNewModuleBase;

            //拷贝模块, 由于有些模块(ntdll)中有一些虚拟地址没挂页，直接memcpy会出异常
            ULONG uModulePages = HookInfo.ModuleSize >> 0xC;
            for (ULONG i = 0; i < uModulePages; i++)
            {
                SIZE_T ByteReaded = 0;
                ReadProcessMemory(GetCurrentProcess(), pHookModuleBase + i * 0x1000, pNewModuleBase + i * 0x1000, 0x1000, &ByteReaded);
            }

            //保存目标地址的代码
           
            uSaveCodeLen = GetCodeLength(HookInfo.upNewModuleBase + HookInfo.upHookOffset, uJmpdeCodeLen);
            if (!uSaveCodeLen)
            {
                bIsSuccess = false;
                break;
            }
            memcpy(HookInfo.SrcReplacedCode, (PVOID)(HookInfo.upNewModuleBase + HookInfo.upHookOffset), uSaveCodeLen);

            stdHookInfo.push_back(HookInfo);
            g_mapHookInfo[(ULONG_PTR)pHookModuleBase] = stdHookInfo;
        }
        else
        {
            HookInfo.upNewModuleBase = g_mapHookInfo[(ULONG_PTR)pHookModuleBase][0].upNewModuleBase;

            //保存目标地址的代码
            uSaveCodeLen = GetCodeLength(HookInfo.upNewModuleBase + HookInfo.upHookOffset, uJmpdeCodeLen);
            if (!uSaveCodeLen)
            {
                bIsSuccess = false;
                break;
            }
            memcpy(HookInfo.SrcReplacedCode, (PVOID)(HookInfo.upNewModuleBase + HookInfo.upHookOffset), uSaveCodeLen);

            //老的模块
          
            g_mapHookInfo[(ULONG_PTR)pHookModuleBase].push_back(HookInfo);
        }

        //生成DispatchCode
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

        PUCHAR pDispatchCode = (PUCHAR)malloc(sizeof(DispatchCode) + uSaveCodeLen);
        DWORD dwOldPro = 0;
        bIsSuccess = VirtualProtect(pDispatchCode, sizeof(DispatchCode) + uSaveCodeLen, PAGE_EXECUTE_READWRITE, &dwOldPro);
        if (!pDispatchCode || !bIsSuccess)
        {
            bIsSuccess = false; 
            break;
        }
        memcpy(pDispatchCode, DispatchCode, 14);
        memcpy(pDispatchCode + 14, HookInfo.SrcReplacedCode, uSaveCodeLen);
        memcpy(pDispatchCode + 14 + uSaveCodeLen, DispatchCode + 14, 6);

        //生成JmpCode
        PUCHAR JmpCode = (PUCHAR)(HookInfo.upNewModuleBase + HookInfo.upHookOffset);
        JmpCode[0] = 0xE9;
        *(PULONG)((ULONG)JmpCode + 1) = (ULONG)pDispatchCode - ((ULONG_PTR)JmpCode + 5);

        //修复DispatchCode
        *(PULONG)(&pDispatchCode[6]) = (ULONG_PTR)upTargetAddr;
        *(PULONG)((PUCHAR)pDispatchCode + 15 + uSaveCodeLen) = HookInfo.upNewModuleBase + HookInfo.upHookOffset + uSaveCodeLen;

        //去掉目标地址的可执行属性
        DWORD dwOldProtect = 0;
        bIsSuccess =  VirtualProtect((PVOID)(HookInfo.upHookOffset +HookInfo.upOldModuleBase), 1, PAGE_READONLY, &dwOldProtect);

    } while (false);
    return bIsSuccess;
}

bool UnHook(ULONG_PTR upHookAddr)
{
    //todo==
    return true;
}