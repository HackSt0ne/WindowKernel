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

std::map<ULONG_PTR, std::vector<HOOK_INFO>> g_mapHookInfo;//ULONG_PTR��ģ���ַ��ÿһ��HOOK_INFO����һ��Hook��


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
    //1. ��0xC0000005�쳣
    //2. �����ַ�������޸Ĺ��ڴ����Եĵ�ַ
    //3. �ӹ���������
    //4. �����������
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
    //�Ӹ�����ַ��ʼ�������uMinLen�������ָ��� 
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

        //1. ��λ����ģ���ַ
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

        //2. �ж��Ƿ��Ѿ����ƹ�ģ�飬�������ֻ�����Hook��
        ULONG uJmpdeCodeLen = 5;
        ULONG uSaveCodeLen;
        if (g_mapHookInfo[(ULONG_PTR)pHookModuleBase].empty())
        {
            //���һ���µ�HOOKģ��
            std::vector<HOOK_INFO> stdHookInfo;
          
            //������µ�ģ��
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

            //����ģ��, ������Щģ��(ntdll)����һЩ�����ַû��ҳ��ֱ��memcpy����쳣
            ULONG uModulePages = HookInfo.ModuleSize >> 0xC;
            for (ULONG i = 0; i < uModulePages; i++)
            {
                SIZE_T ByteReaded = 0;
                ReadProcessMemory(GetCurrentProcess(), pHookModuleBase + i * 0x1000, pNewModuleBase + i * 0x1000, 0x1000, &ByteReaded);
            }

            //����Ŀ���ַ�Ĵ���
           
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

            //����Ŀ���ַ�Ĵ���
            uSaveCodeLen = GetCodeLength(HookInfo.upNewModuleBase + HookInfo.upHookOffset, uJmpdeCodeLen);
            if (!uSaveCodeLen)
            {
                bIsSuccess = false;
                break;
            }
            memcpy(HookInfo.SrcReplacedCode, (PVOID)(HookInfo.upNewModuleBase + HookInfo.upHookOffset), uSaveCodeLen);

            //�ϵ�ģ��
          
            g_mapHookInfo[(ULONG_PTR)pHookModuleBase].push_back(HookInfo);
        }

        //����DispatchCode
        UCHAR DispatchCode[] = {
            0x60,   //pushad
            0x9C,   //pushfd
            0x8B, 0xC4, // mov eax, esp
            0x50,   //push eax
            0xB8, 0x78, 0x56, 0x34, 0x12,   //mov eax, 0x12345678
            0xFF, 0xD0, //call eax
            0x9D,   //popfd
            0x61,   //popad
            //ִ�б�jmpcode���ǵ��ֽ�
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

        //����JmpCode
        PUCHAR JmpCode = (PUCHAR)(HookInfo.upNewModuleBase + HookInfo.upHookOffset);
        JmpCode[0] = 0xE9;
        *(PULONG)((ULONG)JmpCode + 1) = (ULONG)pDispatchCode - ((ULONG_PTR)JmpCode + 5);

        //�޸�DispatchCode
        *(PULONG)(&pDispatchCode[6]) = (ULONG_PTR)upTargetAddr;
        *(PULONG)((PUCHAR)pDispatchCode + 15 + uSaveCodeLen) = HookInfo.upNewModuleBase + HookInfo.upHookOffset + uSaveCodeLen;

        //ȥ��Ŀ���ַ�Ŀ�ִ������
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