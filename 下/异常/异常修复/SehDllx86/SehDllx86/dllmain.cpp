// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "Search.h"

typedef VOID(__fastcall *PFN_RtlInsertInvertedFunctionTable)(
    PVOID ImageBase,
    ULONG SizeOfImage
    );

void test()
{
    MessageBoxA(0, "test", 0, 0);
    __try
    {
        int x = 0;
        int y = 1 / x;
    }
    __except (1)
    {
        MessageBoxA(0, "except", 0, 0);
    }
}


BOOL IsWin7()
{
    OSVERSIONINFOEX osver = { 0 };
    osver.dwOSVersionInfoSize = sizeof(osver);
    osver.dwMajorVersion = 6;
    osver.dwMinorVersion = 1;
    osver.dwPlatformId = VER_PLATFORM_WIN32_NT;

    // 每次调用只能增加一个比较;
    DWORDLONG dwlConditionMask = 0;
    VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, VER_EQUAL);
    VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, VER_EQUAL);
    VER_SET_CONDITION(dwlConditionMask, VER_PLATFORMID, VER_EQUAL);

    if (VerifyVersionInfo(&osver, VER_MAJORVERSION | VER_MINORVERSION | VER_PLATFORMID,
        dwlConditionMask))
        return TRUE;

    return FALSE;
}

ULONG GetInsertInvertedFunctionTableAndLdrpInvertedFunctionTable(PULONG pLdrpInvertedFunctionTable)
{
    if (!pLdrpInvertedFunctionTable)
    {
        return 0;
    }
    *pLdrpInvertedFunctionTable = 0;

    //搜索函数RtlInsertInvertedFunctionTable, 调用它来修复
    HMODULE hNtModule = LoadLibraryA("ntdll.dll");
    if (!hNtModule)
    {
        return 0;
    }
    else
    {
        //遍历ntdll，搜索特征码
        PIMAGE_DOS_HEADER pDOs = (PIMAGE_DOS_HEADER)hNtModule;
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PUCHAR)hNtModule + pDOs->e_lfanew);
        ULONG uSize = pNt->OptionalHeader.SizeOfImage;

        YSignatureCode code;
        PUCHAR pSearchRet = 0;
        PFN_RtlInsertInvertedFunctionTable RtlInsertInvertedFunctionTable = 0;

        if (IsWin7())
        {
            pSearchRet = (PUCHAR)code.search((const void*)((ULONG)hNtModule), uSize, "ff 76 20 ff 76 18 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 5f 5e 5d c2 04 00");

            if (!pSearchRet)
            {
                MessageBoxA(0, "Search Failed!", 0, 0);
                return false;
            }

            LONG uOffset = *(PULONG)(pSearchRet + 12);
            RtlInsertInvertedFunctionTable = (PFN_RtlInsertInvertedFunctionTable)(uOffset + pSearchRet + 16);
            ULONG LdrpInvertedFunctionTable = *(PULONG)(pSearchRet + 7);
            *pLdrpInvertedFunctionTable = LdrpInvertedFunctionTable;
        }
        else
        {
            pSearchRet = (PUCHAR)code.search((const void*)((ULONG)hNtModule), uSize, "8B FF 55 8B EC 83 EC 0C 53 56 57 8D 45 F8 8B FA 50 8D 55 FC 8B D9");
            if (!pSearchRet)
            {
                MessageBoxA(0, "Search Failed!", 0, 0);
                return false;
            }
            RtlInsertInvertedFunctionTable = (PFN_RtlInsertInvertedFunctionTable)pSearchRet;

            pSearchRet = (PUCHAR)code.search((const void*)((ULONG)pSearchRet + 1), uSize, "8B FF 55 8B EC");
            if (!pSearchRet)
            {
                MessageBoxA(0, "Search Failed!", 0, 0);
                return false;
            }

            *pLdrpInvertedFunctionTable = *(PULONG)(pSearchRet + 6);
        }
        return (ULONG)RtlInsertInvertedFunctionTable;
    }
}

bool FixSeh(HMODULE hModule)
{
    //修复x86 SEH异常
    ULONG LdrpInvertedFunctionTable = 0;
    PFN_RtlInsertInvertedFunctionTable RtlInsertInvertedFunctionTable =
        (PFN_RtlInsertInvertedFunctionTable)GetInsertInvertedFunctionTableAndLdrpInvertedFunctionTable(&LdrpInvertedFunctionTable);
    if (RtlInsertInvertedFunctionTable && LdrpInvertedFunctionTable)
    {
        char buf[0x20] = { 0 };
        snprintf(buf, 0x20, "%p, %p", RtlInsertInvertedFunctionTable, LdrpInvertedFunctionTable);
        MessageBoxA(0, buf,0,0);
        PIMAGE_DOS_HEADER pDOs = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PUCHAR)hModule + pDOs->e_lfanew);
        
        RtlInsertInvertedFunctionTable(
            hModule,
            pNt->OptionalHeader.SizeOfImage);

        MessageBoxA(0,"修复完了",0,0);
        return true;
    }
    
    return false;
}

PRUNTIME_FUNCTION MyCallback(
    _In_ DWORD64 ControlPc,
    _In_opt_ PVOID Context
)
{
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)Context;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((ULONG64)Context + pDos->e_lfanew);
    PIMAGE_DATA_DIRECTORY pExceptionDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    
    PRUNTIME_FUNCTION pRuntimeFunc = (PRUNTIME_FUNCTION)(pExceptionDir->VirtualAddress + (ULONG64)Context);
    ULONG64 uCnt = pExceptionDir->Size / sizeof(RUNTIME_FUNCTION);

    PRUNTIME_FUNCTION pFind = NULL;

    for (int i = 0; i < uCnt; i++)
    {
        ULONG64 uStart = (ULONG64)Context + pRuntimeFunc[i].BeginAddress;
        ULONG64 uEnd = (ULONG64)Context + pRuntimeFunc[i].EndAddress;
        if (ControlPc >= uStart && ControlPc <= uEnd)
        {
            pFind = &pRuntimeFunc[i];
            break;
        }
    }
    return pFind;
}

bool FixSehx64(HMODULE hModule)
{
    //第一种：
    if (hModule)
    {
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((ULONG64)hModule + pDos->e_lfanew);
        ULONG64 hModulexx = (ULONG64)hModule | 3;

        if (RtlInstallFunctionTableCallback(
            hModulexx,
            (ULONG64)hModule,
            pNt->OptionalHeader.SizeOfImage,
            MyCallback,
            hModule,
            NULL))
        {
            MessageBoxA(0,"RtlInstallFunctionTableCallback Success",0,0);
            return true;
        }
        else
        {
            MessageBoxA(0, "RtlInstallFunctionTableCallback Failed", 0, 0);
            return false;
        }

        //第二种：
        PIMAGE_DATA_DIRECTORY pExceptionDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        PRUNTIME_FUNCTION pRuntimeFunc = (PRUNTIME_FUNCTION)(pExceptionDir->VirtualAddress + (ULONG64)hModule);
        ULONG64 uCnt = pExceptionDir->Size / sizeof(RUNTIME_FUNCTION);
        RtlAddFunctionTable(pRuntimeFunc, uCnt, (ULONG64)hModule);
    }
    return false;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(0, "start", 0, 0);
        //FixSeh(hModule);
        FixSehx64(hModule);
        test();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

