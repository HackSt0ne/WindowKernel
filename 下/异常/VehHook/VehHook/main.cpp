#include <windows.h>
#include <stdio.h>
#include <time.h>

#include "VehHook.h"
#include "VehHwbpHook.h"

void WINAPI Callback(PMY_CONTEXT pContext)
{
    printf("Callback\r\n");
}

DWORD WINAPI ThreadFunc(
    LPVOID lpThreadParameter
    )
{
    typedef HANDLE(WINAPI*PFN_OpenProcess)(
        _In_ DWORD dwDesiredAccess,
        _In_ BOOL bInheritHandle,
        _In_ DWORD dwProcessId
        );
    PFN_OpenProcess pFunc = (PFN_OpenProcess)lpThreadParameter;
   
    printf("ThreadFunc\r\n");
    while (1)
    {
        pFunc(0, 0, 0);
    }

    return 1;
}

int main()
{
    //veh 内存执行属性异常hook
    //HMODULE hModule = GetModuleHandleA("kernel32.dll");
    //if (hModule)
    //{
    //    PVOID pOpenprocess = GetProcAddress(hModule, "OpenProcess");
    //    InitHook();

    //    bool bIsHookSuccess = AddHook((ULONG_PTR)pOpenprocess, Callback);
    //    if (bIsHookSuccess)
    //    { 
    //        printf("Hook 成功\r\n");

    //        OpenProcess(0,0,0);
    //    }
    //    else
    //    {
    //        printf("Hook 失败\r\n");
    //    }
    //}

   
    //veh 硬件断点hook
    HMODULE hModule = GetModuleHandleA("kernel32.dll");
    if (hModule)
    {
        PVOID pOpenprocess = GetProcAddress(hModule, "OpenProcess");
        if (pOpenprocess)
        {
            HANDLE hThread = CreateThread(NULL, NULL, ThreadFunc, pOpenprocess, 0, NULL);
            Sleep(1000);//线程刚创建，线程结构还不完整，此时去设置dr寄存器，会设置不成功
            if (hThread)
            {
                SetHook((ULONG_PTR)pOpenprocess, Callback, hThread);
            }

           
        }
    }
    //Sleep(3000);
    system("pause");
    return 0;
}