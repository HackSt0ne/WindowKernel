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
    //veh �ڴ�ִ�������쳣hook
    //HMODULE hModule = GetModuleHandleA("kernel32.dll");
    //if (hModule)
    //{
    //    PVOID pOpenprocess = GetProcAddress(hModule, "OpenProcess");
    //    InitHook();

    //    bool bIsHookSuccess = AddHook((ULONG_PTR)pOpenprocess, Callback);
    //    if (bIsHookSuccess)
    //    { 
    //        printf("Hook �ɹ�\r\n");

    //        OpenProcess(0,0,0);
    //    }
    //    else
    //    {
    //        printf("Hook ʧ��\r\n");
    //    }
    //}

   
    //veh Ӳ���ϵ�hook
    HMODULE hModule = GetModuleHandleA("kernel32.dll");
    if (hModule)
    {
        PVOID pOpenprocess = GetProcAddress(hModule, "OpenProcess");
        if (pOpenprocess)
        {
            HANDLE hThread = CreateThread(NULL, NULL, ThreadFunc, pOpenprocess, 0, NULL);
            Sleep(1000);//�̸߳մ������߳̽ṹ������������ʱȥ����dr�Ĵ����������ò��ɹ�
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