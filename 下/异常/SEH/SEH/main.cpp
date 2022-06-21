#include <windows.h>
#include <stdio.h>

//0x10 bytes (sizeof) SEH�쳣����ڵ�Ľṹ
//struct _EXCEPTION_REGISTRATION_RECORD
//{
//    struct _EXCEPTION_REGISTRATION_RECORD* Next;                            //0x0
//    enum _EXCEPTION_DISPOSITION(*Handler)(struct _EXCEPTION_RECORD* arg1, VOID* arg2, struct _CONTEXT* arg3, VOID* arg4); //0x8
//};

typedef struct _SEH_NODE SEH_NODE, *PSEH_NODE;

typedef struct _SEH_NODE
{
    PSEH_NODE Next;
    PVOID Handler;
}SEH_NODE, *PSEH_NODE;

_EXCEPTION_DISPOSITION SehHandler(
    struct _EXCEPTION_RECORD* pExceptionRecord,
    PSEH_NODE pSehNode, 
    struct _CONTEXT* pContext,
    PSEH_NODE pSehNode1
)
{
    printf("ExceptionAddress = %p\r\n", pExceptionRecord->ExceptionAddress);
    printf("ExceptionAddress = %x\r\n", pExceptionRecord->ExceptionCode);
    printf("ExceptionAddress = %d\r\n", pExceptionRecord->ExceptionFlags);
    printf("ExceptionAddress = %p\r\n", pExceptionRecord->NumberParameters);
    MessageBoxA(0,0,0,0);
    return ExceptionContinueSearch;
}

//void AddSehHandlerByManual()
//{
//    //���ڽڵ�
//    SEH_NODE SehNode = { 0 };//SEH�ڵ�һ������ջ��
//    SehNode.Handler = SehHandler;
//
//    ULONG_PTR upPreHandler = 0;
//    __asm
//    {
//        mov eax, fs:[0]//������һ���ڵ�ָ��
//        mov dword ptr[upPreHandler], eax
//    }
//
//    SehNode.Next = (PSEH_NODE)upPreHandler;
//    
//    __asm
//    {
//        lea eax, SehNode
//        mov fs:[0], eax
//    }
//
//    int x = 0;
//    int y = 1 / x;
//
//    printf("-----------------");
//    //ж�ؽڵ�
//    __asm
//    {
//        mov eax, dword ptr[upPreHandler]
//        mov fs:[0], eax
//    }
//}

long WINAPI FilterFunc(DWORD dwExceptionCode, _EXCEPTION_POINTERS* pExceptionPointers)
{    //EXCEPTION_EXECUTE_HANDLER�����������쳣������except
    //EXCEPTION_CONTINUE_SEARCH�����ﲻִ�У�������
    //EXCEPTION_CONTINUE_EXECUTION��������except���Լ��޸�����ȥ����ִ��
    if (STATUS_INTEGER_DIVIDE_BY_ZERO == dwExceptionCode)
    {
        return EXCEPTION_EXECUTE_HANDLER;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void AddSehHandlerByWin()
{
    __try
    {
        int x = 0;
        int y = 1 / x;
    }
    __except(1)
    {
        printf("except1\r\n");
    }
}

int main()
{
    
    //AddSehHandlerByManual();
    AddSehHandlerByWin();
    system("pause");
}