#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
LONG NTAPI VectoredExceptionHandler(
    struct _EXCEPTION_POINTERS *ExceptionInfo
)
{
    ExceptionInfo->ContextRecord->Eip += 3;
    //MessageBoxA(0,0,0,0);
    return EXCEPTION_CONTINUE_EXECUTION;
}

int main()
{
    PSRWLOCK
    AddVectoredExceptionHandler(1, VectoredExceptionHandler);
    
    int a = 1;
    int b = 0;
    int c = a / b;

    printf("³É¹¦½áÊø");
}