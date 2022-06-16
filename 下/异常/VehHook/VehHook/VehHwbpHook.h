#pragma once
#include <windows.h>
#include "Common.h"

bool SetHook(ULONG_PTR upHookAddr, VehHookCallback upTargetAddr, HANDLE hThread);
bool UnSetHook(ULONG_PTR upHookAddr);
LONG NTAPI VehHandler1(
    struct _EXCEPTION_POINTERS *ExceptionInfo
);