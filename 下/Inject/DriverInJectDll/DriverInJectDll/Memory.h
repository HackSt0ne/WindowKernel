#pragma once
#include <ntifs.h>

//申请释放指定进程的应用层内存，并设置页表属性为可执行
ULONG64 AllocateMemoryExecutable(HANDLE hPid, ULONG64 u64Size);
ULONG64 AllocateMemoryNoExecutable(HANDLE hPid, ULONG64 u64Size);
NTSTATUS FreeMemory(HANDLE hPid, ULONG64 u64BaseAddr, ULONG64 u64Size);