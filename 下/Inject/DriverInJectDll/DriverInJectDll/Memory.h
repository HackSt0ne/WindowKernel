#pragma once
#include <ntifs.h>

//�����ͷ�ָ�����̵�Ӧ�ò��ڴ棬������ҳ������Ϊ��ִ��
ULONG64 AllocateMemoryExecutable(HANDLE hPid, ULONG64 u64Size);
ULONG64 AllocateMemoryNoExecutable(HANDLE hPid, ULONG64 u64Size);
NTSTATUS FreeMemory(HANDLE hPid, ULONG64 u64BaseAddr, ULONG64 u64Size);