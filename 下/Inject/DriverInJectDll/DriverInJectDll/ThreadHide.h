#pragma once
#include <ntifs.h>

NTSTATUS ModifyThreadStartAddr(PETHREAD pEthread, ULONG64 uStartAddr);
ULONG64 SetThreadNotification(ULONG uNewMask);
void RemoveThreadFromList(PETHREAD pEthread);