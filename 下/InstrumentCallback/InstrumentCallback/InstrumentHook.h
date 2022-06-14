#pragma once
#include <ntifs.h>



NTSTATUS SetInstrumentHook(HANDLE hPid, PUCHAR pHookFunc, ULONG64 uSize);
VOID UnSetInstrumentHook(HANDLE hPid);