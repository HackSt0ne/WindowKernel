#pragma once
#include <ntddk.h>
#include <ntimage.h>
#include "../Tools/Tools.h"
typedef struct _REL_BLOCK {
	UINT16 offset : 12;
	UINT16 type : 4;
}REL_BLOCK, *PREL_BLOCK;

BOOLEAN IsPE(PVOID buff);
NTSTATUS FileBuff2ImageBuff(PVOID file_buff, PVOID* image_buff);
NTSTATUS FixRelocation(PVOID image_buff);
NTSTATUS FixIAT(PVOID image_buff);
NTSTATUS MemLoadDriver(PVOID file_buff);
NTSTATUS CallEntryPointer(PVOID image_buff);

typedef NTSTATUS(NTAPI * DriverEntryProc)(PDRIVER_OBJECT driver, PUNICODE_STRING reg_path);

