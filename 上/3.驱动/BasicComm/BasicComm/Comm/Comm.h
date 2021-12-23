#pragma once
#include <ntddk.h>
#include "CommStruct.h"
#define DEVICE_NAME L"\\Device\\st0ne"
typedef NTSTATUS (NTAPI * CommCallback)(PCommPkg pkg);

NTSTATUS RegisterComm(PDRIVER_OBJECT driver, CommCallback callback);

NTSTATUS UnRegisterComm();