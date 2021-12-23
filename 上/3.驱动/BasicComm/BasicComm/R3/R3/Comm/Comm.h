#pragma once
#include "../../../Comm/CommStruct.h"
#include <stdio.h>
BOOLEAN InitComm();
BOOLEAN DoComm(ULONG cmd, PVOID in_data, ULONG in_len, PVOID out_data, ULONG out_len);
VOID CloseComm();