#pragma once
#include <ntifs.h>
#include <ntimage.h>

NTSTATUS Inject(HANDLE hPid, PUCHAR pBUffer, SIZE_T uSize);