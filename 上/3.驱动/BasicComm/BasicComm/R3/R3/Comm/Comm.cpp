#include "Comm.h"

HANDLE gdevice;

BOOLEAN InitComm() {
	if (gdevice) {
		return TRUE;
	}

	gdevice = CreateFileA("\\\\.\\st0ne", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (gdevice == INVALID_HANDLE_VALUE)
		return FALSE;
	else{
		return TRUE;
	}
		
	
}

BOOLEAN DoComm(ULONG cmd, PVOID in_data, ULONG in_len, PVOID out_data, ULONG out_len) {
	if (!gdevice)
		InitComm();

	if (gdevice)
	{
		CommPkg pkg = { 0 };
		//初始化结构体
		pkg.id = ID;
		pkg.cmd = cmd;
		pkg.in_data = (ULONG64)in_data;
		pkg.in_len = in_len;
		pkg.out_data = (ULONG64)out_data;
		pkg.out_len = out_len;
		//发送数据
		ULONG written = 0;
		return WriteFile(gdevice, &pkg, sizeof(CommPkg), &written, NULL);
	}
	return FALSE;
}

VOID CloseComm() {
	if(gdevice)
		CloseHandle(gdevice);
}