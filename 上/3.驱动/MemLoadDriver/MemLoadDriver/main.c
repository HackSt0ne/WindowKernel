#include <ntifs.h>
#include "../Tools/Tools.h"
void DriverUnload(PDRIVER_OBJECT pdriver){
	DbgPrint("DriverUnload");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pdriver, PUNICODE_STRING pregpath){
	DbgPrint("DriverEntry");
	NTSTATUS status = STATUS_SUCCESS;
	pdriver->DriverUnload = DriverUnload;
	
	ULONG_PTR module_size = 0;
	ULONG_PTR module_base = QueryModule("ntkrnlpa.exe", &module_size);
	KdPrint(("Module Base: %x, Module Size: %x", module_base, module_size));
	return status;
}