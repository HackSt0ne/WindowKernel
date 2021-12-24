#include "Tools.h"

//遍历内核模块(就是内核进程ntoskr的模块，也是驱动程序)
ULONG_PTR QueryModule(PUCHAR module_name, ULONG_PTR* module_size) {
	if (!module_name || !module_size) return 0;

	PUCHAR target_mod_name = ExAllocatePool(PagedPool, strlen(module_name)+1);
	memset(target_mod_name, 0, strlen(module_name) + 1);
	memcpy(target_mod_name, module_name, strlen(module_name));
	_strupr(target_mod_name);

	ULONG ulInfoLength = 0;
	PVOID pBuffer = NULL;
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	ULONG_PTR module_base = 0;
	do
	{
		ntStatus = ZwQuerySystemInformation(SystemModuleInformation,
			NULL,
			NULL,
			&ulInfoLength);
		if ((ntStatus == STATUS_INFO_LENGTH_MISMATCH))
		{
			pBuffer = ExAllocatePool(PagedPool, ulInfoLength);
			if (pBuffer == NULL) break;

			ntStatus = ZwQuerySystemInformation(SystemModuleInformation,
				pBuffer,
				ulInfoLength,
				&ulInfoLength);
			if (!NT_SUCCESS(ntStatus)) break;

			PSYSTEM_MODULE_INFORMATION pModuleInformation = (PSYSTEM_MODULE_INFORMATION)pBuffer;
			if (_stricmp(target_mod_name, "ntoskrnl.exe") || _stricmp(target_mod_name, "ntkrnlpa.exe"))
			{
				*module_size = pModuleInformation->Module[0].Size;
				module_base = pModuleInformation->Module[0].Base;
				break;
			}
			if (pModuleInformation)
			{
				for (ULONG i = 0; i < pModuleInformation->Count; i++)
				{
					_strupr(pModuleInformation->Module[i].ImageName);
					if (strstr(pModuleInformation->Module[i].ImageName, target_mod_name)) {
						*module_size = pModuleInformation->Module[i].Size;
						module_base = pModuleInformation->Module[i].Base;
						break;
					}
					//KdPrint(("Image:%-50s\t\tBase:0x%p\r\n",pModuleInformation->Module[i].ImageName, pModuleInformation->Module[i].Base));
				}
			}

			ntStatus = STATUS_SUCCESS;
		}
	} while (0);

	if (pBuffer)
	{
		ExFreePool(pBuffer);
	}
	if (target_mod_name)
	{
		ExFreePool(target_mod_name);
	}

	return module_base;
}