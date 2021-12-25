#include "Loader.h"

BOOLEAN IsPE(PVOID buff) {
	if (!buff) return 0;

	PIMAGE_DOS_HEADER pdos = (PIMAGE_DOS_HEADER)buff;
	PIMAGE_NT_HEADERS pnt = (PIMAGE_NT_HEADERS)((PUCHAR)buff + pdos->e_lfanew);

	if (pdos->e_magic != 0x5A4D) return 0;
	if (pnt->Signature != 0x4550) return 0;
	return 1;
}

NTSTATUS FileBuff2ImageBuff(PVOID file_buff, PVOID* image_buff) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!file_buff || !image_buff || !IsPE(file_buff)) return status;

	PIMAGE_DOS_HEADER pdos = (PIMAGE_DOS_HEADER)file_buff;
	PIMAGE_NT_HEADERS pnt = (PIMAGE_NT_HEADERS)((PUCHAR)file_buff + pdos->e_lfanew);

	ULONG size_image = pnt->OptionalHeader.SizeOfImage;
	ULONG size_headers = pnt->OptionalHeader.SizeOfHeaders;
	ULONG num_sections = pnt->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER psection = IMAGE_FIRST_SECTION(pnt);
	PVOID buff = NULL;

	do 
	{
		buff = ExAllocatePool(NonPagedPool, size_image);
		if (!buff) break;
		memcpy(buff, file_buff, size_headers);
	
		for (int i=0;i<num_sections; i++)
		{
			memcpy((PUCHAR)buff + psection->VirtualAddress, (PUCHAR)file_buff + psection->PointerToRawData, psection->SizeOfRawData);
			psection++;
		}
		*image_buff = buff;
		status = STATUS_SUCCESS;
	} while (0);
	return status;
}

NTSTATUS FixRelocation(PVOID image_buff) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!image_buff || !image_buff || !IsPE(image_buff)) return status;

	PIMAGE_DOS_HEADER pdos = (PIMAGE_DOS_HEADER)image_buff;
	PIMAGE_NT_HEADERS pnt = (PIMAGE_NT_HEADERS)((PUCHAR)image_buff + pdos->e_lfanew);

	do 
	{
		PIMAGE_DATA_DIRECTORY preloc_dir = (PIMAGE_DATA_DIRECTORY)&pnt->OptionalHeader.DataDirectory[5];//重定位目录
		if (!preloc_dir) break;

		PIMAGE_BASE_RELOCATION preloc = (PIMAGE_BASE_RELOCATION)((PUCHAR)image_buff + preloc_dir->VirtualAddress);
		while (preloc->SizeOfBlock && preloc->VirtualAddress) {
			ULONG num_blocks = (preloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
			PREL_BLOCK block = (PUCHAR)preloc + sizeof(IMAGE_BASE_RELOCATION);
			for (int i = 0; i < num_blocks; i++) {
				if (block->type == IMAGE_REL_BASED_DIR64) {//64位
					PULONG64 addr = (PUCHAR)image_buff + preloc->VirtualAddress + block->offset;
					ULONG64 value = *addr - pnt->OptionalHeader.ImageBase + (ULONG64)image_buff;
					*addr = value;
				}
				else if (block->type == IMAGE_REL_BASED_HIGHLOW) {//32位
					PULONG addr = (PUCHAR)image_buff + preloc->VirtualAddress + block->offset;
					ULONG value = *addr - pnt->OptionalHeader.ImageBase + (ULONG)image_buff;
					*addr = value;
				}
				block++;
			}
			preloc = (PUCHAR)preloc + preloc->SizeOfBlock;
		}
		status = STATUS_SUCCESS;
	} while (0);
	
	return status;
}


NTSTATUS FixIAT(PVOID image_buff) {
	DbgBreakPoint();
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!image_buff || !IsPE(image_buff)) return status;

	PIMAGE_DOS_HEADER pdos = (PIMAGE_DOS_HEADER)image_buff;
	PIMAGE_NT_HEADERS pnt = (PIMAGE_NT_HEADERS)((PUCHAR)image_buff + pdos->e_lfanew);
	PIMAGE_DATA_DIRECTORY pimport_dir = &pnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR pimport = (PIMAGE_IMPORT_DESCRIPTOR)((PUCHAR)image_buff + pimport_dir->VirtualAddress);

	BOOLEAN isSuccess = TRUE;
	while (pimport->Name) {
		PUCHAR module_name = (PUCHAR)image_buff + pimport->Name;
		ULONG_PTR lib_size = 0;
		ULONG_PTR lib_base = QueryModule(module_name, &lib_size);
		if (!lib_base)
		{
			isSuccess = 0;
			break;
		}

		PIMAGE_THUNK_DATA pthunk_name = (PIMAGE_THUNK_DATA)((PUCHAR)image_buff + pimport->OriginalFirstThunk);//保存函数名的结构
		PIMAGE_THUNK_DATA pthunk_func = (PIMAGE_THUNK_DATA)((PUCHAR)image_buff + pimport->FirstThunk);//要填充函数地址的结构
		for (; pthunk_name->u1.ForwarderString; pthunk_name++, pthunk_func++) {
			PIMAGE_IMPORT_BY_NAME func_name = (PIMAGE_IMPORT_BY_NAME)((PUCHAR)image_buff + pthunk_name->u1.AddressOfData);//函数名结构体
			
			ULONG_PTR func_addr = GetProcAddressByExport(lib_base, func_name->Name);
			
			if (func_addr) {
				pthunk_func->u1.Function = func_addr;
			}
			else {
				isSuccess = 0; 
				break;
			}
		}
		if (!isSuccess) break;
		pimport++;
	}
	if(isSuccess)
		status = STATUS_SUCCESS;

	return status;
}

NTSTATUS CallEntryPointer(PVOID image_buff) {
	PIMAGE_DOS_HEADER pdos = (PIMAGE_DOS_HEADER)image_buff;
	PIMAGE_NT_HEADERS pnt = (PUCHAR)image_buff + pdos->e_lfanew;
	DriverEntryProc ep_func = pnt->OptionalHeader.AddressOfEntryPoint + (PUCHAR)image_buff;
	return ep_func(NULL, NULL);
}

NTSTATUS MemLoadDriver(PVOID file_buff) {
	PVOID image_buff = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	do 
	{
		//拉伸PE
		status = FileBuff2ImageBuff(file_buff, &image_buff);
		if (!NT_SUCCESS(status) || !image_buff)
			break;
		
		//修复重定位
		status = FixRelocation(image_buff);
		if (!NT_SUCCESS(status))
			break;
	
		//修复IAT表
		status = FixIAT(image_buff);
		if (!NT_SUCCESS(status))
			break;
	
		//修复cookie

		//call 入口点
		status = CallEntryPointer(image_buff);
		if (!NT_SUCCESS(status))
			break;

		//抹掉PE头
		memset(image_buff, 0, 0x1000);
	} while (0);

	if (!NT_SUCCESS(status) && image_buff)//失败。释放内存
		ExFreePool(image_buff);

	return status;
}

