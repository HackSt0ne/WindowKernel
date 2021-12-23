#include <ntifs.h>
#include <ntstrsafe.h>
typedef struct _LDR_DATA_TABLE_ENTRY
{
	struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
	struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x8
	struct _LIST_ENTRY InInitializationOrderLinks;                          //0x10
	VOID* DllBase;                                                          //0x18
	VOID* EntryPoint;                                                       //0x1c
	ULONG SizeOfImage;                                                      //0x20
	struct _UNICODE_STRING FullDllName;                                     //0x24
	struct _UNICODE_STRING BaseDllName;                                     //0x2c
	ULONG Flags;                                                            //0x34
	USHORT LoadCount;                                                       //0x38
	USHORT TlsIndex;                                                        //0x3a
	union
	{
		struct _LIST_ENTRY HashLinks;                                       //0x3c
		struct
		{
			VOID* SectionPointer;                                           //0x3c
			ULONG CheckSum;                                                 //0x40
		};
	};
	union
	{
		ULONG TimeDateStamp;                                                //0x44
		VOID* LoadedImports;                                                //0x44
	};
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x48
	VOID* PatchInformation;                                                 //0x4c
	struct _LIST_ENTRY ForwarderLinks;                                      //0x50
	struct _LIST_ENTRY ServiceTagLinks;                                     //0x58
	struct _LIST_ENTRY StaticLinks;                                         //0x60
	VOID* ContextInformation;                                               //0x68
	ULONG OriginalBase;                                                     //0x6c
	union _LARGE_INTEGER LoadTime;                                          //0x70
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

NTKERNELAPI
NTSTATUS
ObReferenceObjectByName(
	IN PUNICODE_STRING ObjectName,
	IN ULONG Attributes,
	IN PACCESS_STATE PassedAccessState OPTIONAL,
	IN ACCESS_MASK DesiredAccess OPTIONAL,
	IN POBJECT_TYPE ObjectType,
	IN KPROCESSOR_MODE AccessMode,
	IN OUT PVOID ParseContext OPTIONAL,
	OUT PVOID *Object
);
extern POBJECT_TYPE * IoDriverObjectType;

void DriverUnload(PDRIVER_OBJECT pdriver){
	DbgPrint("DriverUnload");
}

void EnumerateDrivers(PDRIVER_OBJECT pdriver) {
	//遍历所有的驱动模块
	PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)pdriver->DriverSection;
	PLDR_DATA_TABLE_ENTRY next = ldr->InLoadOrderLinks.Flink;
	
	ULONG count = 0;
	UNICODE_STRING target_driver_name = { 0 };
	RtlInitUnicodeString(&target_driver_name, L"tcpip.sys");

	while (next != ldr) {
		if (next->BaseDllName.Length != 0 && RtlCompareUnicodeString(&target_driver_name, &next->BaseDllName, TRUE) == 0)
		{
			DbgPrint("%x、---%wZ---", count++, &next->BaseDllName);
			RemoveEntryList(&next->InLoadOrderLinks);
			break;
		}
		next = next->InLoadOrderLinks.Flink;
	}
}


void RemoveDriver(PWCH DriverName) {
	LARGE_INTEGER time = { 0 };
	time.QuadPart = -10 * 1000 * 1000 * 5;
	KeDelayExecutionThread(KernelMode, FALSE, &time);
	WCHAR buff[0x100] = L"\\driver\\";
	RtlStringCbCatW(buff, 0x100, DriverName);
	UNICODE_STRING driver_name = { 0 };
	RtlInitUnicodeString(&driver_name, buff);
	PDRIVER_OBJECT pdriver = 0;
	NTSTATUS status = ObReferenceObjectByName(&driver_name, OBJ_CASE_INSENSITIVE, NULL, FILE_ALL_ACCESS, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&pdriver);
	if (!NT_SUCCESS(status)) {
		return;
	}

	PLDR_DATA_TABLE_ENTRY ldr = pdriver->DriverSection;
	if (ldr)
	{
		RemoveEntryList(&ldr->InLoadOrderLinks);
		pdriver->DriverInit = 0;
		pdriver->DriverSection = 0;
	}

	ObDereferenceObject(pdriver);

}

NTSTATUS DriverEntry(PDRIVER_OBJECT pdriver, PUNICODE_STRING pregpath){
	DbgBreakPoint();
	DbgPrint("DriverEntry");
	NTSTATUS status = STATUS_SUCCESS;
	pdriver->DriverUnload = DriverUnload;
	//EnumerateDrivers(pdriver);
	//RemoveDriver(L"http");
	HANDLE thread = 0;
	PsCreateSystemThread(&thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, RemoveDriver, L"CutDriverFromList");
	return status;
}