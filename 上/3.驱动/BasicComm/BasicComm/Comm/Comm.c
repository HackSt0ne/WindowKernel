#include "Comm.h"

CommCallback gcallback = NULL;

NTSTATUS DefaultDispatch(
	_In_ struct _DEVICE_OBJECT *device,
	_Inout_ struct _IRP *irp
) {
	//KdBreakPoint();
	irp->IoStatus.Information = 0;//返回数据的长度是0
	irp->IoStatus.Status = STATUS_SUCCESS;//请求状态是成功
	IoCompleteRequest(irp, IO_NO_INCREMENT);//完成请求
	return STATUS_SUCCESS;
}
NTSTATUS WriteDispatch(
	_In_ struct _DEVICE_OBJECT *device,
	_Inout_ struct _IRP *irp
) {
	//KdBreakPoint();
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PIO_STACK_LOCATION iostack = IoGetCurrentIrpStackLocation(irp);
	PVOID buff = irp->AssociatedIrp.SystemBuffer;
	ULONG length = iostack->Parameters.Write.Length;

	if (length == sizeof(CommPkg) && gcallback)
	{
		PCommPkg pkg = (PCommPkg)buff;
		if(MmIsAddressValid(pkg))
			status = gcallback(pkg);
	}

	irp->IoStatus.Information = 0;//返回数据的长度是0
	irp->IoStatus.Status = status;//请求状态是成功
	IoCompleteRequest(irp, IO_NO_INCREMENT);//完成请求
	return status;
}

NTSTATUS RegisterComm(PDRIVER_OBJECT pdriver, CommCallback callback) {
	

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING device_name = { 0 };
	RtlInitUnicodeString(&device_name, DEVICE_NAME);
	PDEVICE_OBJECT pdevice = NULL;
	status = IoCreateDevice(pdriver, 0, &device_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pdevice);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	UNICODE_STRING sym_name = { 0 };
	RtlInitUnicodeString(&sym_name, SYM_NAME);
	status = IoCreateSymbolicLink(&sym_name, &device_name);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(pdevice);
		return status;
	}

	pdevice->Flags |= DO_BUFFERED_IO;
	pdriver->MajorFunction[IRP_MJ_CREATE] = DefaultDispatch;
	pdriver->MajorFunction[IRP_MJ_CLOSE] = DefaultDispatch;
	pdriver->MajorFunction[IRP_MJ_WRITE] = WriteDispatch;

	gcallback = callback;

}

NTSTATUS UnRegisterComm(PDRIVER_OBJECT pdriver) {
	UNICODE_STRING sym_name = { 0 };
	RtlInitUnicodeString(&sym_name, SYM_NAME);
	IoDeleteSymbolicLink(&sym_name);
	if (pdriver->DeviceObject != NULL)
		IoDeleteDevice(pdriver->DeviceObject);
}