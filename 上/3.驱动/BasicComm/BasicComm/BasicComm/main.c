#include <ntifs.h>
#include "../Comm/Comm.h"

NTSTATUS NTAPI MyCallBack(PCommPkg pkg) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PTest t;
	if (pkg->id != ID) {
		return status;
	}

	switch (pkg->cmd)
	{
		case TEST:
		{
			if (pkg->in_len == sizeof(Test))
			{
				KdBreakPoint();
				//������
				t = (PTest)pkg->in_data;
				KdPrint(("a: %x, b: %x", t->a, t->b));
				//д����
				memcpy(pkg->out_data, "this is out data", strlen("this is out data") + 1);
			}
			break;
		}
		default: break;
	}
}

void DriverUnload(PDRIVER_OBJECT pdriver){
	DbgPrint("DriverUnload");
	UnRegisterComm(pdriver);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pdriver, PUNICODE_STRING pregpath) {
	DbgPrint("DriverEntry");
	NTSTATUS status = STATUS_SUCCESS;
	pdriver->DriverUnload = DriverUnload;

	//ע��ͨ�ŵĹ��̷�װ�����������봦����Ϣ�Ļص��������Ӵ�ֻ��Ҫ����ҵ���߼�
	RegisterComm(pdriver, MyCallBack);

	return status;
}