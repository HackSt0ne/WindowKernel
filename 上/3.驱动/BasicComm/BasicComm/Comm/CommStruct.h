#ifdef _R3
#include <Windows.h>
#else
#include <ntddk.h>
#endif

//����r3 r0��ͬ�����ݽṹ

#define SYM_NAME L"\\??\\st0ne"
#define ID 0x12345678

//�����Լ���ҵ���߼��е�ͨ�Žṹ��
typedef struct _Test {
	int a;
	int b;
}Test, *PTest;

typedef enum _CMD {
	TEST = 0
}CMD;

typedef struct _CommPkg {
	ULONG64 id;
	ULONG64 cmd;
	ULONG64 in_data;
	ULONG64 in_len;
	ULONG64 out_data;
	ULONG64 out_len;
}CommPkg, *PCommPkg;