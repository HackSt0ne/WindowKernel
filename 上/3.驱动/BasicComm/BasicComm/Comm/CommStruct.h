#ifdef _R3
#include <Windows.h>
#else
#include <ntddk.h>
#endif

//定义r3 r0共同的数据结构

#define SYM_NAME L"\\??\\st0ne"
#define ID 0x12345678

//这是自己的业务逻辑中的通信结构体
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