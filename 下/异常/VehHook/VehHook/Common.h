#pragma once
#include <windows.h>

//定义回调函数参数
typedef struct _MY_CONTEXT
{
    ULONG _eflags;
    ULONG _edi;
    ULONG _esi;
    ULONG _ebp;
    ULONG _esp;
    ULONG _ebx;
    ULONG _edx;
    ULONG _ecx;
    ULONG _eax;
}MY_CONTEXT, *PMY_CONTEXT;

typedef struct _DBG_REG7
{
    /*
    // 局部断点(L0~3)与全局断点(G0~3)的标记位
    */
    unsigned L0 : 1;  // 对Dr0保存的地址启用 局部断点
    unsigned G0 : 1;  // 对Dr0保存的地址启用 全局断点
    unsigned L1 : 1;  // 对Dr1保存的地址启用 局部断点
    unsigned G1 : 1;  // 对Dr1保存的地址启用 全局断点
    unsigned L2 : 1;  // 对Dr2保存的地址启用 局部断点
    unsigned G2 : 1;  // 对Dr2保存的地址启用 全局断点
    unsigned L3 : 1;  // 对Dr3保存的地址启用 局部断点
    unsigned G3 : 1;  // 对Dr3保存的地址启用 全局断点
                                      /*
                                      // 【以弃用】用于降低CPU频率，以方便准确检测断点异常
                                      */
    unsigned LE : 1;
    unsigned GE : 1;
    /*
    // 保留字段
    */
    unsigned Reserve1 : 3;
    /*
    // 保护调试寄存器标志位，如果此位为1，则有指令修改条是寄存器时会触发异常
    */
    unsigned GD : 1;
    /*
    // 保留字段
    */
    unsigned Reserve2 : 2;

    unsigned RW0 : 2;  // 设定Dr0指向地址的断点类型 
    unsigned LEN0 : 2;  // 设定Dr0指向地址的断点长度
    unsigned RW1 : 2;  // 设定Dr1指向地址的断点类型
    unsigned LEN1 : 2;  // 设定Dr1指向地址的断点长度
    unsigned RW2 : 2;  // 设定Dr2指向地址的断点类型
    unsigned LEN2 : 2;  // 设定Dr2指向地址的断点长度
    unsigned RW3 : 2;  // 设定Dr3指向地址的断点类型
    unsigned LEN3 : 2;  // 设定Dr3指向地址的断点长度
}DBG_REG7, *PDBG_REG7;

//定义回调函数
typedef void(WINAPI*VehHookCallback)(PMY_CONTEXT pContext);
