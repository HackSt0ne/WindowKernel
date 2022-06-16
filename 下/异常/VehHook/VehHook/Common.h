#pragma once
#include <windows.h>

//����ص���������
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
    // �ֲ��ϵ�(L0~3)��ȫ�ֶϵ�(G0~3)�ı��λ
    */
    unsigned L0 : 1;  // ��Dr0����ĵ�ַ���� �ֲ��ϵ�
    unsigned G0 : 1;  // ��Dr0����ĵ�ַ���� ȫ�ֶϵ�
    unsigned L1 : 1;  // ��Dr1����ĵ�ַ���� �ֲ��ϵ�
    unsigned G1 : 1;  // ��Dr1����ĵ�ַ���� ȫ�ֶϵ�
    unsigned L2 : 1;  // ��Dr2����ĵ�ַ���� �ֲ��ϵ�
    unsigned G2 : 1;  // ��Dr2����ĵ�ַ���� ȫ�ֶϵ�
    unsigned L3 : 1;  // ��Dr3����ĵ�ַ���� �ֲ��ϵ�
    unsigned G3 : 1;  // ��Dr3����ĵ�ַ���� ȫ�ֶϵ�
                                      /*
                                      // �������á����ڽ���CPUƵ�ʣ��Է���׼ȷ���ϵ��쳣
                                      */
    unsigned LE : 1;
    unsigned GE : 1;
    /*
    // �����ֶ�
    */
    unsigned Reserve1 : 3;
    /*
    // �������ԼĴ�����־λ�������λΪ1������ָ���޸����ǼĴ���ʱ�ᴥ���쳣
    */
    unsigned GD : 1;
    /*
    // �����ֶ�
    */
    unsigned Reserve2 : 2;

    unsigned RW0 : 2;  // �趨Dr0ָ���ַ�Ķϵ����� 
    unsigned LEN0 : 2;  // �趨Dr0ָ���ַ�Ķϵ㳤��
    unsigned RW1 : 2;  // �趨Dr1ָ���ַ�Ķϵ�����
    unsigned LEN1 : 2;  // �趨Dr1ָ���ַ�Ķϵ㳤��
    unsigned RW2 : 2;  // �趨Dr2ָ���ַ�Ķϵ�����
    unsigned LEN2 : 2;  // �趨Dr2ָ���ַ�Ķϵ㳤��
    unsigned RW3 : 2;  // �趨Dr3ָ���ַ�Ķϵ�����
    unsigned LEN3 : 2;  // �趨Dr3ָ���ַ�Ķϵ㳤��
}DBG_REG7, *PDBG_REG7;

//����ص�����
typedef void(WINAPI*VehHookCallback)(PMY_CONTEXT pContext);
