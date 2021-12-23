#include <Windows.h>
#include <stdio.h>
#include "Comm/Comm.h"

int main()
{
	Test t = { 0 };
	t.a = 1;
	t.b = 2;

	char out[20] = { 0 };
	BOOLEAN re = InitComm();
	if (re)
		re = DoComm(TEST, &t, sizeof(t), &out, 20);
	CloseComm();
	system("pause");
}