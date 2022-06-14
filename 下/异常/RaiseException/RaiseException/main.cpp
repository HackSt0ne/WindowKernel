#include <windows.h>

int main()
{
    RaiseException(0xC0000007, 0, 0, NULL);
}