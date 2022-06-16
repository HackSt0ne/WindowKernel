#pragma once
#include <windows.h>
#include "Common.h"

bool InitHook();
bool AddHook(ULONG_PTR upHookAddr, VehHookCallback upTargetAddr);
bool UnHook(ULONG_PTR upHookAddr);