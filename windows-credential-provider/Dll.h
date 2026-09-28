#pragma once

#include <windows.h>

void DllAddRef();
void DllRelease();
HRESULT WardenProviderCreateInstance(REFIID riid, void** object);

