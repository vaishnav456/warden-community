#include <windows.h>
#include <unknwn.h>
#include <credentialprovider.h>
#include <cstdio>

#include "..\Guid.h"

using DllGetClassObjectFn = HRESULT(STDAPICALLTYPE*)(REFCLSID, REFIID, void**);

int wmain(int argc, wchar_t** argv)
{
    if (argc != 2)
    {
        fwprintf(stderr, L"usage: ProviderSmokeTest.exe <provider.dll>\n");
        return 2;
    }
    HMODULE module = LoadLibraryExW(argv[1], nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (module == nullptr)
    {
        fwprintf(stderr, L"LoadLibraryEx failed: %lu\n", GetLastError());
        return 3;
    }
    auto getClassObject = reinterpret_cast<DllGetClassObjectFn>(GetProcAddress(module, "DllGetClassObject"));
    if (getClassObject == nullptr)
    {
        fwprintf(stderr, L"DllGetClassObject export missing\n");
        FreeLibrary(module);
        return 4;
    }

    IClassFactory* factory = nullptr;
    HRESULT hr = getClassObject(CLSID_WardenCredentialProvider, IID_PPV_ARGS(&factory));
    if (FAILED(hr))
    {
        fwprintf(stderr, L"class factory failed: 0x%08lx\n", hr);
        FreeLibrary(module);
        return 5;
    }
    ICredentialProvider* provider = nullptr;
    hr = factory->CreateInstance(nullptr, IID_PPV_ARGS(&provider));
    factory->Release();
    if (FAILED(hr))
    {
        fwprintf(stderr, L"provider creation failed: 0x%08lx\n", hr);
        FreeLibrary(module);
        return 6;
    }
    hr = provider->SetUsageScenario(CPUS_LOGON, 0);
    if (FAILED(hr))
    {
        fwprintf(stderr, L"SetUsageScenario failed: 0x%08lx\n", hr);
        provider->Release();
        FreeLibrary(module);
        return 7;
    }
    DWORD fields = 0;
    hr = provider->GetFieldDescriptorCount(&fields);
    if (FAILED(hr) || fields != 5)
    {
        fwprintf(stderr, L"unexpected field count: %lu (0x%08lx)\n", fields, hr);
        provider->Release();
        FreeLibrary(module);
        return 8;
    }
    for (DWORD index = 0; index < fields; ++index)
    {
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* descriptor = nullptr;
        hr = provider->GetFieldDescriptorAt(index, &descriptor);
        if (FAILED(hr) || descriptor == nullptr || descriptor->dwFieldID != index)
        {
            fwprintf(stderr, L"invalid field descriptor %lu\n", index);
            provider->Release();
            FreeLibrary(module);
            return 9;
        }
        CoTaskMemFree(descriptor->pszLabel);
        CoTaskMemFree(descriptor);
    }
    DWORD count = 0;
    DWORD defaultCredential = 0;
    BOOL autoLogon = TRUE;
    hr = provider->GetCredentialCount(&count, &defaultCredential, &autoLogon);
    if (FAILED(hr) || count != 1 || autoLogon != FALSE)
    {
        fwprintf(stderr, L"unexpected credential enumeration\n");
        provider->Release();
        FreeLibrary(module);
        return 10;
    }
    ICredentialProviderCredential* credential = nullptr;
    hr = provider->GetCredentialAt(0, &credential);
    if (FAILED(hr) || credential == nullptr)
    {
        fwprintf(stderr, L"credential retrieval failed: 0x%08lx\n", hr);
        provider->Release();
        FreeLibrary(module);
        return 11;
    }
    BOOL autoSubmit = TRUE;
    hr = credential->SetSelected(&autoSubmit);
    if (FAILED(hr) || autoSubmit != FALSE)
    {
        fwprintf(stderr, L"credential selection behavior is unsafe\n");
        credential->Release();
        provider->Release();
        FreeLibrary(module);
        return 12;
    }
    hr = credential->SetStringValue(1, L"smoketest");
    if (SUCCEEDED(hr)) hr = credential->SetStringValue(2, L"NotARealPassword!123");
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION serialization{};
    PWSTR statusText = nullptr;
    CREDENTIAL_PROVIDER_STATUS_ICON statusIcon = CPSI_NONE;
    if (SUCCEEDED(hr))
    {
        hr = credential->GetSerialization(&response, &serialization, &statusText, &statusIcon);
    }
    if (FAILED(hr) || response != CPGSR_NO_CREDENTIAL_FINISHED ||
        serialization.cbSerialization != 0 || statusText == nullptr || statusIcon != CPSI_ERROR)
    {
        fwprintf(stderr, L"missing-broker failure path is unsafe or invalid\n");
        CoTaskMemFree(statusText);
        credential->Release();
        provider->Release();
        FreeLibrary(module);
        return 13;
    }
    CoTaskMemFree(statusText);
    PWSTR clearedPassword = nullptr;
    hr = credential->GetStringValue(2, &clearedPassword);
    bool passwordWasCleared = SUCCEEDED(hr) && clearedPassword != nullptr && *clearedPassword == L'\0';
    CoTaskMemFree(clearedPassword);
    credential->Release();
    provider->Release();
    FreeLibrary(module);
    if (!passwordWasCleared)
    {
        fwprintf(stderr, L"password field was not cleared after failed broker authentication\n");
        return 14;
    }
    wprintf(L"Warden Credential Provider smoke test passed (%lu fields, 1 tile, no auto-logon, safe broker failure).\n", fields);
    return 0;
}
