#pragma once

#include <windows.h>
#include <shlwapi.h>
#include <credentialprovider.h>

inline HRESULT CopyFieldDescriptor(
    const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& source,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** destination)
{
    if (destination == nullptr)
    {
        return E_INVALIDARG;
    }
    *destination = static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(
        CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
    if (*destination == nullptr)
    {
        return E_OUTOFMEMORY;
    }
    **destination = source;
    (*destination)->pszLabel = nullptr;
    HRESULT hr = SHStrDupW(source.pszLabel, &(*destination)->pszLabel);
    if (FAILED(hr))
    {
        CoTaskMemFree(*destination);
        *destination = nullptr;
    }
    return hr;
}

inline HRESULT ReplaceCoTaskMemString(PWSTR* target, PCWSTR value)
{
    if (target == nullptr)
    {
        return E_INVALIDARG;
    }
    PWSTR replacement = nullptr;
    HRESULT hr = SHStrDupW(value != nullptr ? value : L"", &replacement);
    if (SUCCEEDED(hr))
    {
        CoTaskMemFree(*target);
        *target = replacement;
    }
    return hr;
}

