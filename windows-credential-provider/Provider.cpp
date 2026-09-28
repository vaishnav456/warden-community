#include <new>
#include "Provider.h"
#include "Credential.h"
#include "ComHelpers.h"
#include "Dll.h"
#include "Fields.h"

WardenProvider::WardenProvider()
    : references_(1), scenario_(CPUS_INVALID), credential_(nullptr)
{
    DllAddRef();
}

WardenProvider::~WardenProvider()
{
    if (credential_ != nullptr)
    {
        credential_->Release();
    }
    DllRelease();
}

HRESULT WardenProvider::QueryInterface(REFIID riid, void** object)
{
    if (object == nullptr)
    {
        return E_INVALIDARG;
    }
    *object = nullptr;
    if (riid == IID_IUnknown || riid == IID_ICredentialProvider)
    {
        *object = static_cast<ICredentialProvider*>(this);
    }
    else if (riid == IID_ICredentialProviderSetUserArray)
    {
        *object = static_cast<ICredentialProviderSetUserArray*>(this);
    }
    else
    {
        return E_NOINTERFACE;
    }
    AddRef();
    return S_OK;
}

ULONG WardenProvider::AddRef() { return InterlockedIncrement(&references_); }

ULONG WardenProvider::Release()
{
    LONG value = InterlockedDecrement(&references_);
    if (value == 0)
    {
        delete this;
    }
    return value;
}

HRESULT WardenProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, DWORD)
{
    if (scenario != CPUS_LOGON && scenario != CPUS_UNLOCK_WORKSTATION)
    {
        return E_NOTIMPL;
    }
    scenario_ = scenario;
    if (credential_ != nullptr)
    {
        credential_->Release();
        credential_ = nullptr;
    }
    credential_ = new (std::nothrow) WardenCredential();
    if (credential_ == nullptr)
    {
        return E_OUTOFMEMORY;
    }
    HRESULT hr = credential_->Initialize(scenario);
    if (FAILED(hr))
    {
        credential_->Release();
        credential_ = nullptr;
    }
    return hr;
}

HRESULT WardenProvider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) { return E_NOTIMPL; }
HRESULT WardenProvider::Advise(ICredentialProviderEvents*, UINT_PTR) { return S_OK; }
HRESULT WardenProvider::UnAdvise() { return S_OK; }

HRESULT WardenProvider::GetFieldDescriptorCount(DWORD* count)
{
    if (count == nullptr) return E_INVALIDARG;
    *count = WFI_NUM_FIELDS;
    return S_OK;
}

HRESULT WardenProvider::GetFieldDescriptorAt(DWORD index, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** descriptor)
{
    if (index >= WFI_NUM_FIELDS) return E_INVALIDARG;
    return CopyFieldDescriptor(kWardenFieldDescriptors[index], descriptor);
}

HRESULT WardenProvider::GetCredentialCount(DWORD* count, DWORD* defaultCredential, BOOL* autoLogon)
{
    if (count == nullptr || defaultCredential == nullptr || autoLogon == nullptr) return E_INVALIDARG;
    *count = credential_ != nullptr ? 1 : 0;
    *defaultCredential = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *autoLogon = FALSE;
    return S_OK;
}

HRESULT WardenProvider::GetCredentialAt(DWORD index, ICredentialProviderCredential** credential)
{
    if (credential == nullptr) return E_INVALIDARG;
    *credential = nullptr;
    if (index != 0 || credential_ == nullptr) return E_INVALIDARG;
    return credential_->QueryInterface(IID_PPV_ARGS(credential));
}

HRESULT WardenProvider::SetUserArray(ICredentialProviderUserArray*) { return S_OK; }

HRESULT WardenProviderCreateInstance(REFIID riid, void** object)
{
    auto* provider = new (std::nothrow) WardenProvider();
    if (provider == nullptr)
    {
        return E_OUTOFMEMORY;
    }
    HRESULT hr = provider->QueryInterface(riid, object);
    provider->Release();
    return hr;
}
