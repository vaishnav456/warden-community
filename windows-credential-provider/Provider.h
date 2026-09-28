#pragma once

#include <credentialprovider.h>

// MinGW's credentialprovider.h forward-declares this Windows 8 interface but
// does not define it. Keep the compatibility declaration compiler-scoped so
// Visual Studio continues to use the Windows SDK's authoritative definition.
#if defined(__MINGW32__) && !defined(__ICredentialProviderSetUserArray_INTERFACE_DEFINED__)
#define __ICredentialProviderSetUserArray_INTERFACE_DEFINED__
MIDL_INTERFACE("095C1484-1C0C-4388-9C6D-500E61BF84BD")
ICredentialProviderSetUserArray : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE SetUserArray(
        ICredentialProviderUserArray* users) = 0;
};
static const IID IID_ICredentialProviderSetUserArray =
    {0x095c1484, 0x1c0c, 0x4388, {0x9c, 0x6d, 0x50, 0x0e, 0x61, 0xbf, 0x84, 0xbd}};
#endif

class WardenCredential;

class WardenProvider final : public ICredentialProvider, public ICredentialProviderSetUserArray
{
public:
    WardenProvider();
    ~WardenProvider();

    IFACEMETHODIMP QueryInterface(REFIID riid, void** object) override;
    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;

    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, DWORD flags) override;
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization) override;
    IFACEMETHODIMP Advise(ICredentialProviderEvents* events, UINT_PTR context) override;
    IFACEMETHODIMP UnAdvise() override;
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* count) override;
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD index, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** descriptor) override;
    IFACEMETHODIMP GetCredentialCount(DWORD* count, DWORD* defaultCredential, BOOL* autoLogon) override;
    IFACEMETHODIMP GetCredentialAt(DWORD index, ICredentialProviderCredential** credential) override;
    IFACEMETHODIMP SetUserArray(ICredentialProviderUserArray* users) override;

private:
    LONG references_;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario_;
    WardenCredential* credential_;
};
