#include <windows.h>
#include <unknwn.h>
#include <new>
#include "Dll.h"
#include "Guid.h"

static LONG g_moduleReferences = 0;

void DllAddRef()
{
    InterlockedIncrement(&g_moduleReferences);
}

void DllRelease()
{
    InterlockedDecrement(&g_moduleReferences);
}

class WardenClassFactory final : public IClassFactory
{
public:
    WardenClassFactory() : references_(1) { DllAddRef(); }
    ~WardenClassFactory() { DllRelease(); }

    IFACEMETHODIMP QueryInterface(REFIID riid, void** object) override
    {
        if (object == nullptr)
        {
            return E_INVALIDARG;
        }
        *object = nullptr;
        if (riid == IID_IUnknown || riid == IID_IClassFactory)
        {
            *object = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    IFACEMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&references_); }
    IFACEMETHODIMP_(ULONG) Release() override
    {
        LONG value = InterlockedDecrement(&references_);
        if (value == 0)
        {
            delete this;
        }
        return value;
    }

    IFACEMETHODIMP CreateInstance(IUnknown* outer, REFIID riid, void** object) override
    {
        if (outer != nullptr)
        {
            return CLASS_E_NOAGGREGATION;
        }
        return WardenProviderCreateInstance(riid, object);
    }

    IFACEMETHODIMP LockServer(BOOL lock) override
    {
        lock ? DllAddRef() : DllRelease();
        return S_OK;
    }

private:
    LONG references_;
};

BOOL WINAPI DllMain(HINSTANCE, DWORD, void*)
{
    return TRUE;
}

STDAPI DllCanUnloadNow()
{
    return g_moduleReferences == 0 ? S_OK : S_FALSE;
}

STDAPI DllGetClassObject(REFCLSID clsid, REFIID riid, void** object)
{
    if (object == nullptr)
    {
        return E_INVALIDARG;
    }
    *object = nullptr;
    if (clsid != CLSID_WardenCredentialProvider)
    {
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    auto* factory = new (std::nothrow) WardenClassFactory();
    if (factory == nullptr)
    {
        return E_OUTOFMEMORY;
    }
    HRESULT hr = factory->QueryInterface(riid, object);
    factory->Release();
    return hr;
}
