#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif

#include "Credential.h"
#include "BrokerClient.h"
#include "ComHelpers.h"
#include "Dll.h"
#include "Guid.h"

#include <windows.h>
#include <wincred.h>
#include <ntsecapi.h>
#include <security.h>
#include <shlwapi.h>
#include <limits>
#include <new>
#include <string>
#include <vector>

namespace
{
HRESULT RetrieveNegotiateAuthPackage(ULONG* package)
{
    if (package == nullptr) return E_INVALIDARG;
    HANDLE lsa = nullptr;
    NTSTATUS status = LsaConnectUntrusted(&lsa);
    if (status != STATUS_SUCCESS) return HRESULT_FROM_WIN32(LsaNtStatusToWinError(status));
    const char name[] = NEGOSSP_NAME_A;
    LSA_STRING packageName{};
    packageName.Buffer = const_cast<PCHAR>(name);
    packageName.Length = static_cast<USHORT>(sizeof(name) - 1);
    packageName.MaximumLength = static_cast<USHORT>(sizeof(name));
    status = LsaLookupAuthenticationPackage(lsa, &packageName, package);
    LsaDeregisterLogonProcess(lsa);
    return status == STATUS_SUCCESS ? S_OK : HRESULT_FROM_WIN32(LsaNtStatusToWinError(status));
}

HRESULT ProtectPassword(PCWSTR password, CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, std::wstring* protectedPassword)
{
    if (password == nullptr || protectedPassword == nullptr) return E_INVALIDARG;
    if (*password == L'\0')
    {
        protectedPassword->clear();
        return S_OK;
    }
    std::vector<wchar_t> input(password, password + wcslen(password) + 1);
    CRED_PROTECTION_TYPE protection = CredUnprotected;
    if (CredIsProtectedW(input.data(), &protection) && protection != CredUnprotected)
    {
        *protectedPassword = input.data();
        SecureZeroMemory(input.data(), input.size() * sizeof(wchar_t));
        return S_OK;
    }
    if (scenario == CPUS_CREDUI)
    {
        *protectedPassword = input.data();
        SecureZeroMemory(input.data(), input.size() * sizeof(wchar_t));
        return S_OK;
    }
    DWORD required = 0;
    CredProtectW(FALSE, input.data(), static_cast<DWORD>(input.size()), nullptr, &required, nullptr);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || required == 0)
    {
        SecureZeroMemory(input.data(), input.size() * sizeof(wchar_t));
        return HRESULT_FROM_WIN32(GetLastError());
    }
    std::vector<wchar_t> output(required);
    if (!CredProtectW(FALSE, input.data(), static_cast<DWORD>(input.size()),
        output.data(), &required, nullptr))
    {
        DWORD error = GetLastError();
        SecureZeroMemory(input.data(), input.size() * sizeof(wchar_t));
        SecureZeroMemory(output.data(), output.size() * sizeof(wchar_t));
        return HRESULT_FROM_WIN32(error);
    }
    *protectedPassword = output.data();
    SecureZeroMemory(input.data(), input.size() * sizeof(wchar_t));
    SecureZeroMemory(output.data(), output.size() * sizeof(wchar_t));
    return S_OK;
}

HRESULT InitUnicodeString(const std::wstring& value, UNICODE_STRING* destination)
{
    size_t bytes = value.size() * sizeof(wchar_t);
    if (bytes > std::numeric_limits<USHORT>::max()) return HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW);
    destination->Length = static_cast<USHORT>(bytes);
    destination->MaximumLength = static_cast<USHORT>(bytes + sizeof(wchar_t));
    destination->Buffer = const_cast<PWSTR>(value.c_str());
    return S_OK;
}

HRESULT PackInteractiveLogon(
    const std::wstring& domain,
    const std::wstring& username,
    const std::wstring& password,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario,
    BYTE** packed,
    DWORD* packedSize)
{
    if (packed == nullptr || packedSize == nullptr) return E_INVALIDARG;
    *packed = nullptr;
    *packedSize = 0;
    KERB_INTERACTIVE_UNLOCK_LOGON input{};
    input.Logon.MessageType = scenario == CPUS_UNLOCK_WORKSTATION
        ? KerbWorkstationUnlockLogon : KerbInteractiveLogon;
    HRESULT hr = InitUnicodeString(domain, &input.Logon.LogonDomainName);
    if (SUCCEEDED(hr)) hr = InitUnicodeString(username, &input.Logon.UserName);
    if (SUCCEEDED(hr)) hr = InitUnicodeString(password, &input.Logon.Password);
    if (FAILED(hr)) return hr;

    size_t total = sizeof(input) + input.Logon.LogonDomainName.MaximumLength +
        input.Logon.UserName.MaximumLength + input.Logon.Password.MaximumLength;
    if (total > std::numeric_limits<DWORD>::max()) return E_OUTOFMEMORY;
    auto* buffer = static_cast<BYTE*>(CoTaskMemAlloc(total));
    if (buffer == nullptr) return E_OUTOFMEMORY;
    ZeroMemory(buffer, total);
    auto* output = reinterpret_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(buffer);
    *output = input;
    size_t cursor = sizeof(input);
    auto pack = [&](UNICODE_STRING* target, const std::wstring& value)
    {
        size_t bytes = value.size() * sizeof(wchar_t);
        if (bytes > 0) CopyMemory(buffer + cursor, value.data(), bytes);
        target->Buffer = reinterpret_cast<PWSTR>(static_cast<ULONG_PTR>(cursor));
        cursor += target->MaximumLength;
    };
    pack(&output->Logon.LogonDomainName, domain);
    pack(&output->Logon.UserName, username);
    pack(&output->Logon.Password, password);
    *packed = buffer;
    *packedSize = static_cast<DWORD>(total);
    return S_OK;
}
}

WardenCredential::WardenCredential()
    : references_(1), scenario_(CPUS_INVALID), events_(nullptr), values_{}
{
    DllAddRef();
}

WardenCredential::~WardenCredential()
{
    ClearPassword();
    for (PWSTR& value : values_)
    {
        CoTaskMemFree(value);
        value = nullptr;
    }
    if (events_ != nullptr) events_->Release();
    DllRelease();
}

HRESULT WardenCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario)
{
    scenario_ = scenario;
    HRESULT hr = SHStrDupW(L"Sign in with Warden", &values_[WFI_TITLE]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"", &values_[WFI_USERNAME]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"", &values_[WFI_PASSWORD]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Use your organization email and Warden password", &values_[WFI_STATUS]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Sign in", &values_[WFI_SUBMIT]);
    return hr;
}

HRESULT WardenCredential::QueryInterface(REFIID riid, void** object)
{
    if (object == nullptr) return E_INVALIDARG;
    *object = nullptr;
    if (riid != IID_IUnknown && riid != IID_ICredentialProviderCredential) return E_NOINTERFACE;
    *object = static_cast<ICredentialProviderCredential*>(this);
    AddRef();
    return S_OK;
}

ULONG WardenCredential::AddRef() { return InterlockedIncrement(&references_); }
ULONG WardenCredential::Release()
{
    LONG value = InterlockedDecrement(&references_);
    if (value == 0) delete this;
    return value;
}

HRESULT WardenCredential::Advise(ICredentialProviderCredentialEvents* events)
{
    if (events_ != nullptr) events_->Release();
    events_ = events;
    if (events_ != nullptr) events_->AddRef();
    return S_OK;
}

HRESULT WardenCredential::UnAdvise()
{
    if (events_ != nullptr) events_->Release();
    events_ = nullptr;
    return S_OK;
}

HRESULT WardenCredential::SetSelected(BOOL* autoLogon)
{
    if (autoLogon == nullptr) return E_INVALIDARG;
    *autoLogon = FALSE;
    return S_OK;
}

void WardenCredential::ClearPassword()
{
    if (values_[WFI_PASSWORD] != nullptr)
    {
        SecureZeroMemory(values_[WFI_PASSWORD], wcslen(values_[WFI_PASSWORD]) * sizeof(wchar_t));
    }
}

HRESULT WardenCredential::SetDeselected()
{
    ClearPassword();
    HRESULT hr = ReplaceCoTaskMemString(&values_[WFI_PASSWORD], L"");
    if (SUCCEEDED(hr) && events_ != nullptr)
    {
        events_->SetFieldString(this, WFI_PASSWORD, L"");
    }
    return hr;
}

HRESULT WardenCredential::GetFieldState(DWORD fieldId, CREDENTIAL_PROVIDER_FIELD_STATE* state,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactiveState)
{
    if (fieldId >= WFI_NUM_FIELDS || state == nullptr || interactiveState == nullptr) return E_INVALIDARG;
    *state = kWardenFieldStates[fieldId].state;
    *interactiveState = kWardenFieldStates[fieldId].interactiveState;
    return S_OK;
}

HRESULT WardenCredential::GetStringValue(DWORD fieldId, PWSTR* value)
{
    if (fieldId >= WFI_NUM_FIELDS || value == nullptr) return E_INVALIDARG;
    return SHStrDupW(values_[fieldId] != nullptr ? values_[fieldId] : L"", value);
}

HRESULT WardenCredential::GetBitmapValue(DWORD, HBITMAP*) { return E_NOTIMPL; }
HRESULT WardenCredential::GetCheckboxValue(DWORD, BOOL*, PWSTR*) { return E_NOTIMPL; }

HRESULT WardenCredential::GetSubmitButtonValue(DWORD fieldId, DWORD* adjacentTo)
{
    if (fieldId != WFI_SUBMIT || adjacentTo == nullptr) return E_INVALIDARG;
    *adjacentTo = WFI_PASSWORD;
    return S_OK;
}

HRESULT WardenCredential::GetComboBoxValueCount(DWORD, DWORD*, DWORD*) { return E_NOTIMPL; }
HRESULT WardenCredential::GetComboBoxValueAt(DWORD, DWORD, PWSTR*) { return E_NOTIMPL; }

HRESULT WardenCredential::SetStringValue(DWORD fieldId, PCWSTR value)
{
    if (fieldId != WFI_USERNAME && fieldId != WFI_PASSWORD) return E_INVALIDARG;
    if (fieldId == WFI_PASSWORD) ClearPassword();
    return ReplaceCoTaskMemString(&values_[fieldId], value);
}

HRESULT WardenCredential::SetCheckboxValue(DWORD, BOOL) { return E_NOTIMPL; }
HRESULT WardenCredential::SetComboBoxSelectedValue(DWORD, DWORD) { return E_NOTIMPL; }
HRESULT WardenCredential::CommandLinkClicked(DWORD) { return E_NOTIMPL; }

HRESULT WardenCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization,
    PWSTR* optionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* optionalStatusIcon)
{
    if (response == nullptr || serialization == nullptr || optionalStatusText == nullptr || optionalStatusIcon == nullptr)
        return E_INVALIDARG;
    *response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    ZeroMemory(serialization, sizeof(*serialization));
    *optionalStatusText = nullptr;
    *optionalStatusIcon = CPSI_NONE;

    std::wstring username = values_[WFI_USERNAME] != nullptr ? values_[WFI_USERNAME] : L"";
    std::wstring password = values_[WFI_PASSWORD] != nullptr ? values_[WFI_PASSWORD] : L"";
    BrokerAuthenticationResult broker = AuthenticateWithWardenBroker(username, password);
    if (!broker.success)
    {
        SHStrDupW(broker.message.c_str(), optionalStatusText);
        *optionalStatusIcon = CPSI_ERROR;
        *response = CPGSR_NO_CREDENTIAL_FINISHED;
        SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
        ClearPassword();
        if (events_ != nullptr) events_->SetFieldString(this, WFI_PASSWORD, L"");
        return S_OK;
    }

    // The password typed into LogonUI is the reusable Warden credential and
    // is used only for online verification. Windows LSA receives a random,
    // device-specific shadow password held by the SYSTEM broker in DPAPI;
    // administrators therefore never need to know or redeploy the user's
    // Warden password when assigning another PC.
    std::wstring localPassword = broker.localPassword;
    SecureZeroMemory(broker.localPassword.data(), broker.localPassword.size() * sizeof(wchar_t));

    wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD computerNameLength = ARRAYSIZE(computerName);
    if (!GetComputerNameW(computerName, &computerNameLength))
    {
        DWORD error = GetLastError();
        SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
        SecureZeroMemory(localPassword.data(), localPassword.size() * sizeof(wchar_t));
        ClearPassword();
        if (events_ != nullptr) events_->SetFieldString(this, WFI_PASSWORD, L"");
        return HRESULT_FROM_WIN32(error);
    }
    std::wstring protectedPassword;
    HRESULT hr = ProtectPassword(localPassword.c_str(), scenario_, &protectedPassword);
    if (SUCCEEDED(hr))
    {
        hr = PackInteractiveLogon(computerName, broker.username, protectedPassword, scenario_,
            &serialization->rgbSerialization, &serialization->cbSerialization);
    }
    SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
    SecureZeroMemory(localPassword.data(), localPassword.size() * sizeof(wchar_t));
    SecureZeroMemory(protectedPassword.data(), protectedPassword.size() * sizeof(wchar_t));
    ClearPassword();
    if (events_ != nullptr) events_->SetFieldString(this, WFI_PASSWORD, L"");
    if (FAILED(hr)) return hr;
    hr = RetrieveNegotiateAuthPackage(&serialization->ulAuthenticationPackage);
    if (FAILED(hr))
    {
        SecureZeroMemory(serialization->rgbSerialization, serialization->cbSerialization);
        CoTaskMemFree(serialization->rgbSerialization);
        ZeroMemory(serialization, sizeof(*serialization));
        return hr;
    }
    serialization->clsidCredentialProvider = CLSID_WardenCredentialProvider;
    *response = CPGSR_RETURN_CREDENTIAL_FINISHED;
    return S_OK;
}

HRESULT WardenCredential::ReportResult(NTSTATUS, NTSTATUS, PWSTR* optionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* optionalStatusIcon)
{
    if (optionalStatusText != nullptr) *optionalStatusText = nullptr;
    if (optionalStatusIcon != nullptr) *optionalStatusIcon = CPSI_NONE;
    ClearPassword();
    return S_OK;
}
