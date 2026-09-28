#include "BrokerClient.h"

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace
{
constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\WardenIdentityBroker.v1";
constexpr DWORD kPipeWaitMs = 5000;
constexpr uint32_t kMaxFrame = 8 * 1024;

bool WriteExact(HANDLE pipe, const void* data, DWORD size)
{
    const auto* cursor = static_cast<const BYTE*>(data);
    DWORD remaining = size;
    while (remaining > 0)
    {
        DWORD written = 0;
        if (!WriteFile(pipe, cursor, remaining, &written, nullptr) || written == 0)
        {
            return false;
        }
        cursor += written;
        remaining -= written;
    }
    return true;
}

bool ReadExact(HANDLE pipe, void* data, DWORD size)
{
    auto* cursor = static_cast<BYTE*>(data);
    DWORD remaining = size;
    while (remaining > 0)
    {
        DWORD read = 0;
        if (!ReadFile(pipe, cursor, remaining, &read, nullptr) || read == 0)
        {
            return false;
        }
        cursor += read;
        remaining -= read;
    }
    return true;
}

std::string Utf8FromWide(const std::wstring& value)
{
    if (value.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string result(static_cast<size_t>(size), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), result.data(), size, nullptr, nullptr) != size)
    {
        SecureZeroMemory(result.data(), result.size());
        return {};
    }
    return result;
}

std::wstring WideFromUtf8(const std::string& value)
{
    if (value.empty()) return {};
    int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0);
    if (size <= 0) return {};
    std::wstring result(static_cast<size_t>(size), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), result.data(), size) != size)
    {
        return {};
    }
    return result;
}

std::string JsonEscape(const std::string& value)
{
    static constexpr char hex[] = "0123456789abcdef";
    std::string output;
    output.reserve(value.size() + 8);
    for (unsigned char ch : value)
    {
        switch (ch)
        {
        case '"': output += "\\\""; break;
        case '\\': output += "\\\\"; break;
        case '\b': output += "\\b"; break;
        case '\f': output += "\\f"; break;
        case '\n': output += "\\n"; break;
        case '\r': output += "\\r"; break;
        case '\t': output += "\\t"; break;
        default:
            if (ch < 0x20)
            {
                output += "\\u00";
                output.push_back(hex[(ch >> 4) & 0xf]);
                output.push_back(hex[ch & 0xf]);
            }
            else
            {
                output.push_back(static_cast<char>(ch));
            }
        }
    }
    return output;
}

bool ExtractJsonString(const std::string& json, const char* name, std::string* value)
{
    const std::string needle = std::string("\"") + name + "\":\"";
    size_t cursor = json.find(needle);
    if (cursor == std::string::npos) return false;
    cursor += needle.size();
    std::string output;
    while (cursor < json.size())
    {
        char ch = json[cursor++];
        if (ch == '"')
        {
            *value = output;
            return true;
        }
        if (ch != '\\')
        {
            output.push_back(ch);
            continue;
        }
        if (cursor >= json.size()) return false;
        char escaped = json[cursor++];
        switch (escaped)
        {
        case '"': output.push_back('"'); break;
        case '\\': output.push_back('\\'); break;
        case '/': output.push_back('/'); break;
        case 'b': output.push_back('\b'); break;
        case 'f': output.push_back('\f'); break;
        case 'n': output.push_back('\n'); break;
        case 'r': output.push_back('\r'); break;
        case 't': output.push_back('\t'); break;
        default: return false;
        }
    }
    return false;
}

BrokerAuthenticationResult Failure(const wchar_t* message)
{
    BrokerAuthenticationResult result;
    result.message = message;
    return result;
}
}

BrokerAuthenticationResult AuthenticateWithWardenBroker(
    const std::wstring& username,
    const std::wstring& password)
{
    if (username.empty() || username.size() > 254 || password.empty() || password.size() > 128)
    {
        return Failure(L"Enter your Warden email and password.");
    }

    std::string userUtf8 = Utf8FromWide(username);
    std::string passwordUtf8 = Utf8FromWide(password);
    if (userUtf8.empty() || passwordUtf8.empty())
    {
        SecureZeroMemory(passwordUtf8.data(), passwordUtf8.size());
        return Failure(L"The sign-in details contain unsupported characters.");
    }
    std::string escapedPassword = JsonEscape(passwordUtf8);
    SecureZeroMemory(passwordUtf8.data(), passwordUtf8.size());
    std::string request;
    request.reserve(userUtf8.size() + escapedPassword.size() + 48);
    request.append("{\"version\":1,\"username\":\"");
    request.append(JsonEscape(userUtf8));
    request.append("\",\"password\":\"");
    request.append(escapedPassword);
    request.append("\"}");
    SecureZeroMemory(escapedPassword.data(), escapedPassword.size());
    if (request.size() > kMaxFrame)
    {
        SecureZeroMemory(request.data(), request.size());
        return Failure(L"The sign-in request is too large.");
    }

    if (!WaitNamedPipeW(kPipeName, kPipeWaitMs))
    {
        SecureZeroMemory(request.data(), request.size());
        return Failure(L"The Warden service is unavailable. Use another sign-in option.");
    }
    HANDLE pipe = CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (pipe == INVALID_HANDLE_VALUE)
    {
        SecureZeroMemory(request.data(), request.size());
        return Failure(L"The Warden service is unavailable. Use another sign-in option.");
    }

    uint32_t requestSize = static_cast<uint32_t>(request.size());
    bool sent = WriteExact(pipe, &requestSize, sizeof(requestSize)) &&
        WriteExact(pipe, request.data(), requestSize);
    SecureZeroMemory(request.data(), request.size());
    if (!sent)
    {
        CloseHandle(pipe);
        return Failure(L"Warden could not process the sign-in request.");
    }

    uint32_t responseSize = 0;
    if (!ReadExact(pipe, &responseSize, sizeof(responseSize)) ||
        responseSize == 0 || responseSize > kMaxFrame)
    {
        CloseHandle(pipe);
        return Failure(L"Warden returned an invalid response.");
    }
    std::string response(responseSize, '\0');
    bool received = ReadExact(pipe, response.data(), responseSize);
    CloseHandle(pipe);
    if (!received)
    {
        SecureZeroMemory(response.data(), response.size());
        return Failure(L"Warden could not verify this sign-in.");
    }

    BrokerAuthenticationResult result;
    result.success = response.find("\"ok\":true") != std::string::npos;
    std::string field;
    if (result.success && ExtractJsonString(response, "username", &field))
    {
        result.username = WideFromUtf8(field);
    }
    field.clear();
    if (result.success && ExtractJsonString(response, "local_password", &field))
    {
        result.localPassword = WideFromUtf8(field);
        SecureZeroMemory(field.data(), field.size());
        field.clear();
    }
    if (!result.success && ExtractJsonString(response, "message", &field))
    {
        result.message = WideFromUtf8(field);
    }
    SecureZeroMemory(response.data(), response.size());
    if (result.success && (result.username.empty() || result.localPassword.empty()))
    {
        result.success = false;
        result.message = L"Warden returned an invalid account.";
    }
    if (!result.success && result.message.empty())
    {
        result.message = L"Warden could not verify this sign-in.";
    }
    return result;
}
