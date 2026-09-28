#pragma once

#include <string>

struct BrokerAuthenticationResult
{
    bool success = false;
    std::wstring username;
    std::wstring localPassword;
    std::wstring message;
};

BrokerAuthenticationResult AuthenticateWithWardenBroker(
    const std::wstring& username,
    const std::wstring& password);
