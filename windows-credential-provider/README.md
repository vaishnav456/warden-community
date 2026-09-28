# Warden Credential Provider

This x64 Windows V2 Credential Provider adds a **Warden sign-in** tile for
logon and workstation unlock. It does not install a Credential Provider
filter and never disables Microsoft's built-in password provider.

Authentication flow:

1. LogonUI collects the Warden username and password in this provider.
2. The provider sends one bounded request to
   `\\.\pipe\WardenIdentityBroker.v1`.
3. The Warden Agent service owns that SYSTEM-only pipe and authenticates the
   identity through its existing mTLS and TLS-pinned server connection.
4. On success, the SYSTEM broker returns that endpoint's DPAPI-protected,
   randomly generated shadow credential over the SYSTEM-only named pipe.
5. The provider serializes the shadow credential for the matching local
   Windows account. Windows LSA performs the final authentication.

The provider does not persist credentials and has no direct network client.
The reusable Warden password is never used as a Windows local-account
password and is never included in an endpoint provisioning job.
The current milestone is online authentication only; an offline verifier must
not be added until its expiry, revocation, rollback, and machine-bound key
design have been reviewed and tested.

## Build

Build `WardenCredentialProvider.vcxproj` as `Release|x64` using Visual Studio
2022 Community with Desktop development with C++ and a Windows 10/11 SDK.
From an elevated PowerShell prompt, run `Build-CredentialProvider.ps1`. It
places the official-SDK build at `dist\WardenCredentialProvider.dll`; the
Linux build service then signs that exact DLL, embeds its SHA-256 into the
agent, and packages both files together. Windows installer builds fail closed
when this artifact is absent or does not match the embedded hash.

## Safe VM test

1. Keep a separate local administrator and a VM snapshot.
2. Install and start a Warden Agent build containing `identity_broker.go`.
3. Run `Register-WardenCredentialProvider.ps1` as administrator with the built
   DLL path.
4. Lock (do not initially sign out) and verify both the Warden tile and the
   normal Windows password tile remain available.
5. Use `Unregister-WardenCredentialProvider.ps1` for rollback.

Production packages must Authenticode-sign the DLL and scripts. The register
script accepts an unsigned DLL only for the isolated development VM.
