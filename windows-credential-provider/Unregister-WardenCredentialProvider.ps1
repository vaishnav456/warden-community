#Requires -RunAsAdministrator
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$clsid = '{7C0EAF41-2D67-4F6B-A562-6BF97BD19EE1}'
$providerKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid"
$comKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\$clsid"
$installDir = Join-Path $env:ProgramFiles 'Warden\CredentialProvider'

Remove-Item -LiteralPath $providerKey -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $comKey -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem -LiteralPath $installDir -Filter 'WardenCredentialProvider*.dll' -File -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue
Write-Output 'Unregistered Warden Credential Provider. Reboot before deleting the DLL if LogonUI has loaded it.'
