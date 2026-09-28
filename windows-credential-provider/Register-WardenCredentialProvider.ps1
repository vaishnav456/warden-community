#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$DllPath
)

$ErrorActionPreference = 'Stop'
$clsid = '{7C0EAF41-2D67-4F6B-A562-6BF97BD19EE1}'
$installDir = Join-Path $env:ProgramFiles 'Warden\CredentialProvider'
$resolvedDll = (Resolve-Path -LiteralPath $DllPath).Path
$hash = (Get-FileHash -LiteralPath $resolvedDll -Algorithm SHA256).Hash.ToLowerInvariant()
$installedDll = Join-Path $installDir "WardenCredentialProvider-$($hash.Substring(0, 16)).dll"
$providerKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid"
$comKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\$clsid"

New-Item -ItemType Directory -Path $installDir -Force | Out-Null
if (-not (Test-Path -LiteralPath $installedDll -PathType Leaf)) {
    Copy-Item -LiteralPath $resolvedDll -Destination $installedDll
}

$signature = Get-AuthenticodeSignature -LiteralPath $installedDll
if ($signature.Status -notin @('Valid', 'NotSigned')) {
    throw "Credential Provider signature is invalid: $($signature.Status)"
}

New-Item -Path $providerKey -Force | Out-Null
Set-Item -Path $providerKey -Value 'Warden Credential Provider'
New-Item -Path $comKey -Force | Out-Null
Set-Item -Path $comKey -Value 'Warden Credential Provider'
New-Item -Path (Join-Path $comKey 'InprocServer32') -Force | Out-Null
Set-Item -Path (Join-Path $comKey 'InprocServer32') -Value $installedDll
New-ItemProperty -Path (Join-Path $comKey 'InprocServer32') -Name ThreadingModel -Value Apartment -PropertyType String -Force | Out-Null

Get-ChildItem -LiteralPath $installDir -Filter 'WardenCredentialProvider*.dll' -File |
    Where-Object { $_.FullName -ne $installedDll } |
    Remove-Item -Force -ErrorAction SilentlyContinue

Write-Output "Registered Warden Credential Provider at $installedDll"
Write-Output 'The built-in Windows providers were not changed.'
