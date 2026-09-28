[CmdletBinding()]
param(
    [string]$Configuration = "Release",
    [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"
$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$project = Join-Path $projectDir "WardenCredentialProvider.vcxproj"
$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw "Visual Studio Installer (vswhere.exe) was not found. Install Visual Studio 2022 Community with Desktop development with C++."
}
$msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe | Select-Object -First 1
if (-not $msbuild) {
    throw "MSBuild was not found. Install the Visual Studio 2022 C++ workload and Windows SDK."
}
& $msbuild $project /m /t:Rebuild "/p:Configuration=$Configuration" "/p:Platform=$Platform"
if ($LASTEXITCODE -ne 0) { throw "Credential Provider build failed with exit code $LASTEXITCODE" }

$built = Join-Path $projectDir "$Platform\$Configuration\WardenCredentialProvider.dll"
if (-not (Test-Path -LiteralPath $built)) { throw "Expected build output was not found: $built" }
$dist = Join-Path $projectDir "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null
$destination = Join-Path $dist "WardenCredentialProvider.dll"
Copy-Item -LiteralPath $built -Destination $destination -Force
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $destination).Hash.ToLowerInvariant()
Write-Host "Credential Provider ready: $destination"
Write-Host "SHA-256: $hash"
