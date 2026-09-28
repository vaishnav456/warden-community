$ErrorActionPreference = 'Stop'
$output = Join-Path $PSScriptRoot 'dist'
New-Item -ItemType Directory -Force -Path $output | Out-Null
Push-Location $PSScriptRoot
try {
    $env:CGO_ENABLED = '0'
    $env:GOOS = 'windows'; $env:GOARCH = 'amd64'
    go build -trimpath -ldflags '-s -w' -o (Join-Path $output 'warden-home-node-windows-amd64.exe') .
    $env:GOOS = 'linux'; $env:GOARCH = 'amd64'
    go build -trimpath -ldflags '-s -w' -o (Join-Path $output 'warden-home-node-linux-amd64') .
} finally {
    Pop-Location
}
