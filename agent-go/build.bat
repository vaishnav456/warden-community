@echo off
setlocal EnableDelayedExpansion

echo ===================================================
echo  Warden Agent Go Build Script
echo ===================================================
echo.

:: ── 1. Check Go is installed ─────────────────────────────────────────────────
where go >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Go is not on PATH.
    echo Download and install from: https://go.dev/dl/
    echo Then add to PATH, e.g.: C:\Program Files\Go\bin
    exit /b 1
)
for /f "tokens=3" %%v in ('go version') do set GO_VER=%%v
echo [OK] Go found: %GO_VER%

:: ── 2. Verify minimum Go version (1.27+) ─────────────────────────────────────
for /f "tokens=2 delims=." %%v in ("%GO_VER:go=%") do set GO_MINOR=%%v
if %GO_MINOR% LSS 27 (
    echo [ERROR] Go 1.27+ is required. You have %GO_VER%.
    exit /b 1
)

:: ── 3. Set build environment ──────────────────────────────────────────────────
set GOOS=windows
set GOARCH=amd64
set CGO_ENABLED=0

if "%WARDEN_SERVER_URL%"=="" set WARDEN_SERVER_URL=https://warden.example.com
if "%WARDEN_SERVER_ED25519_PUBKEY%"=="" (
    echo [ERROR] WARDEN_SERVER_ED25519_PUBKEY is required for build-time command-signing pinning.
    exit /b 1
)
if "%WARDEN_CERT_FINGERPRINT%"=="" (
    echo [ERROR] WARDEN_CERT_FINGERPRINT is required for build-time TLS pinning.
    exit /b 1
)

echo [INFO] GOOS=%GOOS%  GOARCH=%GOARCH%  CGO_ENABLED=%CGO_ENABLED%
set WARDEN_REQUIRE_AUTHENTICODE=false
if not "%WARDEN_SIGN_CERT_THUMBPRINT%"=="" set WARDEN_REQUIRE_AUTHENTICODE=true
if not "%WARDEN_SIGN_PFX_PATH%"=="" set WARDEN_REQUIRE_AUTHENTICODE=true
echo.

:: ── 4. Download dependencies ──────────────────────────────────────────────────
echo [INFO] Downloading Go module dependencies...
go mod tidy
if errorlevel 1 (
    echo [ERROR] go mod tidy failed. Check your internet connection.
    exit /b 1
)
go mod download
if errorlevel 1 (
    echo [ERROR] go mod download failed.
    exit /b 1
)
echo [OK] Dependencies ready.
echo.

:: ── 5. Create output directory ────────────────────────────────────────────────
if not exist "dist" mkdir dist

:: ── 6. Build the agent ────────────────────────────────────────────────────────
echo [INFO] Building warden-agent.exe...
go build -v ^
    -ldflags="-H windowsgui -s -w -X main.buildServerURL=%WARDEN_SERVER_URL% -X main.buildServerEd25519Pubkey=%WARDEN_SERVER_ED25519_PUBKEY% -X main.buildCertFingerprint=%WARDEN_CERT_FINGERPRINT% -X main.buildRequireAuthenticode=%WARDEN_REQUIRE_AUTHENTICODE%" ^
    -o dist\warden-agent.exe ^
    .
if errorlevel 1 (
    echo [ERROR] Build failed.
    exit /b 1
)

echo.
echo [OK] Build successful!
echo Output: %CD%\dist\warden-agent.exe

:: ── 7. Code signing (optional) ────────────────────────────────────────────────
:: Set WARDEN_SIGN_CERT_THUMBPRINT (cert already imported into this
:: machine's certificate store — preferred, no password sits in the
:: environment) to sign automatically. Falls back to WARDEN_SIGN_PFX_PATH +
:: WARDEN_SIGN_PFX_PASSWORD for a raw .pfx file instead. Skipped entirely
:: if neither is set — the exe just ships unsigned, same as before. Note:
:: the applocker-pin-warden-publisher policy template (see
:: agent-go/POLICY_ASSETS.md) requires a real signing cert to be meaningful.
if not "%WARDEN_SIGN_CERT_THUMBPRINT%"=="" (
    echo.
    echo [INFO] Signing with cert thumbprint %WARDEN_SIGN_CERT_THUMBPRINT%...
    where signtool >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] signtool not found on PATH ^(install the Windows SDK^).
        exit /b 1
    )
    signtool sign /sha1 %WARDEN_SIGN_CERT_THUMBPRINT% /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 dist\warden-agent.exe
    if errorlevel 1 (
        echo [ERROR] signtool sign failed.
        exit /b 1
    )
    signtool verify /pa /all /v dist\warden-agent.exe
    if errorlevel 1 exit /b 1
    echo [OK] Signed.
) else if not "%WARDEN_SIGN_PFX_PATH%"=="" (
    echo.
    echo [INFO] Signing with pfx %WARDEN_SIGN_PFX_PATH%...
    where signtool >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] signtool not found on PATH ^(install the Windows SDK^).
        exit /b 1
    )
    signtool sign /f "%WARDEN_SIGN_PFX_PATH%" /p "%WARDEN_SIGN_PFX_PASSWORD%" /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 dist\warden-agent.exe
    if errorlevel 1 (
        echo [ERROR] signtool sign failed.
        exit /b 1
    )
    signtool verify /pa /all /v dist\warden-agent.exe
    if errorlevel 1 exit /b 1
    echo [OK] Signed.
) else (
    echo.
    echo [WARN] No signing cert configured ^(WARDEN_SIGN_CERT_THUMBPRINT / WARDEN_SIGN_PFX_PATH^) — shipping UNSIGNED.
    echo        See agent-go/POLICY_ASSETS.md re: applocker-pin-warden-publisher.
)

:: Show file size
for %%f in (dist\warden-agent.exe) do (
    set SIZE=%%~zf
    set /a SIZE_MB=!SIZE! / 1048576
    echo Size:   !SIZE_MB! MB  (!SIZE! bytes)
)

echo.
echo ===================================================
echo  Service management:
echo    dist\warden-agent.exe install   - Install Windows service
echo    dist\warden-agent.exe start     - Start service
echo    dist\warden-agent.exe stop      - Stop service
echo    dist\warden-agent.exe remove    - Remove service
echo.
echo  Standalone (with enrollment):
echo    set WARDEN_ENROLLMENT_TOKEN=your-token
echo    Trust pins must be supplied at build time; runtime enrollment cannot replace them.
echo    dist\warden-agent.exe
echo ===================================================

endlocal
