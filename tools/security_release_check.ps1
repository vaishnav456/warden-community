param(
    [string]$EvidenceRoot = ""
)

$ErrorActionPreference = "Stop"
$repository = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
if (-not $EvidenceRoot) {
    $EvidenceRoot = Join-Path $repository "artifacts\security\$stamp"
}
New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null

function Run-Evidence([string]$Name, [scriptblock]$Command) {
    $path = Join-Path $EvidenceRoot "$Name.txt"
    & $Command 2>&1 | Tee-Object -FilePath $path
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed; see $path"
    }
}

Push-Location $repository
try {
    docker compose build warden-server build-service
    if ($LASTEXITCODE -ne 0) { throw "Community image build failed" }
    Run-Evidence "server-tests" {
        docker run --rm `
            -e SUPABASE_URL=http://postgrest:3000 `
            -e SUPABASE_SERVICE_KEY=test-only-service-key `
            -e SECRET_KEY=test-only-not-a-production-secret `
            -e BUILD_SERVICE_KEY=test-only-build-service-key `
            -e ED25519_PRIVATE_KEY_B64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= `
            -e TENANT_MASTER_KEK_B64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= `
            -e DEVICE_CA_DIR=/tmp/warden-test-device-ca `
            -e DEVICE_CA_AUTO_BOOTSTRAP=true `
            -e PYTHONPATH=/workspace/server:/workspace/tools `
            --tmpfs /workspace/tmp:size=64m,mode=1777 `
            -v "${repository}:/workspace:ro" -w /workspace/server `
            warden-community-server:local python -m unittest discover -s tests -q
    }
    Run-Evidence "python-dependencies" { docker run --rm --user 0 warden-community-server:local sh -c "pip install -q pip-audit && pip-audit -r requirements.txt" }
    Run-Evidence "build-service-dependencies" { docker run --rm --user 0 warden-community-build-service:local sh -c "pip install -q --break-system-packages pip-audit && pip-audit --local" }
    Run-Evidence "static-analysis" { docker run --rm --user 0 warden-community-server:local sh -c "pip install -q bandit && bandit -q -r /app -x /app/tests -lll" }
    # Dependency-only mode is intentional: agent-go is Windows-targeted and a
    # Linux scanner cannot load its syscall packages for call-graph analysis.
    # Windows cross-compilation below validates the actual target build.
    Run-Evidence "go-dependencies" { docker run --rm -v "${repository}:/src" ghcr.io/google/osv-scanner:latest scan source --config /src/osv-scanner.toml --no-call-analysis=go --recursive /src/agent-go /src/agent-posix /src/home-node }
    Run-Evidence "windows-agent-build" { docker run --rm -e GOOS=windows -e GOARCH=amd64 -v "${repository}\agent-go:/src" -w /src golang:1.27 go test -c -o /tmp/warden-agent.test.exe . }
    Run-Evidence "posix-agent-tests" { docker run --rm -v "${repository}\agent-posix:/src" -w /src golang:1.27 go test ./... }
    Run-Evidence "home-node-tests" { docker run --rm -v "${repository}\home-node:/src" -w /src golang:1.27 go test ./... }

    docker run --rm --user 0 -v "${EvidenceRoot}:/out" warden-community-server:local sh -c "pip install -q cyclonedx-bom && cyclonedx-py requirements requirements.txt --output-format JSON --output-file /out/server-python.cdx.json"
    if ($LASTEXITCODE -ne 0) { throw "Python SBOM generation failed" }
    docker run --rm --user 0 -v "${EvidenceRoot}:/out" warden-community-build-service:local sh -c "pip install -q --break-system-packages cyclonedx-bom && cyclonedx-py requirements requirements.txt --output-format JSON --output-file /out/build-service-python.cdx.json"
    if ($LASTEXITCODE -ne 0) { throw "Build-service SBOM generation failed" }
    docker run --rm -v "${repository}:/src" -v "${EvidenceRoot}:/out" -w /src golang:1.27 sh -c "go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest && cyclonedx-gomod mod -json -output /out/windows-agent.cdx.json /src/agent-go && cyclonedx-gomod mod -json -output /out/posix-agent.cdx.json /src/agent-posix && cyclonedx-gomod mod -json -output /out/home-node.cdx.json /src/home-node"
    if ($LASTEXITCODE -ne 0) { throw "Go SBOM generation failed" }

    docker image inspect warden-community-server:local | ConvertTo-Json -Depth 20 | Set-Content -Encoding utf8 (Join-Path $EvidenceRoot "server-image-metadata.json")
    docker image inspect warden-community-build-service:local | ConvertTo-Json -Depth 20 | Set-Content -Encoding utf8 (Join-Path $EvidenceRoot "build-image-metadata.json")
    Get-FileHash -Algorithm SHA256 (Join-Path $repository "server\requirements.txt"), (Join-Path $repository "agent-go\go.mod"), (Join-Path $repository "agent-go\go.sum"), (Join-Path $repository "home-node\go.mod"), (Join-Path $repository "home-node\go.sum") |
        ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $EvidenceRoot "dependency-manifest-hashes.json")
    git rev-parse HEAD | Set-Content -Encoding ascii (Join-Path $EvidenceRoot "commit.txt")
    Write-Host "Security release evidence written to $EvidenceRoot"
}
finally {
    Pop-Location
}
