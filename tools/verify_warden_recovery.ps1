param(
    [string]$PostgresContainer = "warden-postgres"
)

$ErrorActionPreference = "Stop"
$stamp = Get-Date -Format "yyyyMMddHHmmss"
$temporaryDatabase = "warden_restore_verify_$stamp"
$containerDump = "/tmp/warden-restore-$stamp.dump"
$evidenceDirectory = Join-Path $PSScriptRoot "..\artifacts\recovery"
$temporaryDump = Join-Path $evidenceDirectory "warden-restore-$stamp.dump"
$evidenceFile = Join-Path $evidenceDirectory "warden-restore-$stamp.json"
New-Item -ItemType Directory -Force -Path $evidenceDirectory | Out-Null

function Assert-LastCommand([string]$Step) {
    if ($LASTEXITCODE -ne 0) {
        throw "$Step failed with exit code $LASTEXITCODE"
    }
}

try {
    docker exec $PostgresContainer pg_dump -U warden_admin -d warden -Fc -f $containerDump
    Assert-LastCommand "Database backup"

    docker cp "${PostgresContainer}:${containerDump}" $temporaryDump
    Assert-LastCommand "Evidence copy"

    docker exec $PostgresContainer createdb -U warden_admin $temporaryDatabase
    Assert-LastCommand "Temporary restore database creation"

    docker exec $PostgresContainer pg_restore -U warden_admin -d $temporaryDatabase --exit-on-error $containerDump
    Assert-LastCommand "Database restore"

    $companyCount = docker exec $PostgresContainer psql -U warden_admin -d $temporaryDatabase -Atc "SELECT count(*) FROM endpt.companies"
    Assert-LastCommand "Restored database verification"
    if (-not ($companyCount -match '^\d+$')) {
        throw "Restored database verification returned an unexpected result"
    }

    $sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $temporaryDump).Hash.ToLowerInvariant()
    $evidenceName = Split-Path -Leaf $evidenceFile
    $evidence = "$evidenceName sha256=$sha256 companies=$companyCount"
    $safeEvidence = $evidence.Replace("'", "''")
    $recordSql = "INSERT INTO endpt.platform_recovery_checks(check_type,status,notes,evidence) VALUES ('restore_test','passed','Automated logical backup restored into an isolated temporary database and queried successfully.','$safeEvidence'); INSERT INTO endpt.audit_log(action,detail) VALUES ('automated_restore_test_completed', jsonb_build_object('evidence','$safeEvidence'));"
    docker exec $PostgresContainer psql -v ON_ERROR_STOP=1 -U warden_admin -d warden -c $recordSql
    Assert-LastCommand "Recovery evidence recording"

    [ordered]@{
        checked_at = (Get-Date).ToUniversalTime().ToString("o")
        status = "passed"
        source_database = "warden"
        isolated_restore_database = $temporaryDatabase
        company_rows_verified = [int]$companyCount
        backup_sha256 = $sha256
        raw_backup_retained = $false
    } | ConvertTo-Json | Set-Content -Encoding utf8 -LiteralPath $evidenceFile

    Write-Host "Restore verification passed. Evidence: $evidenceFile"
    Write-Host "SHA-256: $sha256"
}
finally {
    docker exec $PostgresContainer dropdb -U warden_admin --if-exists $temporaryDatabase 2>$null
    docker exec $PostgresContainer rm -f $containerDump 2>$null
    Remove-Item -LiteralPath $temporaryDump -Force -ErrorAction SilentlyContinue
}
