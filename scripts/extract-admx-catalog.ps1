<#
.SYNOPSIS
  Extracts a clean, structured JSON summary of every Administrative Template
  policy defined in this machine's local ADMX/ADML files.

.DESCRIPTION
  Run this on a real Windows machine (any edition — the ADMX baseline ships
  with every Windows install at C:\Windows\PolicyDefinitions). Parses every
  .admx file plus its matching en-US .adml (for the human-readable display
  name/category), and emits one JSON object per policy with:

    - name / displayName / category
    - registry key path, value name
    - type: boolean | decimal | enum | text  (ADMX's own element types)
    - for decimal: min/max
    - for enum: the list of option labels + their underlying registry values
    - supportedOn: the raw ADMX "supported on" string (e.g.
      "SUPPORTED_Windows10" or "SUPPORTED_WindowsHome") — this is how ADMX
      itself encodes which Windows versions/editions a policy applies to,
      which is what the Warden policy catalog importer uses to label each
      setting's edition support (Home/Pro/Enterprise/Education).

  This does NOT modify anything on the machine — read-only.

.OUTPUTS
  admx-catalog.json in the current directory. Share this file back so it
  can be imported into Warden's policy settings catalog.
#>

$ErrorActionPreference = 'Stop'

$admxDir = "$env:WINDIR\PolicyDefinitions"
$admlDir = Join-Path $admxDir "en-US"

if (-not (Test-Path $admxDir)) {
    Write-Host "No PolicyDefinitions folder found at $admxDir" -ForegroundColor Red
    exit 1
}

$results = [System.Collections.Generic.List[object]]::new()
$admxFiles = Get-ChildItem -Path $admxDir -Filter "*.admx" -File

Write-Host "Found $($admxFiles.Count) ADMX files. Parsing..." -ForegroundColor Cyan

foreach ($admxFile in $admxFiles) {
    try {
        [xml]$admx = Get-Content -Path $admxFile.FullName -Raw
    } catch {
        Write-Host "  Skipping $($admxFile.Name): failed to parse ($($_.Exception.Message))" -ForegroundColor Yellow
        continue
    }

    # Matching .adml (same base filename) holds the human-readable strings.
    $admlPath = Join-Path $admlDir ($admxFile.BaseName + ".adml")
    $stringTable = @{}
    $presentationTable = @{}
    if (Test-Path $admlPath) {
        try {
            [xml]$adml = Get-Content -Path $admlPath -Raw
            $ns = New-Object System.Xml.XmlNamespaceManager($adml.NameTable)
            $ns.AddNamespace("a", $adml.DocumentElement.NamespaceURI)
            foreach ($s in $adml.SelectNodes("//a:stringTable/a:string", $ns)) {
                $stringTable[$s.id] = $s.'#text'
            }
        } catch {
            Write-Host "  Warning: failed to parse ADML for $($admxFile.Name)" -ForegroundColor Yellow
        }
    }

    $nsAdmx = New-Object System.Xml.XmlNamespaceManager($admx.NameTable)
    $nsAdmx.AddNamespace("a", $admx.DocumentElement.NamespaceURI)

    $categoryName = $admxFile.BaseName

    foreach ($policy in $admx.SelectNodes("//a:policy", $nsAdmx)) {
        $displayNameRef = $policy.displayName -replace '^\$\(string\.', '' -replace '\)$', ''
        $displayName = if ($stringTable.ContainsKey($displayNameRef)) { $stringTable[$displayNameRef] } else { $policy.name }

        $explainRef = $policy.explainText -replace '^\$\(string\.', '' -replace '\)$', ''
        $explainText = if ($stringTable.ContainsKey($explainRef)) { $stringTable[$explainRef] } else { $null }

        $supportedOn = $null
        $supportedOnNode = $policy.SelectSingleNode("a:supportedOn", $nsAdmx)
        if ($supportedOnNode -and $supportedOnNode.ref) { $supportedOn = $supportedOnNode.ref }

        $entry = [ordered]@{
            name         = $policy.name
            displayName  = $displayName
            explainText  = $explainText
            category     = $categoryName
            admxFile     = $admxFile.Name
            policyClass  = $policy.class
            registryKey  = $policy.key
            valueName    = $policy.valueName
            supportedOn  = $supportedOn
            elements     = @()
        }

        # Simple boolean policies: <enabledValue>/<disabledValue> directly
        # under <policy>, no <elements> block at all.
        if (-not $policy.SelectSingleNode("a:elements", $nsAdmx) -and $policy.valueName) {
            $entry.type = "boolean"
        }

        $elementsNode = $policy.SelectSingleNode("a:elements", $nsAdmx)
        if ($elementsNode) {
            foreach ($el in $elementsNode.ChildNodes) {
                $elEntry = [ordered]@{
                    kind      = $el.LocalName   # decimal | enum | text | boolean | list | multiText
                    id        = $el.id
                    valueName = $el.valueName
                }
                if ($el.LocalName -eq "decimal") {
                    $elEntry.min = $el.minValue
                    $elEntry.max = $el.maxValue
                }
                if ($el.LocalName -eq "enum") {
                    # ADMX <item><value> is either <decimal value="N"/> (a real
                    # numeric registry DWORD) or <string>text</string> (stored
                    # as a REG_SZ, even though it's still an enum choice --
                    # e.g. drive letters, GUIDs, "Enabled"/"Block"/etc). Track
                    # which one this element actually uses so the filter step
                    # can set the right regType -- getting this wrong means
                    # every push of that setting fails (tried to parse a GUID
                    # or "Block" as a base-10 integer).
                    $items = @()
                    $usesStringValue = $false
                    foreach ($item in $el.SelectNodes("a:item", $nsAdmx)) {
                        $labelRef = $item.displayName -replace '^\$\(string\.', '' -replace '\)$', ''
                        $label = if ($stringTable.ContainsKey($labelRef)) { $stringTable[$labelRef] } else { $item.displayName }
                        $valueNode = $item.SelectSingleNode("a:value/a:decimal", $nsAdmx)
                        $val = if ($valueNode) { $valueNode.value } else {
                            $strNode = $item.SelectSingleNode("a:value/a:string", $nsAdmx)
                            if ($strNode) { $usesStringValue = $true; $strNode.'#text' } else { $null }
                        }
                        $items += [ordered]@{ label = $label; value = $val }
                    }
                    $elEntry.items = $items
                    $elEntry.valueType = if ($usesStringValue) { "string" } else { "decimal" }
                }
                $entry.elements += $elEntry
            }
        }

        $results.Add($entry) | Out-Null
    }
}

Write-Host "Extracted $($results.Count) policies across $($admxFiles.Count) files." -ForegroundColor Green

$outPath = Join-Path (Get-Location) "admx-catalog.json"
$results | ConvertTo-Json -Depth 10 | Set-Content -Path $outPath -Encoding UTF8
Write-Host "Saved to $outPath" -ForegroundColor Green
Write-Host "Review this locally, then process it with filter_admx_catalog.py for your own deployment." -ForegroundColor Cyan
