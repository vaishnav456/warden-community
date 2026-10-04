package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func windowsUpdate(p map[string]interface{}) (int, string, error) {
	action, _ := p["action"].(string)
	if action == "" {
		action = "check"
	}
	switch action {
	case "check":
		out, err := exec.Command("UsoClient", "StartScan").CombinedOutput()
		if err != nil {
			return commandExitCode(err), string(out), fmt.Errorf("Windows Update scan: %w", err)
		}
		count, err := reportWindowsPatchInventory()
		if err != nil {
			return 1, "Windows Update scan triggered, but inventory reporting failed", err
		}
		return 0, fmt.Sprintf("Windows Update scan triggered; reported %d pending updates", count), nil
	case "install":
		rebootMode, _ := p["reboot_mode"].(string)
		if rebootMode == "" {
			rebootMode = "notify"
		}
		if rebootMode != "never" && rebootMode != "notify" {
			return 1, "", fmt.Errorf("unsupported restart mode; no updates installed")
		}
		allowed := map[string]bool{"Critical": true, "Important": true, "Moderate": true, "Low": true, "Unspecified": true}
		severities := []string{}
		if raw, ok := p["severities"].([]interface{}); ok {
			for _, value := range raw {
				if text, ok := value.(string); ok && allowed[text] {
					severities = append(severities, text)
				}
			}
		}
		if len(severities) == 0 {
			severities = []string{"Critical", "Important", "Moderate", "Low", "Unspecified"}
		}
		quoted := make([]string, 0, len(severities))
		for _, severity := range severities {
			quoted = append(quoted, "'"+severity+"'")
		}
		script := `$ErrorActionPreference='Stop'; $allowed=@(` + strings.Join(quoted, ",") + `); ` +
			`$session=New-Object -ComObject Microsoft.Update.Session; $search=$session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0"); ` +
			`$selected=New-Object -ComObject Microsoft.Update.UpdateColl; foreach($u in $search.Updates){ $s=$(if($u.MsrcSeverity){$u.MsrcSeverity}else{'Unspecified'}); if($allowed -contains $s){ if(-not $u.EulaAccepted){$u.AcceptEula()}; [void]$selected.Add($u) } }; ` +
			`if($selected.Count -eq 0){ Write-Output 'No approved updates are applicable'; exit 0 }; ` +
			`$downloader=$session.CreateUpdateDownloader(); $downloader.Updates=$selected; $download=$downloader.Download(); ` +
			`$ready=New-Object -ComObject Microsoft.Update.UpdateColl; foreach($u in $selected){if($u.IsDownloaded){[void]$ready.Add($u)}}; ` +
			`if($download.ResultCode -ne 2 -or $ready.Count -ne $selected.Count){throw 'Approved updates did not all download; no installation started'}; ` +
			`$installer=$session.CreateUpdateInstaller(); $installer.Updates=$ready; $installer.AllowSourcePrompts=$false; $result=$installer.Install(); ` +
			`$failed=0; for($i=0;$i -lt $ready.Count;$i++){ $r=$result.GetUpdateResult($i); Write-Output ("Update {0}: result={1}; hresult={2}; reboot={3}" -f $ready.Item($i).Identity.UpdateID,$r.ResultCode,$r.HResult,$r.RebootRequired); if($r.ResultCode -ne 2){$failed++} }; ` +
			`Write-Output ("Approved={0}; failed={1}; result={2}; reboot={3}" -f $ready.Count,$failed,$result.ResultCode,$result.RebootRequired); if($result.RebootRequired){Write-Output 'WARDEN_REBOOT_REQUIRED'}; if($failed -gt 0 -or $result.ResultCode -ne 2){exit 1}`
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
		defer cancel()
		out, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
		if ctx.Err() != nil {
			return 1, string(out), fmt.Errorf("Windows Update installation timed out")
		}
		if rebootMode == "notify" && strings.Contains(string(out), "WARDEN_REBOOT_REQUIRED") {
			notifyUserOfRemoteAccess("Windows updates need a restart", "Save your work and restart Windows when convenient. Warden has not forced a restart.")
		}
		if err != nil {
			return commandExitCode(err), string(out), fmt.Errorf("Windows Update install: %w", err)
		}
		_, _ = reportWindowsPatchInventory()
		return 0, strings.TrimSpace(string(out)), nil
	default:
		return 1, "", fmt.Errorf("action must be 'check' or 'install'")
	}
}

func reportWindowsPatchInventory() (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Microsoft.Update.Session is available on supported Windows editions and
	// returns authoritative applicability data without relying on locale-specific
	// command output. ConvertTo-Json receives an explicit array so zero, one and
	// many updates all share the same wire shape.
	script := `$session = New-Object -ComObject Microsoft.Update.Session; ` +
		`$result = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0"); ` +
		`$items = @($result.Updates | ForEach-Object { [pscustomobject]@{ ` +
		`update_id=$_.Identity.UpdateID; title=$_.Title; kb_articles=@($_.KBArticleIDs); ` +
		`severity=$(if ($_.MsrcSeverity) { $_.MsrcSeverity } else { 'Unspecified' }); ` +
		`categories=@($_.Categories | ForEach-Object { $_.Name }); ` +
		`reboot_required=[bool]$_.RebootRequired } }); ` +
		`ConvertTo-Json -InputObject $items -Compress -Depth 5`
	out, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if ctx.Err() != nil {
		return 0, fmt.Errorf("query pending updates: timed out")
	}
	if err != nil {
		return 0, fmt.Errorf("query pending updates: %w: %s", err, strings.TrimSpace(string(out)))
	}

	updates := make([]map[string]interface{}, 0)
	if trimmed := bytes.TrimSpace(out); len(trimmed) > 0 && string(trimmed) != "null" {
		if err := json.Unmarshal(trimmed, &updates); err != nil {
			return 0, fmt.Errorf("decode pending updates: %w", err)
		}
	}
	if len(updates) > 500 {
		updates = updates[:500]
	}
	if _, err := apiPostAuth("/api/agent/patch-inventory", map[string]interface{}{
		"updates": updates,
	}); err != nil {
		return 0, fmt.Errorf("report pending updates: %w", err)
	}
	return len(updates), nil
}
