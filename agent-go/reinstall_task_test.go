package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReinstallTaskXMLUsesSupportedSystemPrincipal(t *testing.T) {
	xml := reinstallTaskXML(`C:\ProgramData\WardenReinstall\test\run-reinstall.cmd`)
	if strings.Contains(xml, "<LogonType>") {
		t.Fatal("SYSTEM XML must omit LogonType: ServiceAccount is a COM enum, not XML schema value")
	}
	for _, required := range []string{"<UserId>S-1-5-18</UserId>", "<Delay>PT45S</Delay>", "<AllowStartOnDemand>true</AllowStartOnDemand>", "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>", "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"} {
		if !strings.Contains(xml, required) {
			t.Fatalf("missing task setting %s", required)
		}
	}
}

// Opt-in native validation only: TASK_VALIDATE_ONLY=1 never registers/runs a
// task or changes service state. It catches Windows schema errors unit tests miss.
func TestReinstallTaskXMLAcceptedByWindows(t *testing.T) {
	if os.Getenv("WARDEN_TEST_TASK_XML") != "1" {
		t.Skip("enable native Task Scheduler validation with WARDEN_TEST_TASK_XML=1")
	}
	path := filepath.Join(t.TempDir(), "reinstall-task.xml")
	if err := os.WriteFile(path, encodeUTF16LE(reinstallTaskXML(`C:\ProgramData\WardenReinstall\validate\run-reinstall.cmd`)), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `$ErrorActionPreference='Stop'; $s=New-Object -ComObject Schedule.Service; $s.Connect(); $xml=[IO.File]::ReadAllText($env:WARDEN_TASK_XML_PATH); $null=$s.GetFolder('\').RegisterTask('Warden-Validation-Only', $xml, 1, 'SYSTEM', $null, 5); 'XML validation passed'`)
	cmd.Env = append(os.Environ(), "WARDEN_TASK_XML_PATH="+path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native Task Scheduler rejected XML: %v: %s", err, output)
	}
}
