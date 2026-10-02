package main

import (
	"errors"
	diskPkg "github.com/shirou/gopsutil/v3/disk"
	"testing"
	"time"
)

func TestLocalDrivesAllLettersAndUsedSpace(t *testing.T) {
	const gib = 1024 * 1024 * 1024
	var probed []string
	snapshot := collectLocalDrives(time.Unix(0, 0), func(root string) bool {
		return root == "C:\\" || root == "D:\\" || root == "H:\\"
	}, func(root string) (*diskPkg.UsageStat, error) {
		probed = append(probed, root)
		return &diskPkg.UsageStat{Total: 100 * gib, Free: 25 * gib}, nil
	})
	drives := snapshot["volumes"].([]localDrive)
	if len(drives) != 3 || len(probed) != 3 || drives[2].MountPoint != "H:" ||
		drives[0].UsedGB != 75 || drives[0].TotalGB != 100 || drives[0].FreeGB != 25 {
		t.Fatalf("Incorrect drive snapshot: %#v", snapshot)
	}
	if snapshot["captured_at"] != "1970-01-01T00:00:00Z" {
		t.Fatal(snapshot)
	}
}

func TestLocalDrivesInaccessibleAndInvalidNotZero(t *testing.T) {
	snapshot := collectLocalDrives(time.Now(), func(root string) bool { return root == "C:\\" || root == "D:\\" },
		func(root string) (*diskPkg.UsageStat, error) {
			if root == "C:\\" {
				return nil, errors.New("locked volume")
			}
			return &diskPkg.UsageStat{Total: 100, Free: 101}, nil
		})
	if len(snapshot["volumes"].([]localDrive)) != 0 {
		t.Fatal(snapshot)
	}
}
