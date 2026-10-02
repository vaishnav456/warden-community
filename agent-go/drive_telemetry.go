package main

import (
	diskPkg "github.com/shirou/gopsutil/v3/disk"
	"golang.org/x/sys/windows"
	"time"
)

type localDrive struct {
	MountPoint string  `json:"mount_point"`
	TotalGB    float64 `json:"total_gb"`
	UsedGB     float64 `json:"used_gb"`
	FreeGB     float64 `json:"free_gb"`
}

// Fixed local volumes only: never probe disconnected network shares or USB media.
// Do not cache indefinitely: removal, resizing and newly assigned letters are
// reflected in the next heartbeat. Failed/inaccessible volumes are not zero usage.
func localDriveSnapshot() map[string]interface{} {
	return collectLocalDrives(time.Now(), func(root string) bool {
		path, err := windows.UTF16PtrFromString(root)
		return err == nil && windows.GetDriveType(path) == windows.DRIVE_FIXED
	}, diskPkg.Usage)
}

func collectLocalDrives(now time.Time, fixed func(string) bool, usage func(string) (*diskPkg.UsageStat, error)) map[string]interface{} {
	drives := make([]localDrive, 0)
	for letter := 'A'; letter <= 'Z'; letter++ {
		root := string(letter) + ":\\"
		if !fixed(root) {
			continue
		}
		stat, err := usage(root)
		if err != nil || stat == nil || stat.Total == 0 || stat.Free > stat.Total {
			continue
		}
		const gib = 1024 * 1024 * 1024
		drives = append(drives, localDrive{root[:2], round2(float64(stat.Total) / gib),
			round2(float64(stat.Total-stat.Free) / gib), round2(float64(stat.Free) / gib)})
	}
	return map[string]interface{}{"captured_at": now.UTC().Format(time.RFC3339), "volumes": drives}
}
