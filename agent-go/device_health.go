package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

var deviceHealthCache struct {
	sync.Mutex
	next  time.Time
	value map[string]interface{}
}

// Read-only inventory runs off the heartbeat path. Missing sensors remain
// unknown; a stopped Defender service is not proof that antivirus is absent.
func deviceHealthSnapshot() map[string]interface{} {
	deviceHealthCache.Lock()
	defer deviceHealthCache.Unlock()
	if time.Now().After(deviceHealthCache.next) {
		deviceHealthCache.next = time.Now().Add(5 * time.Minute)
		go func() {
			script := `$ErrorActionPreference='Stop'; $disks=@(); try { $disks=@(Get-PhysicalDisk | Select-Object FriendlyName,HealthStatus,OperationalStatus) } catch {}; $service=Get-Service -Name WinDefend -ErrorAction SilentlyContinue; @{disks=$disks; defender_status=$(if($service){$service.Status.ToString()}else{'Unknown'})} | ConvertTo-Json -Depth 5 -Compress`
			raw, err := runPowerShellSecret(script, nil, 10*time.Second)
			result := map[string]interface{}{"status": "unknown"}
			if err == nil && len(raw) <= 65536 && json.Unmarshal(raw, &result) == nil {
				if disks, ok := result["disks"].([]interface{}); ok {
					for _, rawDisk := range disks {
						if disk, ok := rawDisk.(map[string]interface{}); ok {
							// CIM can serialize HealthStatus as its UInt16 enum.
							switch fmt.Sprint(disk["HealthStatus"]) {
							case "0":
								disk["HealthStatus"] = "Healthy"
							case "1":
								disk["HealthStatus"] = "Warning"
							case "2":
								disk["HealthStatus"] = "Unhealthy"
							}
						}
					}
				}
				result["status"] = "reported"
				result["collected_at"] = time.Now().UTC().Format(time.RFC3339)
			}
			deviceHealthCache.Lock()
			deviceHealthCache.value = result
			deviceHealthCache.Unlock()
		}()
	}
	if deviceHealthCache.value == nil {
		return map[string]interface{}{"status": "unknown"}
	}
	return deviceHealthCache.value
}
