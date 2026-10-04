package main

import (
	"fmt"
	"golang.org/x/sys/windows/registry"
)

// ── Peripheral policy ─────────────────────────────────────────────────────────

func setPeripheralPolicy(p map[string]interface{}) (int, string, error) {
	policyType, _ := p["policy_type"].(string)
	setStart := func(svc string, start uint32) error {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Services\`+svc, registry.SET_VALUE)
		if err != nil {
			return err
		}
		defer k.Close()
		return k.SetDWordValue("Start", start)
	}
	switch policyType {
	case "block_usb_storage":
		if err := setStart("USBSTOR", 4); err != nil {
			return 1, "", fmt.Errorf("block_usb_storage: %w", err)
		}
	case "allow_usb_storage":
		if err := setStart("USBSTOR", 3); err != nil {
			return 1, "", fmt.Errorf("allow_usb_storage: %w", err)
		}
	// "block_all_usb" (USBSTOR + usbhub) intentionally removed: usbhub.sys is
	// the USB hub driver itself, not specific to storage — disabling it takes
	// out every USB device on the machine, including keyboard/mouse, on the
	// next reboot. Blocking mass storage only (USBSTOR) already covers the
	// legitimate "no flash drives" use case without that risk.
	default:
		return 1, "", fmt.Errorf("policy_type '%s' not allowed", policyType)
	}
	return 0, fmt.Sprintf("Policy %s applied", policyType), nil
}
