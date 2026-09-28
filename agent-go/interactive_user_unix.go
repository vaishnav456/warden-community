//go:build !windows

package main

import (
	"os/exec"
	"strings"
)

// currentInteractiveUser returns a locally signed-in desktop/terminal user.
// The Agent normally runs as root, so the process identity is not useful here.
func currentInteractiveUser() string {
	output, err := exec.Command("who").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] != "root" {
			return fields[0]
		}
	}
	return ""
}
