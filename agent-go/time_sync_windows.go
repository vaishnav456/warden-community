//go:build windows

package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func prepareSystemClock() error {
	_, _ = exec.Command("sc.exe", "config", "w32time", "start=", "auto").CombinedOutput()
	_, _ = exec.Command("sc.exe", "start", "w32time").CombinedOutput()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "w32tm.exe", "/resync", "/force").CombinedOutput()
	if ctx.Err() != nil {
		return fmt.Errorf("w32tm timed out")
	}
	if err != nil {
		return fmt.Errorf("w32tm: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

type windowsSystemTime struct {
	Year, Month, DayOfWeek, Day        uint16
	Hour, Minute, Second, Milliseconds uint16
}

func setSystemTimeUTC(value time.Time) error {
	value = value.UTC()
	stamp := windowsSystemTime{
		Year: uint16(value.Year()), Month: uint16(value.Month()),
		Day: uint16(value.Day()), Hour: uint16(value.Hour()),
		Minute: uint16(value.Minute()), Second: uint16(value.Second()),
		Milliseconds: uint16(value.Nanosecond() / int(time.Millisecond)),
	}
	procedure := syscall.NewLazyDLL("kernel32.dll").NewProc("SetSystemTime")
	result, _, callErr := procedure.Call(uintptr(unsafe.Pointer(&stamp)))
	if result == 0 {
		return fmt.Errorf("SetSystemTime: %v", callErr)
	}
	return nil
}

func applySystemTimeZone(value string) (bool, error) {
	currentRaw, err := exec.Command("tzutil.exe", "/g").CombinedOutput()
	current := strings.TrimSpace(string(currentRaw))
	if err == nil && strings.EqualFold(current, value) {
		return false, nil
	}
	output, err := exec.Command("tzutil.exe", "/s", value).CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("tzutil: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return true, nil
}
