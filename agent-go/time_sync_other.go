//go:build !windows

package main

import "time"

func prepareSystemClock() error                { return nil }
func setSystemTimeUTC(time.Time) error         { return nil }
func applySystemTimeZone(string) (bool, error) { return false, nil }
