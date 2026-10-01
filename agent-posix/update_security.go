package main

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func validateDownloadURL(raw string) error {
	candidate, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid download URL: %w", err)
	}
	base, err := url.Parse(serverURL())
	if err != nil || base.Host == "" || base.Scheme != "https" {
		return fmt.Errorf("configured Warden origin must use HTTPS")
	}
	if candidate.Scheme != "https" || candidate.Host == "" || candidate.User != nil || candidate.Fragment != "" {
		return fmt.Errorf("download must be an HTTPS URL without credentials or fragments")
	}
	if !strings.EqualFold(candidate.Host, base.Host) {
		return fmt.Errorf("download origin does not match the configured Warden server")
	}
	return nil
}

func compareAgentVersions(left, right string) (int, error) {
	parse := func(value string) ([3]uint64, error) {
		var result [3]uint64
		parts := strings.Split(value, ".")
		if len(parts) != 3 {
			return result, fmt.Errorf("version must be major.minor.patch")
		}
		for index, part := range parts {
			if part == "" || strings.IndexFunc(part, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				return result, fmt.Errorf("version contains a non-numeric component")
			}
			number, err := strconv.ParseUint(part, 10, 64)
			if err != nil {
				return result, err
			}
			result[index] = number
		}
		return result, nil
	}
	a, err := parse(left)
	if err != nil {
		return 0, err
	}
	b, err := parse(right)
	if err != nil {
		return 0, err
	}
	for index := range a {
		if a[index] < b[index] {
			return -1, nil
		}
		if a[index] > b[index] {
			return 1, nil
		}
	}
	return 0, nil
}
