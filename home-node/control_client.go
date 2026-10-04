package main

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

func validateHomeServerURL(raw string) error {
	target, err := url.Parse(raw)
	if err != nil || target.Scheme != "https" || target.Host == "" || target.User != nil || target.RawQuery != "" || target.Fragment != "" {
		return fmt.Errorf("Warden server URL must be HTTPS without credentials, query, or fragment")
	}
	return nil
}

func homeControlClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return fmt.Errorf("Home control redirect refused")
	}}
}
