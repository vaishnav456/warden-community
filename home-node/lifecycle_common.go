package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func copyInstallFiles(sourceConfig, destinationExecutable, destinationConfig string) error {
	raw, err := os.ReadFile(sourceConfig)
	if err != nil {
		return fmt.Errorf("read configuration: %w", err)
	}
	var installed config
	if err := json.Unmarshal(raw, &installed); err != nil {
		return fmt.Errorf("parse configuration: %w", err)
	}
	base, _ := filepath.Abs(filepath.Dir(sourceConfig))
	paths := []*string{&installed.Root, &installed.TLSCert, &installed.TLSKey, &installed.ClientCA, &installed.ClientCert, &installed.ClientKey}
	for _, value := range paths {
		if *value != "" && !filepath.IsAbs(*value) {
			*value = filepath.Join(base, *value)
		}
	}
	encoded, err := json.MarshalIndent(installed, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destinationExecutable), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destinationConfig), 0700); err != nil {
		return err
	}
	if err := copyCurrentExecutable(destinationExecutable); err != nil {
		return err
	}
	return os.WriteFile(destinationConfig, append(encoded, '\n'), 0600)
}

func copyCurrentExecutable(destinationExecutable string) error {
	currentPath, err := filepath.Abs(os.Args[0])
	if err != nil {
		return err
	}
	destinationPath, err := filepath.Abs(destinationExecutable)
	if err != nil {
		return err
	}
	if filepath.Clean(currentPath) == filepath.Clean(destinationPath) {
		return fmt.Errorf("run upgrade from a newly downloaded Warden Home executable, not the installed copy")
	}
	if err := os.MkdirAll(filepath.Dir(destinationExecutable), 0755); err != nil {
		return err
	}
	current, err := os.Open(currentPath)
	if err != nil {
		return err
	}
	defer current.Close()
	target, err := os.OpenFile(destinationExecutable, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	if _, err = io.Copy(target, current); err != nil {
		target.Close()
		return err
	}
	if err := target.Close(); err != nil {
		return err
	}
	return nil
}
