// Warden Home Node stores tenant files without routing file contents through
// the Warden control plane. Every data request requires an offline-verifiable,
// short-lived Ed25519 grant scoped to a tenant, node, space and path prefix.
package main

import (
	"context"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var (
	cfg               config
	configPathInUse   string
	pub               ed25519.PublicKey
	aead              cipher.AEAD
	peerClientCert    tls.Certificate
	peerCertLoaded    bool
	encryptionKeyID   string
	nonceMu           sync.Mutex
	seenNonces        = map[string]int64{}
	storageMu         sync.Mutex
	replicationMu     sync.Mutex
	replicationOK     = map[string]int64{}
	replicationActive sync.Map
	replicationReady  = make(chan struct{}, 1)
)

func runConfiguredServer(path string, stop <-chan struct{}) error {
	if err := loadConfig(path); err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	})
	mux.HandleFunc("/v1/list", handleList)
	mux.HandleFunc("/v1/directory", handleDirectory)
	mux.HandleFunc("/v1/file", handleFile)
	mux.HandleFunc("/v1/history", handleHistory)
	mux.HandleFunc("/v1/package", handlePackageCache)
	servingCertificate, err := watchServingCertificate(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return err
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			certificate := servingCertificate.Load()
			if certificate == nil {
				return nil, errors.New("TLS certificate is unavailable")
			}
			return certificate, nil
		},
	}
	if cfg.ClientCA != "" {
		raw, err := os.ReadFile(cfg.ClientCA)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return errors.New("invalid client CA")
		}
		tlsCfg.ClientCAs = pool
		// Permit unauthenticated transport only to the minimal /health endpoint.
		// Data handlers independently require a verified certificate whose
		// Warden identity matches the signed grant.
		tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	server := &http.Server{Addr: cfg.Listen, Handler: http.MaxBytesHandler(mux, 5*1024*1024*1024+1024), TLSConfig: tlsCfg, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute, WriteTimeout: 10 * time.Minute}
	go heartbeatLoop(stop)
	go backupLoop(stop)
	go homeP2PLoop(stop)
	log.Printf("Warden Home Node %s listening on %s", cfg.NodeID, cfg.Listen)
	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServeTLS("", "") }()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-stop:
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	}
}

func main() {
	if handled, err := runAsSystemService(); handled {
		if err != nil {
			log.Fatal(err)
		}
		return
	}
	command, args := "serve", os.Args[1:]
	if len(args) > 0 && (args[0] == "serve" || args[0] == "install" || args[0] == "upgrade" || args[0] == "uninstall" || args[0] == "apply-update" || args[0] == "trust-updates" || args[0] == "backup" || args[0] == "verify-backup" || args[0] == "restore-backup") {
		command, args = args[0], args[1:]
	}
	flags := flag.NewFlagSet(command, flag.ExitOnError)
	path := flags.String("config", "warden-home.json", "configuration file")
	manifest := flags.String("manifest", "", "signed managed-update manifest")
	snapshot := flags.String("snapshot", "", "independent snapshot ID")
	restoreRoot := flags.String("restore-root", "", "new, non-existing recovery directory")
	_ = flags.Parse(args)
	switch command {
	case "backup", "verify-backup", "restore-backup":
		if err := loadBackupConfig(*path); err != nil {
			log.Fatal(err)
		}
		var result backupSummary
		var err error
		switch command {
		case "backup":
			result, err = createBackup()
		case "verify-backup":
			result, err = verifyBackup(*snapshot)
		case "restore-backup":
			result, err = restoreBackup(*snapshot, *restoreRoot)
		}
		if err != nil {
			log.Fatal(err)
		}
		encoded, _ := json.Marshal(result)
		fmt.Println(string(encoded))
	case "install":
		if err := installSystemService(*path); err != nil {
			log.Fatal(err)
		}
		log.Print("Warden Home service installed and started")
	case "uninstall":
		if err := uninstallSystemService(); err != nil {
			log.Fatal(err)
		}
		log.Print("Warden Home service removed; configuration, keys, and encrypted data were preserved")
	case "upgrade":
		if err := upgradeSystemService(); err != nil {
			log.Fatal(err)
		}
		log.Print("Warden Home service upgraded and restarted; configuration, keys, and encrypted data were preserved")
	case "apply-update":
		if *manifest == "" {
			log.Fatal("managed update manifest is required")
		}
		if err := loadManagedUpdateConfig(*path); err != nil {
			log.Fatal(err)
		}
		if err := applyManagedUpdateManifest(*manifest); err != nil {
			log.Fatal(err)
		}
		log.Print("Signed managed Warden Home update applied")
	case "trust-updates":
		if err := configureManagedUpdateTrust(*path); err != nil {
			log.Fatal(err)
		}
		log.Print("Root-owned Home update identity configured")
	default:
		stop := make(chan struct{})
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
		go func() { <-signals; close(stop) }()
		if err := runConfiguredServer(*path, stop); err != nil {
			log.Fatal(err)
		}
	}
}
