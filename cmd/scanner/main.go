package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/fn0rd-io/scanner/pkg/client"
)

var (
	coordURL    = flag.String("coordinator", "https://coordinator.fn0rd.io", "URL of coordinator service")
	workers     = flag.Uint("workers", uint(runtime.NumCPU()*4), "Number of worker goroutines")
	logfile     = flag.String("logfile", "STDOUT", "Log file path")
	statedir    = flag.String("statedir", "/var/lib/fn0rd", "Directory to store state")
	iface       = flag.String("iface", "", "Network interface to use for scanning")
	metrics     = flag.String("metrics", "127.0.0.1:0", "Address to serve Prometheus metrics on")
	showversion = flag.Bool("version", false, "Show version information")
	debug       = flag.Bool("debug", false, "Enable debug logging")
	version     = ""
	commit      = ""
	date        = ""
)

func init() {
	flag.Parse()
	if *showversion {
		slog.Info(fmt.Sprintf("Scanner version %s, commit %s, built at %s", version, commit, date))
		os.Exit(0)
	}
	setupLogging()
	if *workers == 0 {
		*workers = uint(runtime.NumCPU() * 4)
		slog.Info(fmt.Sprintf("Using default worker count: %d", *workers))
	}
}

func main() {
	// Load or create identity key
	privateKey, err := loadOrCreateIdentity()
	if err != nil {
		slog.Error(fmt.Sprintf("Identity key error: %v", err))
	}

	// Configure and start client
	client, err := setupClient(privateKey)
	if err != nil {
		slog.Error(fmt.Sprintf("Client setup error: %v", err))
		os.Exit(2)
	}

	slog.Info(fmt.Sprintf("Scanner started with %d workers, connected to %s", *workers, *coordURL))

	// Handle graceful shutdown
	waitForShutdown(client)
}

func setupLogging() {
	var logWriter io.Writer = os.Stdout

	if *logfile != "STDOUT" && *logfile != "" {
		f, err := os.OpenFile(*logfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			slog.Error(fmt.Sprintf("Failed to open log file: %v\n", err))
			os.Exit(2)
		}
		// Note: This file handle intentionally remains open for the duration of the program
		logWriter = f
	}

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}

	// Create a text handler that writes to the selected output
	textHandler := slog.NewTextHandler(logWriter, &slog.HandlerOptions{
		Level:     level,
		AddSource: true,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.SourceKey {
				s := a.Value.Any().(*slog.Source)
				s.File = path.Base(s.File)
			}
			return a
		},
	})

	// Set the default logger with our configured handler
	slog.SetDefault(slog.New(textHandler))
}

func loadOrCreateIdentity() (ed25519.PrivateKey, error) {
	// Check if identity file exists
	identityPath := filepath.Join(*statedir, "identity")

	// Try to load existing key
	if _, err := os.Stat(identityPath); err == nil {
		keyData, err := os.ReadFile(identityPath)
		if err == nil {
			// First try to parse as PEM
			block, _ := pem.Decode(keyData)
			if block != nil && block.Type == "PRIVATE KEY" {
				// Parse the PKCS8 private key
				key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
				if err == nil {
					if privKey, ok := key.(ed25519.PrivateKey); ok {
						slog.Info(fmt.Sprintf("Using existing identity from %s (PEM format)", identityPath))
						return privKey, nil
					}
					slog.Info("Identity file contains unsupported key type, generating new key")
				} else {
					slog.Error(fmt.Sprintf("Failed to parse private key: %v", err))
				}
			} else if len(keyData) == ed25519.PrivateKeySize {
				// Try legacy raw format
				slog.Info(fmt.Sprintf("Using existing identity from %s (legacy format)", identityPath))
				return ed25519.PrivateKey(keyData), nil
			} else {
				slog.Info("Identity file has invalid format, generating new key")
			}
		} else {
			slog.Error(fmt.Sprintf("Failed to read identity file: %v", err))
		}
	}

	// Generate new key
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	slog.Info(fmt.Sprintf("Generated new ED25519 key with public key: %x", pubKey))

	// Convert to PKCS8
	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to marshal private key to PKCS8: %v", err))
		return privKey, nil
	}

	// Create PEM block
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Key,
	}
	pemData := pem.EncodeToMemory(pemBlock)

	// Save new key to file
	if err := os.MkdirAll(*statedir, 0700); err != nil {
		slog.Error(fmt.Sprintf("Failed to create state directory: %v", err))
	} else if err := os.WriteFile(identityPath, pemData, 0600); err != nil {
		slog.Error(fmt.Sprintf("Failed to save identity file: %v", err))
	} else {
		slog.Info(fmt.Sprintf("Generated and saved new identity to %s (PEM format)", identityPath))
	}

	return privKey, nil
}

func setupClient(privateKey ed25519.PrivateKey) (*client.Client, error) {
	// Configure client
	config := client.DefaultConfig()
	config.CoordinatorURL = *coordURL
	config.Workers = uint32(*workers)
	config.PrivateKey = &privateKey
	config.Interface = *iface
	config.MetricsPort = *metrics
	config.Debug = *debug

	// Create and start client
	client, err := client.NewClient(config)
	if err != nil {
		return nil, err
	}

	if err := client.Start(); err != nil {
		return nil, err
	}

	return client, nil
}

func waitForShutdown(client *client.Client) {
	// Set up signal handling
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	// Create a context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Signal cancellation to any long-running operations
	go func() {
		client.Stop()
		slog.Info("Scanner shutdown complete")
		cancel()
	}()

	// Wait for shutdown to complete or timeout
	<-ctx.Done()
}
