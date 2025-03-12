package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/fn0rd-io/scanner/pkg/client"
)

var (
	coordURL = flag.String("coordinator", "https://coordinator.fn0rd.io", "URL of coordinator service")
	workers  = flag.Uint("workers", uint(runtime.NumCPU()*4), "Number of worker goroutines")
	logfile  = flag.String("logfile", "STDOUT", "Log file path")
	statedir = flag.String("statedir", "/var/lib/fn0rd", "Directory to store state")
	iface    = flag.String("iface", "", "Network interface to use for scanning")
	metrics  = flag.String("metrics", "127.0.0.1:0", "Address to serve Prometheus metrics on")
)

func init() {
	flag.Parse()
	setupLogging()
	if *workers == 0 {
		*workers = uint(runtime.NumCPU() * 4)
		log.Printf("Using default worker count: %d", *workers)
	}
}

func main() {
	// Load or create identity key
	privateKey, err := loadOrCreateIdentity()
	if err != nil {
		log.Fatalf("Identity key error: %v", err)
	}

	// Configure and start client
	client, err := setupClient(privateKey)
	if err != nil {
		log.Fatalf("Client setup error: %v", err)
	}

	log.Printf("Scanner started with %d workers, connected to %s", *workers, *coordURL)

	// Handle graceful shutdown
	waitForShutdown(client)
}

func setupLogging() {
	if *logfile != "STDOUT" && *logfile != "" {
		f, err := os.OpenFile(*logfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		// Note: This file handle intentionally remains open for the duration of the program
		log.SetOutput(f)
	} else {
		log.SetOutput(os.Stdout)
	}
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
						log.Printf("Using existing identity from %s (PEM format)", identityPath)
						return privKey, nil
					}
					log.Printf("Identity file contains unsupported key type, generating new key")
				} else {
					log.Printf("Failed to parse private key: %v", err)
				}
			} else if len(keyData) == ed25519.PrivateKeySize {
				// Try legacy raw format
				log.Printf("Using existing identity from %s (legacy format)", identityPath)
				return ed25519.PrivateKey(keyData), nil
			} else {
				log.Printf("Identity file has invalid format, generating new key")
			}
		} else {
			log.Printf("Failed to read identity file: %v", err)
		}
	}

	// Generate new key
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	log.Printf("Generated new ED25519 key with public key: %x", pubKey)

	// Convert to PKCS8
	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		log.Printf("Failed to marshal private key to PKCS8: %v", err)
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
		log.Printf("Failed to create state directory: %v", err)
	} else if err := os.WriteFile(identityPath, pemData, 0600); err != nil {
		log.Printf("Failed to save identity file: %v", err)
	} else {
		log.Printf("Generated and saved new identity to %s (PEM format)", identityPath)
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
		log.Println("Scanner shutdown complete")
		cancel()
	}()

	// Wait for shutdown to complete or timeout
	<-ctx.Done()
}
