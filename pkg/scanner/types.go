package scanner

import (
	"context"
	"crypto/ed25519"
	"sync"
	"time"

	"connectrpc.com/connect"
	coordinatorv1 "github.com/fn0rd-io/protobuf/coordinator/v1"
)

// Result represents the outcome of scanning an IP address
type Result struct {
	Target []byte
	Data   []byte
	Error  error
}

// Config holds the scanner client configuration
type Config struct {
	// Coordinator connection settings
	CoordinatorURL string

	// Authentication
	PrivateKey *ed25519.PrivateKey

	// Performance tuning
	Workers        uint32
	ConnectTimeout time.Duration
}

// Client manages the connection to the coordinator service
type Client struct {
	config Config

	// Connection state
	ctx     context.Context
	cancel  context.CancelFunc
	stream  *connect.BidiStreamForClient[coordinatorv1.StreamRequest, coordinatorv1.StreamResponse]
	stateMu sync.Mutex // Protects stream and registered flags

	// Task management
	taskCh        chan *coordinatorv1.TargetResponse
	resultCh      chan Result
	activeWorkers sync.WaitGroup

	// Connection state
	registered  bool
	reconnectCh chan struct{}
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() Config {
	return Config{
		CoordinatorURL: "http://127.0.0.1:8080",
		Workers:        4,
		ConnectTimeout: 10 * time.Second,
	}
}
