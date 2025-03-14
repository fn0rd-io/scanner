package client

import (
	"context"
	"crypto/ed25519"
	"sync"
	"time"

	"connectrpc.com/connect"
	coordinatorv1 "github.com/fn0rd-io/protobuf/coordinator/v1"
)

// Config holds the scanner client configuration
type Config struct {
	// Coordinator connection settings
	CoordinatorURL string

	// Authentication
	PrivateKey *ed25519.PrivateKey

	// Performance tuning
	Workers        uint32
	ConnectTimeout time.Duration

	Interface   string
	UDP         bool
	MetricsPort string
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() Config {
	return Config{
		CoordinatorURL: "http://127.0.0.1:8080",
		Workers:        4,
		ConnectTimeout: 10 * time.Second,
	}
}

// Client manages the connection to the coordinator and task processing
type Client struct {
	config        Config
	ctx           context.Context
	cancel        context.CancelFunc
	stream        *connect.BidiStreamForClient[coordinatorv1.StreamRequest, coordinatorv1.StreamResponse]
	registered    bool
	activeWorkers sync.WaitGroup
	stateMu       sync.Mutex
	taskCh        chan *coordinatorv1.TargetResponse
	reconnectCh   chan struct{}
	attempt       uint8
}

// Result holds the outcome of a task processing attempt
type Result struct {
	Target []byte
	Data   []byte
	Error  error
}
