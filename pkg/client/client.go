package client

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	mrand "math/rand"
	"net"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	coordinatorv1 "github.com/fn0rd-io/protobuf/coordinator/v1"
	"github.com/fn0rd-io/protobuf/coordinator/v1/coordinatorconnect"
	"github.com/fn0rd-io/scanner/pkg/common"
	_ "github.com/fn0rd-io/scanner/pkg/nmap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	baseBackoff       = 1 * time.Second
	maxBackoff        = 5 * time.Minute
	reconnectWaitTime = 50 * time.Millisecond
)

// Error constants
var (
	ErrNoWorkers        = errors.New("must specify at least one worker")
	ErrNoPrivateKey     = errors.New("must provide a private key")
	ErrInvalidPublicKey = errors.New("public key is not an Ed25519 key")
	ErrTaskExpired      = errors.New("task expired before processing")
	ErrNotConnected     = errors.New("not connected to coordinator")
)

// NewClient creates a new coordinator client
func NewClient(config Config) (*Client, error) {
	if config.Workers == 0 {
		return nil, ErrNoWorkers
	}

	if config.PrivateKey == nil {
		return nil, ErrNoPrivateKey
	}

	ctx, cancel := context.WithCancel(context.Background())

	client := &Client{
		config:      config,
		ctx:         ctx,
		cancel:      cancel,
		taskCh:      make(chan *coordinatorv1.TargetResponse, config.Workers),
		reconnectCh: make(chan struct{}, 1), // Buffer of 1 to prevent blocking
		stateMu:     sync.RWMutex{},
	}

	// Determine capabilities
	client.capabilities = client.determineCapabilities()

	totalWorkers.Set(float64(config.Workers))

	return client, nil
}

// Start begins the client's operation by connecting to the coordinator
// and starting worker goroutines
func (c *Client) Start() error {
	c.InitMetrics()

	// Start the workers
	c.startWorkers()

	// Start goroutines for connection management and message handling
	go c.connectionManager()
	go c.receiveMessages()

	if c.config.Debug {
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-c.ctx.Done():
					return
				case <-ticker.C:
					try := c.stateMu.TryLock()
					if try {
						c.stateMu.Unlock()
					}
					slog.Debug(fmt.Sprintf("TryLock: %v", try))
				}
			}
		}()
	}

	// Trigger initial connection
	c.reconnectCh <- struct{}{}

	return nil
}

// Stop gracefully shuts down the client
func (c *Client) Stop() {
	slog.Info("Shutting down scanner client...")
	c.cancel()
	c.activeWorkers.Wait()
	slog.Info("Scanner client stopped")
}

// startWorkers launches the specified number of worker goroutines
func (c *Client) startWorkers() {
	for i := uint32(0); i < c.config.Workers; i++ {
		c.activeWorkers.Add(1)
		go c.worker(i + 1)
	}
}

// connectionManager handles the connection lifecycle including reconnection logic
func (c *Client) connectionManager() {
	slog.Info(fmt.Sprintf("Connection manager started for coordinator at %s", c.config.CoordinatorURL))

	// transport := http.DefaultTransport
	// transport.(*http.Transport).DialContext = (&net.Dialer{
	// 	Timeout:   c.config.ConnectTimeout,
	// 	KeepAlive: 30 * time.Second,
	// 	DualStack: true,
	// }).DialContext
	// httpClient := http.DefaultClient
	// httpClient.Transport = transport

	// Create connect client with custom HTTP client
	client := coordinatorconnect.NewCoordinatorServiceClient(
		http.DefaultClient,
		c.config.CoordinatorURL,
		connect.WithGRPC(),
	)

	pingTimer := time.NewTicker(5 * time.Second)
	defer pingTimer.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-pingTimer.C:
			if err := c.sendPing(); err != nil {
				if errors.Is(err, ErrNotConnected) {
					continue
				}
				streamErrors.Inc()
				c.triggerReconnect(err)
			}
		case <-c.reconnectCh:
			slog.Debug("Attempting to connect to coordinator...")
			slog.Debug("Getting Lock")
			c.stateMu.Lock()
			slog.Debug("Got Lock")
			c.stream = client.Stream(c.ctx)
			c.stateMu.Unlock()
			slog.Debug("Connection established")
		}
	}
}

// sendPing sends a ping message to the coordinator
func (c *Client) sendPing() error {
	nonce, err := generateNonce(16)
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	if c.stream == nil || !c.registered {
		return ErrNotConnected
	}
	return c.stream.Send(&coordinatorv1.StreamRequest{
		Nonce: nonce,
		Request: &coordinatorv1.StreamRequest_Ping{
			Ping: &coordinatorv1.PingRequest{
				Timestamp: timestamppb.Now(),
			},
		},
	})
}

// calculateBackoff determines the next backoff period with jitter
func calculateBackoff(base time.Duration, attempt uint8, max time.Duration) time.Duration {
	backoff := time.Duration(float64(base) * math.Pow(1.5, float64(attempt)))
	if backoff > max {
		backoff = max
	}

	// Add jitter (±20%)
	jitter := time.Duration(mrand.Float64()*0.4*float64(backoff) - 0.2*float64(backoff))

	slog.Debug(fmt.Sprintf("Calculated backoff: %v + %v", backoff, jitter))
	return backoff + jitter
}

// register sends registration information to the coordinator
func (c *Client) register() error {
	// Extract public key from private key
	ed25519PubKey, ok := c.config.PrivateKey.Public().(ed25519.PublicKey)
	if !ok {
		return ErrInvalidPublicKey
	}

	// Use the raw bytes directly - this will be exactly 32 bytes
	pubKeyBytes := []byte(ed25519PubKey)

	// Generate nonce
	nonce, err := generateNonce(16)
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Create registration request
	req := &coordinatorv1.StreamRequest{
		Nonce: nonce,
		Request: &coordinatorv1.StreamRequest_Register{
			Register: &coordinatorv1.RegisterRequest{
				PublicKey:    pubKeyBytes,
				Workers:      c.config.Workers,
				Capabilities: c.capabilities,
			},
		},
	}

	// Sign the request
	if err := c.signRequest(req, nonce, c.config.Workers); err != nil {
		return err
	}

	// Send registration
	slog.Debug("Getting Lock")
	c.stateMu.Lock()
	slog.Debug("Got Lock")
	defer c.stateMu.Unlock()
	if c.stream == nil {
		return ErrNotConnected
	}
	stream := c.stream

	if err := stream.Send(req); err != nil {
		return fmt.Errorf("failed to send registration: %w", err)
	}

	slog.Debug(fmt.Sprintf("Registration with %d workers sent successfully", c.config.Workers))
	c.registered = true
	return nil
}

// determineCapabilities checks what capabilities this scanner supports
func (c *Client) determineCapabilities() []coordinatorv1.Capability {
	capabilities := []coordinatorv1.Capability{}

	slog.Info("Determining scanner capabilities...")

	// Check if Nmap scanner is available
	n, err := common.GetScanner("nmap").New(context.Background(), "127.0.0.1", "", true)
	if err != nil {
		slog.Info(fmt.Sprintf("Cannot create Nmap scanner: %v", err))
	} else {
		capabilities = append(capabilities, coordinatorv1.Capability_CAPABILITY_NMAP)
		if _, err := n.Run(); err == nil {
			c.config.UDP = true
			capabilities = append(capabilities, coordinatorv1.Capability_CAPABILITY_NMAP_FULL)
		} else {
			slog.Warn(fmt.Sprintf("Limiting Capabilities to TCP-Only: %v", err))
		}
	}

	return capabilities
}

// generateNonce creates a cryptographically secure random nonce
func generateNonce(size int) ([]byte, error) {
	nonce := make([]byte, size)
	_, err := rand.Read(nonce)
	return nonce, err
}

// signRequest signs a request with the client's private key
func (c *Client) signRequest(req *coordinatorv1.StreamRequest, nonce []byte, workerCount uint32) error {
	// Prepare data to sign: nonce + worker count as bytes
	workerBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(workerBytes, workerCount)
	dataToSign := append(nonce, workerBytes...)

	// Sign the raw message (Ed25519 does its own hashing internally)
	signature, err := c.config.PrivateKey.Sign(rand.Reader, dataToSign, crypto.Hash(0))
	if err != nil {
		return fmt.Errorf("failed to sign request: %w", err)
	}

	req.Signature = signature
	return nil
}

// receiveMessages handles incoming messages from the coordinator
func (c *Client) receiveMessages() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			// Get stream safely
			c.stateMu.RLock()

			// Handle nil stream case
			if c.stream == nil {
				c.stateMu.RUnlock()
				slog.Debug("Stream is nil, waiting for connection...")
				time.Sleep(reconnectWaitTime)
				continue
			}

			if !c.registered {
				slog.Debug("Not registered, attempting to register...")
				c.stateMu.RUnlock()
				if err := c.register(); err != nil {
					c.triggerReconnect(err)
				}
				continue
			}

			// Try to receive a message
			resp, err := c.stream.Receive()
			if err != nil {
				c.stateMu.RUnlock()
				streamErrors.Inc()
				c.triggerReconnect(err)
				continue
			}

			// Reset attempt counter on successful receive
			if c.attempt > 0 {
				c.attempt = 0
			}

			// Process the response
			switch {
			case resp.GetTarget() != nil:
				target := resp.GetTarget()
				c.taskCh <- target
				tasksAssigned.Inc()
			case resp.GetPing() != nil:
				// No need to do anything for pings
			default:
				slog.Warn("Received unknown response type")
			}
			c.stateMu.RUnlock()
		}
	}
}

// triggerReconnect signals that a reconnection is needed
func (c *Client) triggerReconnect(err error) {
	slog.Info(fmt.Sprintf("Reconnection triggered: %v", err))
	slog.Debug("Getting Lock")
	c.stateMu.Lock()
	slog.Debug("Got Lock")
	defer c.stateMu.Unlock()
	c.attempt++
	c.stream = nil
	c.registered = false
	time.Sleep(calculateBackoff(baseBackoff, c.attempt, maxBackoff))
	select {
	case c.reconnectCh <- struct{}{}:
		// Signal sent successfully
	default:
		// Channel is full (reconnection already triggered)
	}
}

// worker processes tasks received from the coordinator
func (c *Client) worker(id uint32) {
	defer c.activeWorkers.Done()
	slog.Debug(fmt.Sprintf("Worker %d started", id))

	for {
		select {
		case <-c.ctx.Done():
			slog.Debug(fmt.Sprintf("Worker %d shutting down", id))
			return
		case task := <-c.taskCh:
			c.processTask(id, task)
		}
	}
}

// processTask handles a single scanning task
func (c *Client) processTask(id uint32, task *coordinatorv1.TargetResponse) {
	target := task.Target
	deadline := task.Deadline.AsTime()

	slog.Debug(fmt.Sprintf("Worker %d: processing task for %#v", id, target))

	// Calculate time remaining until deadline
	if time.Until(deadline) < 0 {
		slog.Info(fmt.Sprintf("Worker %d: task already expired, skipping", id))
		c.submitResult(Result{
			Target: target,
			Error:  ErrTaskExpired,
		})
		return
	}

	// Create context with deadline
	ctx, cancel := context.WithDeadline(c.ctx, deadline)
	defer cancel()

	// Run the scan
	result, err := c.runScan(ctx, id, target)
	c.submitResult(Result{
		Target: target,
		Data:   result,
		Error:  err,
	})
}

// runScan executes an Nmap scan against the target
func (c *Client) runScan(ctx context.Context, id uint32, target []byte) ([]byte, error) {
	n, err := common.GetScanner("nmap").New(ctx, net.IP(target).String(), c.config.Interface, c.config.UDP)
	if err != nil {
		slog.Info(fmt.Sprintf("Worker %d: failed to create Nmap scanner: %v", id, err))
		return nil, fmt.Errorf("scanner initialization failed: %w", err)
	}

	result, err := n.Run()
	if err != nil {
		slog.Info(fmt.Sprintf("Worker %d: task failed: %v", id, err))
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	return result, nil
}

// submitResult sends a task result to the coordinator
func (c *Client) submitResult(result Result) {
	if result.Error != nil {
		slog.Info(fmt.Sprintf("Task error: %v", result.Error))
		tasksFailed.Inc()
	}

	// Generate nonce
	nonce, err := generateNonce(16)
	if err != nil {
		c.triggerReconnect(err)
		return
	}

	// Create submit request
	req := &coordinatorv1.StreamRequest{
		Nonce: nonce,
		Request: &coordinatorv1.StreamRequest_Submit{
			Submit: &coordinatorv1.SubmitRequest{
				Result: result.Data,
			},
		},
	}

	// Prepare data to sign: nonce + result data
	dataToSign := append(nonce, result.Data...)

	// Sign the raw message (Ed25519 does its own hashing internally)
	signature, err := c.config.PrivateKey.Sign(rand.Reader, dataToSign, crypto.Hash(0))
	if err != nil {
		c.triggerReconnect(err)
		return
	}

	req.Signature = signature

	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	if c.stream == nil || !c.registered {
		slog.Info("Cannot submit result: not connected")
		return
	}

	// Send result
	if err := c.stream.Send(req); err != nil {
		streamErrors.Inc()
		c.triggerReconnect(err)
		return
	}

	tasksCompleted.Inc()
}
